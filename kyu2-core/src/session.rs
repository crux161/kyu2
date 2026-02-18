use crate::{KyuPipeline, WirehairEncoder, WirehairDecoder, SessionManifest, KeyExchange, HandshakePacket};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::{Read, Write, ErrorKind};
use std::thread;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use anyhow::{Result, bail};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::{Aead, generic_array::GenericArray}};

// --- Constants ---
const BLOCK_SIZE: usize = 1024 * 64; 
const CONSTANT_UDP_SIZE: usize = 1200; // E: Safe Universal MTU
const TARGET_PACKET_SIZE: usize = 1150; // Leave room for headers
const TYPE_DATA: u8 = b'D';
const TYPE_HANDSHAKE: u8 = b'H';
const TYPE_ACK: u8 = b'A';  // A: Early Termination
const TYPE_PING: u8 = b'P'; // C: Keepalive
const TYPE_PONG: u8 = b'O';

// --- Helper: QUIC-Style Header Masking ---
fn generate_header_mask(secret: &[u8; 32], payload_sample: &[u8]) -> [u8; 22] {
    let key = GenericArray::from_slice(secret);
    let cipher = ChaCha20Poly1305::new(key);
    let mut nonce_bytes = [0u8; 12];
    let copy_len = payload_sample.len().min(12);
    nonce_bytes[..copy_len].copy_from_slice(&payload_sample[..copy_len]);
    let nonce = GenericArray::from_slice(&nonce_bytes);
    if let Ok(encrypted) = cipher.encrypt(nonce, [0u8; 22].as_ref()) {
        let mut mask = [0u8; 22];
        mask.copy_from_slice(&encrypted[..22]);
        return mask;
    }
    [0u8; 22] 
}

// --- B: Congestion Control (Pacer) ---
struct Pacer {
    target_bytes_per_sec: u64,
    start_time: Instant,
    bytes_sent: u64,
}
impl Pacer {
    fn new(target_bytes_per_sec: u64) -> Self {
        Self { target_bytes_per_sec, start_time: Instant::now(), bytes_sent: 0 }
    }
    fn pace(&mut self, packet_size: u64) {
        if self.target_bytes_per_sec == 0 { return; } // 0 = Unlimited
        self.bytes_sent += packet_size;
        let expected_duration = Duration::from_secs_f64(self.bytes_sent as f64 / self.target_bytes_per_sec as f64);
        let elapsed = self.start_time.elapsed();
        if expected_duration > elapsed {
            thread::sleep(expected_duration - elapsed);
        }
    }
}

// --- Events ---
#[derive(Debug, Clone)]
pub enum KyuEvent {
    Log(String),
    HandshakeInitiated,
    HandshakeComplete,
    FileDetected { stream_id: u32, name: String, size: u64 },
    Progress { stream_id: u32, current: u64, total: u64 },
    TransferComplete { stream_id: u32, path: PathBuf },
    EarlyTermination { stream_id: u32 }, // New Event
    Error(String),
}

// --- SENDER ---
pub struct KyuSender {
    socket: UdpSocket,
    dest: String,
    session_id: Option<u64>,
    shared_key: Option<[u8; 32]>,
}

impl KyuSender {
    pub fn new(dest: &str) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(dest)?;
        socket.set_nonblocking(true)?; // Required for async ACK checking
        Ok(Self { socket, dest: dest.to_string(), session_id: None, shared_key: None })
    }

    /// C: Keepalive Trigger (GUI can call this on a timer)
    pub fn ping(&self) -> Result<()> {
        let mut packet = vec![TYPE_PING];
        if let Some(sid) = self.session_id {
            packet.extend_from_slice(&sid.to_le_bytes());
            self.socket.send(&packet)?;
        }
        Ok(())
    }

    pub fn send_file<F>(&mut self, path: &Path, redundancy: f32, max_bytes_per_sec: u64, on_event: F) -> Result<()> 
    where F: Fn(KyuEvent) {
        let filename = path.file_name().unwrap().to_str().unwrap();
        let file_size = path.metadata()?.len();
        let stream_id = rand::random::<u32>(); 
        
        on_event(KyuEvent::Log(format!("Starting transfer: {} (Stream #{:x})", filename, stream_id)));

        if self.session_id.is_none() {
            on_event(KyuEvent::HandshakeInitiated);
            let (sid, key) = self.perform_handshake()?;
            self.session_id = Some(sid);
            self.shared_key = Some(key);
            on_event(KyuEvent::HandshakeComplete);
        }

        let session_id = self.session_id.unwrap();
        let shared_key = self.shared_key.unwrap();
        let mut pipeline = KyuPipeline::new(&shared_key);
        let mut pacer = Pacer::new(max_bytes_per_sec);

        let manifest = SessionManifest::new(filename, file_size);
        self.send_chunk(&mut pipeline, &shared_key, &manifest.to_bytes(), 0, 2.0, session_id, stream_id, &mut pacer, &on_event)?;

        let mut file = File::open(path)?;
        let mut buffer = vec![0u8; BLOCK_SIZE];
        let mut block_id = 1u64;

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 { break; }

            let chunk = &buffer[0..bytes_read];
            // If send_chunk returns false, we received an Early Termination ACK!
            let cont = self.send_chunk(&mut pipeline, &shared_key, chunk, block_id, redundancy, session_id, stream_id, &mut pacer, &on_event)?;
            
            if !cont {
                on_event(KyuEvent::EarlyTermination { stream_id });
                return Ok(());
            }
            
            let progress = (block_id as u64 * BLOCK_SIZE as u64).min(file_size);
            on_event(KyuEvent::Progress { stream_id, current: progress, total: file_size });
            block_id += 1;
        }

        on_event(KyuEvent::TransferComplete { stream_id, path: path.to_path_buf() });
        Ok(())
    }

    fn perform_handshake(&self) -> Result<(u64, [u8; 32])> {
        self.socket.set_nonblocking(false)?; // Block for handshake
        self.socket.set_read_timeout(Some(Duration::from_millis(500)))?;
        
        let my_keys = KeyExchange::new();
        let my_id = rand::random::<u64>();
        let hello = HandshakePacket { protocol_version: 1, session_id: my_id, public_key: *my_keys.public.as_bytes() };
        let mut packet = vec![TYPE_HANDSHAKE];
        packet.extend(bincode::serialize(&hello)?);
        let mut buf = [0u8; 1024];

        for _ in 0..10 {
            self.socket.send(&packet)?;
            if let Ok((amt, _)) = self.socket.recv_from(&mut buf) {
                if amt > 1 && buf[0] == TYPE_HANDSHAKE {
                    if let Ok(server_hello) = bincode::deserialize::<HandshakePacket>(&buf[1..amt]) {
                        if server_hello.session_id == my_id {
                            self.socket.set_nonblocking(true)?; // Return to non-blocking
                            return Ok((my_id, my_keys.derive_shared_secret(server_hello.public_key)));
                        }
                    }
                }
            }
        }
        bail!("Handshake timed out")
    }

    /// Returns `true` if transmission should continue, `false` if an ACK aborted it.
    fn send_chunk<F>(&self, pipeline: &mut KyuPipeline, shared_key: &[u8; 32], data: &[u8], block_id: u64, redundancy: f32, session_id: u64, stream_id: u32, pacer: &mut Pacer, _on_event: &F) -> Result<bool> 
    where F: Fn(KyuEvent) {
        let protected = pipeline.protect_block(data, block_id)?;
        let total_size = protected.len() as u32;

        let mut pkt_size = TARGET_PACKET_SIZE as u32;
        if total_size <= pkt_size { pkt_size = (total_size + 1) / 2; }

        let encoder = WirehairEncoder::new(&protected, pkt_size)?;
        let needed_packets = (total_size + pkt_size - 1) / pkt_size;
        let total_packets = (needed_packets as f32 * redundancy).ceil() as u32;

        let mut ack_buf = [0u8; 32];

        for seq_id in 0..total_packets {
            // A: Check for Early Termination ACK
            match self.socket.recv_from(&mut ack_buf) {
                Ok((amt, _)) if amt == 13 && ack_buf[0] == TYPE_ACK => {
                    let ack_sid = u64::from_le_bytes(ack_buf[1..9].try_into().unwrap());
                    let ack_stream = u32::from_le_bytes(ack_buf[9..13].try_into().unwrap());
                    if ack_sid == session_id && ack_stream == stream_id {
                        return Ok(false); // Abort!
                    }
                }
                _ => {} // Ignore WouldBlock or other packets for now
            }

            let packet_data = encoder.encode(seq_id).map_err(|e| anyhow::anyhow!("{:?}", e))?;
            
            let mut plain_hdr = [0u8; 22];
            plain_hdr[0..4].copy_from_slice(&stream_id.to_le_bytes());
            plain_hdr[4..12].copy_from_slice(&block_id.to_le_bytes());
            plain_hdr[12..16].copy_from_slice(&seq_id.to_le_bytes());
            plain_hdr[16..20].copy_from_slice(&total_size.to_le_bytes());
            plain_hdr[20..22].copy_from_slice(&(pkt_size as u16).to_le_bytes());

            let mask = generate_header_mask(shared_key, &packet_data);
            for i in 0..22 { plain_hdr[i] ^= mask[i]; }

            let mut wire_packet = Vec::with_capacity(CONSTANT_UDP_SIZE);
            wire_packet.push(TYPE_DATA);
            wire_packet.extend_from_slice(&session_id.to_le_bytes());
            wire_packet.extend_from_slice(&plain_hdr);
            wire_packet.extend_from_slice(&packet_data);

            if wire_packet.len() < CONSTANT_UDP_SIZE {
                wire_packet.resize(CONSTANT_UDP_SIZE, 0u8);
            }

            // Handle OS buffer limits gracefully
            loop {
                match self.socket.send(&wire_packet) {
                    Ok(_) => break,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(Duration::from_micros(100)),
                    Err(e) => return Err(e.into()),
                }
            }
            
            pacer.pace(wire_packet.len() as u64); // B: Apply Congestion Control
        }
        Ok(true)
    }
}

// --- RECEIVER ---
pub struct KyuReceiver {
    socket: UdpSocket,
    out_dir: PathBuf,
}

impl KyuReceiver {
    pub fn new(bind_addr: &str, out_dir: &Path) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?; 
        Ok(Self { socket, out_dir: out_dir.to_path_buf() })
    }

    pub fn run_loop<F>(&self, on_event: F) -> Result<()>
    where F: Fn(u64, KyuEvent) {
        let mut buf = [0u8; 2048]; 

        struct StreamState {
            file: Option<(File, String, u64)>, 
            decoder: Option<(u64, WirehairDecoder)>,
            bytes_received: u64,
        }
        struct SessionState {
            shared_secret: [u8; 32],
            pipeline: KyuPipeline,
            streams: HashMap<u32, StreamState>, 
            last_active: Instant, // D: Garbage Collection
        }
        let mut sessions: HashMap<u64, SessionState> = HashMap::new();
        let mut last_gc_sweep = Instant::now();

        on_event(0, KyuEvent::Log(format!("Listening on {:?}", self.socket.local_addr()?)));

        loop {
            // D: Perform Garbage Collection every 10 seconds
            if last_gc_sweep.elapsed() > Duration::from_secs(10) {
                sessions.retain(|sid, session| {
                    let alive = session.last_active.elapsed() < Duration::from_secs(300); // 5 min timeout
                    if !alive { on_event(*sid, KyuEvent::Log("Session dropped (Timeout)".into())); }
                    alive
                });
                last_gc_sweep = Instant::now();
            }

            match self.socket.recv_from(&mut buf) {
                Ok((amt, src)) => {
                    if amt < 1 { continue; }
                    match buf[0] {
                        TYPE_HANDSHAKE => {
                            if let Ok(client_hello) = bincode::deserialize::<HandshakePacket>(&buf[1..amt]) {
                                let session_id = client_hello.session_id;
                                let server_keys = KeyExchange::new();
                                let my_public_bytes = *server_keys.public.as_bytes();
                                let shared_secret = server_keys.derive_shared_secret(client_hello.public_key);

                                let reply = HandshakePacket { protocol_version: 1, session_id, public_key: my_public_bytes };
                                let mut resp = vec![TYPE_HANDSHAKE];
                                resp.extend(bincode::serialize(&reply).unwrap());
                                let _ = self.socket.send_to(&resp, src);

                                sessions.insert(session_id, SessionState {
                                    shared_secret,
                                    pipeline: KyuPipeline::new(&shared_secret),
                                    streams: HashMap::new(),
                                    last_active: Instant::now(),
                                });
                                on_event(session_id, KyuEvent::HandshakeComplete);
                            }
                        }
                        TYPE_PING => { // C: Automatic Pong Reply
                            if amt >= 9 {
                                let session_id = u64::from_le_bytes(buf[1..9].try_into().unwrap());
                                if let Some(session) = sessions.get_mut(&session_id) {
                                    session.last_active = Instant::now();
                                    let mut pong = vec![TYPE_PONG];
                                    pong.extend_from_slice(&session_id.to_le_bytes());
                                    let _ = self.socket.send_to(&pong, src);
                                }
                            }
                        }
                        TYPE_DATA => {
                            if amt < 31 { continue; }
                            let session_id = u64::from_le_bytes(buf[1..9].try_into().unwrap());

                            if let Some(session) = sessions.get_mut(&session_id) {
                                session.last_active = Instant::now(); // Update GC timer
                                
                                let masked_hdr = &buf[9..31];
                                let payload_with_padding = &buf[31..amt];
                                let mask = generate_header_mask(&session.shared_secret, payload_with_padding);
                                let mut plain_hdr = [0u8; 22];
                                for i in 0..22 { plain_hdr[i] = masked_hdr[i] ^ mask[i]; }

                                let stream_id = u32::from_le_bytes(plain_hdr[0..4].try_into().unwrap());
                                let block_id = u64::from_le_bytes(plain_hdr[4..12].try_into().unwrap());
                                let seq_id = u32::from_le_bytes(plain_hdr[12..16].try_into().unwrap());
                                let total_size = u32::from_le_bytes(plain_hdr[16..20].try_into().unwrap());
                                let pkt_size = u16::from_le_bytes(plain_hdr[20..22].try_into().unwrap());
                                
                                let valid_payload_len = (pkt_size as usize).min(payload_with_padding.len());
                                let actual_payload = &payload_with_padding[..valid_payload_len];

                                let stream = session.streams.entry(stream_id).or_insert(StreamState {
                                    file: None, decoder: None, bytes_received: 0
                                });

                                if let Some((active_id, _)) = stream.decoder {
                                    if block_id != active_id { stream.decoder = None; }
                                }
                                if stream.decoder.is_none() {
                                    if let Ok(dec) = WirehairDecoder::new(total_size as u64, pkt_size as u32) {
                                        stream.decoder = Some((block_id, dec));
                                    }
                                }

                                if let Some((_, ref mut decoder)) = stream.decoder {
                                    if let Ok(true) = decoder.decode(seq_id, actual_payload) { 
                                        if let Ok(protected) = decoder.recover() {
                                            if let Ok(raw) = session.pipeline.restore_block(&protected, block_id) {
                                                if block_id == 0 {
                                                    if stream.file.is_none() {
                                                        if let Some(meta) = SessionManifest::from_bytes(&raw) {
                                                            let safe_name = Path::new(&meta.filename).file_name().unwrap();
                                                            if let Ok(f) = File::create(self.out_dir.join(safe_name)) {
                                                                stream.file = Some((f, meta.filename.clone(), meta.file_size));
                                                                on_event(session_id, KyuEvent::FileDetected { stream_id, name: meta.filename, size: meta.file_size });
                                                            }
                                                        }
                                                    }
                                                } else if let Some((ref mut file, ref filename, total_bytes)) = stream.file {
                                                    let _ = file.write_all(&raw);
                                                    stream.bytes_received += raw.len() as u64;
                                                    
                                                    on_event(session_id, KyuEvent::Progress { stream_id, current: stream.bytes_received, total: total_bytes });

                                                    if stream.bytes_received >= total_bytes {
                                                        let _ = file.sync_all();
                                                        on_event(session_id, KyuEvent::TransferComplete { stream_id, path: self.out_dir.join(filename) });
                                                        
                                                        // A: Fire Early Termination ACK (send 3 times to ensure delivery)
                                                        let mut ack = vec![TYPE_ACK];
                                                        ack.extend_from_slice(&session_id.to_le_bytes());
                                                        ack.extend_from_slice(&stream_id.to_le_bytes());
                                                        for _ in 0..3 { let _ = self.socket.send_to(&ack, src); }

                                                        // D: Clean up stream memory immediately
                                                        session.streams.remove(&stream_id);
                                                    }
                                                }
                                            }
                                        }
                                        if let Some(s) = session.streams.get_mut(&stream_id) { s.decoder = None; }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
                Err(e) => { on_event(0, KyuEvent::Error(format!("Socket Error: {}", e))); break; }
            }
        }
        Ok(())
    }
}
