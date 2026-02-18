use crate::{KyuPipeline, WirehairEncoder, WirehairDecoder, SessionManifest, KeyExchange, HandshakePacket};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::{Read, Write};
use std::thread;
use std::time::Duration;
use std::collections::HashMap;
use anyhow::{Result, bail};

// --- Crypto Imports for Header Protection ---
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::{Aead, generic_array::GenericArray}};

// --- Constants ---
const BLOCK_SIZE: usize = 1024 * 64; 
const TARGET_PACKET_SIZE: usize = 1400;
const CONSTANT_UDP_SIZE: usize = 1400; // Traffic Analysis Padding Size
const TYPE_DATA: u8 = b'D';
const TYPE_HANDSHAKE: u8 = b'H';

// --- Helper: QUIC-Style Header Masking ---
fn generate_header_mask(secret: &[u8; 32], payload_sample: &[u8]) -> [u8; 22] {
    let key = GenericArray::from_slice(secret);
    let cipher = ChaCha20Poly1305::new(key);
    
    // Use the first 12 bytes of the payload as a dynamic nonce
    let mut nonce_bytes = [0u8; 12];
    let copy_len = payload_sample.len().min(12);
    nonce_bytes[..copy_len].copy_from_slice(&payload_sample[..copy_len]);
    let nonce = GenericArray::from_slice(&nonce_bytes);

    // Encrypt 22 bytes of zeros to generate our keystream mask
    // We only care about the ciphertext, so we discard the MAC appended by AEAD
    if let Ok(encrypted) = cipher.encrypt(nonce, [0u8; 22].as_ref()) {
        let mut mask = [0u8; 22];
        mask.copy_from_slice(&encrypted[..22]);
        return mask;
    }
    [0u8; 22] // Fallback (should never be hit)
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
    Error(String),
}

// --- SENDER ---

pub struct KyuSender {
    socket: UdpSocket,
    dest: String,
}

impl KyuSender {
    pub fn new(dest: &str) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(dest)?;
        Ok(Self { socket, dest: dest.to_string() })
    }

    pub fn send_file<F>(&self, path: &Path, redundancy: f32, on_event: F) -> Result<()> 
    where F: Fn(KyuEvent) {
        let filename = path.file_name().unwrap().to_str().unwrap();
        let file_size = path.metadata()?.len();
        let stream_id = rand::random::<u32>(); 
        
        on_event(KyuEvent::Log(format!("Starting transfer: {} (Stream #{:x})", filename, stream_id)));

        on_event(KyuEvent::HandshakeInitiated);
        let (session_id, shared_key) = self.perform_handshake()?;
        on_event(KyuEvent::HandshakeComplete);
        
        let mut pipeline = KyuPipeline::new(&shared_key);

        let manifest = SessionManifest::new(filename, file_size);
        self.send_chunk(&mut pipeline, &shared_key, &manifest.to_bytes(), 0, 2.0, session_id, stream_id)?;

        let mut file = File::open(path)?;
        let mut buffer = vec![0u8; BLOCK_SIZE];
        let mut block_id = 1u64;

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 { break; }

            let chunk = &buffer[0..bytes_read];
            self.send_chunk(&mut pipeline, &shared_key, chunk, block_id, redundancy, session_id, stream_id)?;
            
            let progress = (block_id as u64 * BLOCK_SIZE as u64).min(file_size);
            on_event(KyuEvent::Progress { stream_id, current: progress, total: file_size });

            block_id += 1;
        }

        on_event(KyuEvent::TransferComplete { stream_id, path: path.to_path_buf() });
        Ok(())
    }

    fn perform_handshake(&self) -> Result<(u64, [u8; 32])> {
        let my_keys = KeyExchange::new();
        let my_id = rand::random::<u64>();

        let hello = HandshakePacket { protocol_version: 1, session_id: my_id, public_key: *my_keys.public.as_bytes() };
        let mut packet = vec![TYPE_HANDSHAKE];
        packet.extend(bincode::serialize(&hello)?);
        let mut buf = [0u8; 1024];

        for _ in 0..10 {
            self.socket.send(&packet)?;
            self.socket.set_read_timeout(Some(Duration::from_millis(500)))?;
            if let Ok((amt, _)) = self.socket.recv_from(&mut buf) {
                if amt > 1 && buf[0] == TYPE_HANDSHAKE {
                    if let Ok(server_hello) = bincode::deserialize::<HandshakePacket>(&buf[1..amt]) {
                        if server_hello.session_id == my_id {
                            let secret = my_keys.derive_shared_secret(server_hello.public_key);
                            return Ok((my_id, secret));
                        }
                    }
                }
            }
        }
        bail!("Handshake timed out")
    }

    fn send_chunk(&self, pipeline: &mut KyuPipeline, shared_key: &[u8; 32], data: &[u8], block_id: u64, redundancy: f32, session_id: u64, stream_id: u32) -> Result<()> {
        let protected = pipeline.protect_block(data, block_id)?;
        let total_size = protected.len() as u32;

        let mut pkt_size = TARGET_PACKET_SIZE as u32;
        if total_size <= pkt_size {
            pkt_size = (total_size + 1) / 2;
        }

        let encoder = WirehairEncoder::new(&protected, pkt_size)?;
        let needed_packets = (total_size + pkt_size - 1) / pkt_size;
        let total_packets = (needed_packets as f32 * redundancy).ceil() as u32;

        for seq_id in 0..total_packets {
            let packet_data = encoder.encode(seq_id).map_err(|e| anyhow::anyhow!("{:?}", e))?;
            
            // 1. Pack the Plaintext Header (22 Bytes)
            let mut plain_hdr = [0u8; 22];
            plain_hdr[0..4].copy_from_slice(&stream_id.to_le_bytes());
            plain_hdr[4..12].copy_from_slice(&block_id.to_le_bytes());
            plain_hdr[12..16].copy_from_slice(&seq_id.to_le_bytes());
            plain_hdr[16..20].copy_from_slice(&total_size.to_le_bytes());
            plain_hdr[20..22].copy_from_slice(&(pkt_size as u16).to_le_bytes());

            // 2. Generate Mask & Apply XOR
            let mask = generate_header_mask(shared_key, &packet_data);
            for i in 0..22 { plain_hdr[i] ^= mask[i]; }

            // 3. Assemble Final Wire Packet
            let mut wire_packet = Vec::with_capacity(CONSTANT_UDP_SIZE);
            wire_packet.push(TYPE_DATA);
            wire_packet.extend_from_slice(&session_id.to_le_bytes());
            wire_packet.extend_from_slice(&plain_hdr); // Encrypted!
            wire_packet.extend_from_slice(&packet_data);

            // 4. Traffic Padding
            if wire_packet.len() < CONSTANT_UDP_SIZE {
                wire_packet.resize(CONSTANT_UDP_SIZE, 0u8);
            }

            self.socket.send(&wire_packet)?;
            if seq_id % 10 == 0 { thread::sleep(Duration::from_micros(10)); }
        }
        Ok(())
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
        let mut buf = [0u8; 2048]; // Max UDP recv buffer

        struct StreamState {
            file: Option<(File, String, u64)>, 
            decoder: Option<(u64, WirehairDecoder)>,
            bytes_received: u64,
        }
        struct SessionState {
            shared_secret: [u8; 32], // Needed for Unmasking
            pipeline: KyuPipeline,
            streams: HashMap<u32, StreamState>, 
        }
        let mut sessions: HashMap<u64, SessionState> = HashMap::new();

        on_event(0, KyuEvent::Log(format!("Listening on {:?}", self.socket.local_addr()?)));

        loop {
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
                                });
                                on_event(session_id, KyuEvent::HandshakeComplete);
                            }
                        }
                        TYPE_DATA => {
                            if amt < 31 { continue; } // Malformed
                            let session_id = u64::from_le_bytes(buf[1..9].try_into().unwrap());

                            if let Some(session) = sessions.get_mut(&session_id) {
                                // 1. Extract Masked Header and Payload Sample
                                let masked_hdr = &buf[9..31];
                                let payload_with_padding = &buf[31..amt];

                                // 2. Generate Mask & Reverse XOR
                                let mask = generate_header_mask(&session.shared_secret, payload_with_padding);
                                let mut plain_hdr = [0u8; 22];
                                for i in 0..22 { plain_hdr[i] = masked_hdr[i] ^ mask[i]; }

                                // 3. Parse Unmasked Header
                                let stream_id = u32::from_le_bytes(plain_hdr[0..4].try_into().unwrap());
                                let block_id = u64::from_le_bytes(plain_hdr[4..12].try_into().unwrap());
                                let seq_id = u32::from_le_bytes(plain_hdr[12..16].try_into().unwrap());
                                let total_size = u32::from_le_bytes(plain_hdr[16..20].try_into().unwrap());
                                let pkt_size = u16::from_le_bytes(plain_hdr[20..22].try_into().unwrap());
                                
                                // 4. Discard Traffic Padding (Crucial for Wirehair)
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
                                    if let Ok(true) = decoder.decode(seq_id, actual_payload) { // Pass ONLY actual_payload
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
                                                    }
                                                }
                                            }
                                        }
                                        stream.decoder = None;
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
