use crate::{KyuPipeline, WirehairEncoder, WirehairDecoder, SessionManifest, KeyExchange, HandshakePacket};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::{Read, Write};
use std::thread;
use std::time::Duration;
use std::collections::HashMap;
use anyhow::{Result, bail};

// --- Constants ---
const BLOCK_SIZE: usize = 1024 * 64; 
const TARGET_PACKET_SIZE: usize = 1400;
const TYPE_DATA: u8 = b'D';
const TYPE_HANDSHAKE: u8 = b'H';

// --- Events for the GUI ---
#[derive(Debug, Clone)]
pub enum KyuEvent {
    Log(String),
    HandshakeInitiated,
    HandshakeComplete,
    FileDetected { name: String, size: u64 },
    Progress { current: u64, total: u64 },
    TransferComplete { path: PathBuf },
    Error(String),
}

// --- The Sender API ---
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
        
        on_event(KyuEvent::Log(format!("Starting transfer: {}", filename)));

        // 1. Handshake
        on_event(KyuEvent::HandshakeInitiated);
        let (session_id, shared_key) = self.perform_handshake()?;
        on_event(KyuEvent::HandshakeComplete);
        
        let mut pipeline = KyuPipeline::new(&shared_key);

        // 2. Manifest
        let manifest = SessionManifest::new(filename, file_size);
        self.send_chunk(&mut pipeline, &manifest.to_bytes(), 0, 2.0, session_id)?;

        // 3. Data
        let mut file = File::open(path)?;
        let mut buffer = vec![0u8; BLOCK_SIZE];
        let mut block_id = 1u64;

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 { break; }

            let chunk = &buffer[0..bytes_read];
            self.send_chunk(&mut pipeline, chunk, block_id, redundancy, session_id)?;
            
            let progress = (block_id as u64 * BLOCK_SIZE as u64).min(file_size);
            on_event(KyuEvent::Progress { current: progress, total: file_size });

            block_id += 1;
        }

        on_event(KyuEvent::TransferComplete { path: path.to_path_buf() });
        Ok(())
    }

    fn perform_handshake(&self) -> Result<(u64, [u8; 32])> {
        let my_keys = KeyExchange::new();
        let my_id = rand::random::<u64>();

        let hello = HandshakePacket {
            protocol_version: 1,
            session_id: my_id,
            public_key: *my_keys.public.as_bytes(),
        };
        
        let mut packet = vec![TYPE_HANDSHAKE];
        packet.extend(bincode::serialize(&hello)?);
        let mut buf = [0u8; 1024];

        for _ in 0..10 { // 5 seconds retry
            self.socket.send(&packet)?;
            self.socket.set_read_timeout(Some(Duration::from_millis(500)))?;
            
            if let Ok((amt, _)) = self.socket.recv_from(&mut buf) {
                if amt > 1 && buf[0] == TYPE_HANDSHAKE {
                    let server_hello: HandshakePacket = bincode::deserialize(&buf[1..amt])?;
                    if server_hello.session_id == my_id {
                        let secret = my_keys.derive_shared_secret(server_hello.public_key);
                        return Ok((my_id, secret));
                    }
                }
            }
        }
        bail!("Handshake timed out")
    }

    fn send_chunk(&self, pipeline: &mut KyuPipeline, data: &[u8], block_id: u64, redundancy: f32, session_id: u64) -> Result<()> {
        let protected = pipeline.protect_block(data, block_id)?;
        let total_size = protected.len() as u32;

        let mut actual_packet_size = TARGET_PACKET_SIZE as u32;
        if total_size <= actual_packet_size {
            actual_packet_size = (total_size + 1) / 2;
        }

        let encoder = WirehairEncoder::new(&protected, actual_packet_size)?;
        let needed_packets = (total_size + actual_packet_size - 1) / actual_packet_size;
        let total_packets = (needed_packets as f32 * redundancy).ceil() as u32;

        for seq_id in 0..total_packets {
            let packet_data = encoder.encode(seq_id).map_err(|e| anyhow::anyhow!("{:?}", e))?;
            
            let mut wire_packet = Vec::with_capacity(27 + packet_data.len());
            wire_packet.push(TYPE_DATA);
            wire_packet.extend_from_slice(&session_id.to_le_bytes());
            wire_packet.extend_from_slice(&block_id.to_le_bytes());
            wire_packet.extend_from_slice(&seq_id.to_le_bytes());
            wire_packet.extend_from_slice(&total_size.to_le_bytes());
            wire_packet.extend_from_slice(&(actual_packet_size as u16).to_le_bytes());
            wire_packet.extend_from_slice(&packet_data);

            self.socket.send(&wire_packet)?;
            // Tiny sleep to prevent overflowing OS buffers
            if seq_id % 10 == 0 { thread::sleep(Duration::from_micros(10)); }
        }
        Ok(())
    }
}

pub struct KyuReceiver {
    socket: UdpSocket,
    out_dir: PathBuf,
}

impl KyuReceiver {
    /// Bind to a specific port and set the output directory for received files.
    pub fn new(bind_addr: &str, out_dir: &Path) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr)?;
        // Set non-blocking to False (Blocking Mode) for simplicity in a dedicated thread
        // or set a short timeout if you want the GUI loop to stay responsive.
        socket.set_read_timeout(Some(Duration::from_millis(100)))?; 
        
        Ok(Self {
            socket,
            out_dir: out_dir.to_path_buf(),
        })
    }

    /// Run the receiver loop. This function BLOCKS, so run it in a thread!
    /// It calls the callback `on_event` whenever something happens.
    pub fn run_loop<F>(&self, on_event: F) -> Result<()>
    where F: Fn(u64, KyuEvent) { // Callback gets (SessionID, Event)
        let mut buf = [0u8; 2048];

        // State for active transfers
        struct SessionState {
            pipeline: KyuPipeline,
            file: Option<(File, String, u64)>, // File, Name, TotalSize
            decoder: Option<(u64, WirehairDecoder)>,
            bytes_received: u64,
        }
        let mut sessions: HashMap<u64, SessionState> = HashMap::new();

        on_event(0, KyuEvent::Log(format!("Listening on {:?}", self.socket.local_addr()?)));

        loop {
            // We use a timeout so this loop isn't infinite-blocking, allowing clean shutdown if needed
            match self.socket.recv_from(&mut buf) {
                Ok((amt, src)) => {
                    if amt < 1 { continue; }
                    let packet_type = buf[0];

                    match packet_type {
                        // --- HANDSHAKE ---
                        TYPE_HANDSHAKE => {
                            if let Ok(client_hello) = bincode::deserialize::<HandshakePacket>(&buf[1..amt]) {
                                let session_id = client_hello.session_id;
                                
                                // Generate Keys
                                let server_keys = KeyExchange::new();
                                let my_public_bytes = *server_keys.public.as_bytes();
                                let shared_secret = server_keys.derive_shared_secret(client_hello.public_key);

                                // Reply
                                let reply = HandshakePacket {
                                    protocol_version: 1,
                                    session_id,
                                    public_key: my_public_bytes,
                                };
                                let mut resp = vec![TYPE_HANDSHAKE];
                                resp.extend(bincode::serialize(&reply)?);
                                self.socket.send_to(&resp, src)?;

                                // Init Session
                                sessions.insert(session_id, SessionState {
                                    pipeline: KyuPipeline::new(&shared_secret),
                                    file: None,
                                    decoder: None,
                                    bytes_received: 0,
                                });

                                on_event(session_id, KyuEvent::HandshakeComplete);
                            }
                        }

                        // --- DATA ---
                        TYPE_DATA => {
                            if amt < 27 { continue; }
                            let session_id = u64::from_le_bytes(buf[1..9].try_into().unwrap());

                            if let Some(session) = sessions.get_mut(&session_id) {
                                let block_id = u64::from_le_bytes(buf[9..17].try_into().unwrap());
                                let seq_id = u32::from_le_bytes(buf[17..21].try_into().unwrap());
                                let total_size = u32::from_le_bytes(buf[21..25].try_into().unwrap());
                                let pkt_size = u16::from_le_bytes(buf[25..27].try_into().unwrap());
                                let payload = &buf[27..amt];

                                // 1. Manage Decoder State
                                if let Some((active_id, _)) = session.decoder {
                                    if block_id != active_id { session.decoder = None; }
                                }
                                if session.decoder.is_none() {
                                    if let Ok(dec) = WirehairDecoder::new(total_size as u64, pkt_size as u32) {
                                        session.decoder = Some((block_id, dec));
                                    }
                                }

                                // 2. Decode Packet
                                if let Some((_, ref mut decoder)) = session.decoder {
                                    if let Ok(true) = decoder.decode(seq_id, payload) {
                                        // RECOVERED!
                                        if let Ok(protected) = decoder.recover() {
                                            if let Ok(raw) = session.pipeline.restore_block(&protected, block_id) {
                                                
                                                // Case A: Manifest (Block 0)
                                                if block_id == 0 {
                                                    if session.file.is_none() { // Only process once
                                                        if let Some(manifest) = SessionManifest::from_bytes(&raw) {
                                                            let safe_name = Path::new(&manifest.filename).file_name().unwrap();
                                                            let dest = self.out_dir.join(safe_name);
                                                            
                                                            if let Ok(f) = File::create(&dest) {
                                                                session.file = Some((f, manifest.filename.clone(), manifest.file_size));
                                                                on_event(session_id, KyuEvent::FileDetected { 
                                                                    name: manifest.filename, 
                                                                    size: manifest.file_size 
                                                                });
                                                            }
                                                        }
                                                    }
                                                } 
                                                // Case B: Data (Block 1..N)
                                                else if let Some((ref mut file, ref filename, total_bytes)) = session.file {
                                                    let _ = file.write_all(&raw);
                                                    session.bytes_received += raw.len() as u64;
                                                    
                                                    // Emit Progress
                                                    on_event(session_id, KyuEvent::Progress { 
                                                        current: session.bytes_received, 
                                                        total: total_bytes 
                                                    });

                                                    // Check Completion
                                                    if session.bytes_received >= total_bytes {
                                                        // Flush and finish
                                                        let _ = file.sync_all();

                                                        //construct actual path with capture
                                                        let final_path = self.out_dir.join(filename);

                                                        on_event(session_id, KyuEvent::TransferComplete { 
                                                            path: final_path
                                                        });
                                                        // Cleanup session to free memory
                                                        //sessions.remove(&session_id);
                                                    }
                                                }
                                            }
                                        }
                                        // Clear decoder to save RAM
                                        session.decoder = None;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                    // Timeout is normal (heartbeat tick), just loop again
                    continue;
                }
                Err(e) => {
                    on_event(0, KyuEvent::Error(format!("Socket Error: {}", e)));
                    break;
                }
            }
        }
        Ok(())
    }
}
