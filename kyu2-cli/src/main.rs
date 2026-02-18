use clap::{Parser, Subcommand};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::path::Path;
use std::thread;
use std::time::Duration;
use kyu2_core::{init, KyuPipeline, WirehairEncoder, WirehairDecoder, SessionManifest, KeyExchange, HandshakePacket};

use rand;

#[derive(Parser)]
#[command(name = "kyu2")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Send {
        input_file: String,
        #[arg(long, default_value = "127.0.0.1:8080")]
        dest: String,
        #[arg(long, default_value_t = 1.1)]
        redundancy: f32,
    },
    Recv {
        #[arg(long, default_value = "0.0.0.0:8080")]
        bind: String,
        #[arg(long, short = 'd', default_value = ".")]
        out_dir: String,
    },
}

const BLOCK_SIZE: usize = 1024 * 64; 
const TARGET_PACKET_SIZE: usize = 1400;

// Packet Type Headers
const TYPE_DATA: u8 = b'D';
const TYPE_HANDSHAKE: u8 = b'H';

fn main() -> Result<()> {
    init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Send { input_file, dest, redundancy } => {
            send_file(&input_file, &dest, redundancy)
        }
        Commands::Recv { bind, out_dir } => {
            recv_file(&bind, &out_dir)
        }
    }
}

// --- SENDER LOGIC ---

fn send_file(path: &str, dest: &str, redundancy: f32) -> Result<()> {
    let file_path = Path::new(path);
    let filename = file_path.file_name().unwrap().to_str().unwrap();
    let file_size = file_path.metadata()?.len();
    
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(dest)?;

    // 1. HANDSHAKE (Get the unique session key)
    let (session_id, shared_key) = perform_handshake(&socket, dest)?;
    let mut pipeline = KyuPipeline::new(&shared_key);

    println!(">>> Sending '{}' ({}) via Session #{:x}...", filename, file_size, session_id);

    // 2. SEND MANIFEST (Block 0)
    let manifest = SessionManifest::new(filename, file_size);
    let manifest_bytes = manifest.to_bytes();
    send_chunk(&socket, &mut pipeline, &manifest_bytes, 0, 2.0, session_id)?;

    // 3. SEND DATA (Blocks 1..N)
    let mut file = File::open(path)?;
    let mut buffer = vec![0u8; BLOCK_SIZE];
    let mut block_id = 1u64;

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 { break; }

        let chunk = &buffer[0..bytes_read];
        send_chunk(&socket, &mut pipeline, chunk, block_id, redundancy, session_id)?;
        
        let progress = (block_id as u64 * BLOCK_SIZE as u64).min(file_size);
        print!("\r  -> [Data] Sent {} / {} bytes...", progress, file_size);
        std::io::stdout().flush()?;

        block_id += 1;
    }

    println!("\n>>> Done. Sent {} blocks.", block_id);
    Ok(())
}

fn perform_handshake(socket: &UdpSocket, _dest: &str) -> Result<(u64, [u8; 32])> {
    println!(">>> [Handshake] Negotiating keys...");
    
    let my_keys = KeyExchange::new();
    let my_id = rand::random::<u64>();

    let hello = HandshakePacket {
        protocol_version: 1,
        session_id: my_id,
        public_key: *my_keys.public.as_bytes(),
    };
    
    // Construct Packet: [TYPE_HANDSHAKE] [Bincode Blob]
    let mut packet = vec![TYPE_HANDSHAKE];
    packet.extend(bincode::serialize(&hello)?);

    // Retry Logic
    let mut buf = [0u8; 1024];
    for _ in 0..5 {
        socket.send(&packet)?;
        
        socket.set_read_timeout(Some(Duration::from_millis(500)))?;
        if let Ok((amt, _)) = socket.recv_from(&mut buf) {
            if amt > 1 && buf[0] == TYPE_HANDSHAKE {
                let server_hello: HandshakePacket = bincode::deserialize(&buf[1..amt])?;
                if server_hello.session_id == my_id {
                    let secret = my_keys.derive_shared_secret(server_hello.public_key);
                    println!(">>> [Handshake] Secure Tunnel Established.");
                    return Ok((my_id, secret));
                }
            }
        }
    }
    anyhow::bail!("Handshake timed out");
}

fn send_chunk(socket: &UdpSocket, pipeline: &mut KyuPipeline, data: &[u8], block_id: u64, redundancy: f32, session_id: u64) -> Result<()> {
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
        
        // Header: [TYPE_DATA] [SessionID: u64] [BlockID: u64] [SeqID: u32] [Total: u32] [Pkt: u16] [Payload]
        let mut wire_packet = Vec::with_capacity(27 + packet_data.len());
        wire_packet.push(TYPE_DATA);
        wire_packet.extend_from_slice(&session_id.to_le_bytes());
        wire_packet.extend_from_slice(&block_id.to_le_bytes());
        wire_packet.extend_from_slice(&seq_id.to_le_bytes());
        wire_packet.extend_from_slice(&total_size.to_le_bytes());
        wire_packet.extend_from_slice(&(actual_packet_size as u16).to_le_bytes());
        wire_packet.extend_from_slice(&packet_data);

        socket.send(&wire_packet)?;
        thread::sleep(Duration::from_micros(10));
    }
    Ok(())
}

// --- RECEIVER LOGIC ---

fn recv_file(bind_addr: &str, out_dir: &str) -> Result<()> {
    println!("<<< Listening on {}...", bind_addr);
    let socket = UdpSocket::bind(bind_addr)?;
    
    // Store active sessions: SessionID -> (Pipeline, ActiveFile, DecoderState)
    struct SessionState {
        pipeline: KyuPipeline,
        file: Option<(File, String)>,
        decoder: Option<(u64, WirehairDecoder)>,
    }
    let mut sessions: HashMap<u64, SessionState> = HashMap::new();
    let mut buf = [0u8; 2048]; 

    loop {
        let (amt, src) = socket.recv_from(&mut buf)?;
        if amt < 1 { continue; }

        let packet_type = buf[0];

        match packet_type {
            TYPE_HANDSHAKE => {
                // Client Hello
                if let Ok(client_hello) = bincode::deserialize::<HandshakePacket>(&buf[1..amt]) {
                    println!("<<< [Handshake] New Session Request: #{:x}", client_hello.session_id);
                    
                    let server_keys = KeyExchange::new();

                    let my_public_bytes = *server_keys.public.as_bytes();
                    let shared_secret = server_keys.derive_shared_secret(client_hello.public_key);
                    
                    // Reply with Server Hello
                    let reply = HandshakePacket {
                        protocol_version: 1,
                        session_id: client_hello.session_id,
                        public_key: my_public_bytes,
                    };

                    let mut resp = vec![TYPE_HANDSHAKE];
                    resp.extend(bincode::serialize(&reply)?);
                    socket.send_to(&resp, src)?;

                    // Init Session
                    sessions.insert(client_hello.session_id, SessionState {
                        pipeline: KyuPipeline::new(&shared_secret),
                        file: None,
                        decoder: None,
                    });
                }
            }
            TYPE_DATA => {
                if amt < 27 { continue; } // Min Header size
                let session_id = u64::from_le_bytes(buf[1..9].try_into()?);
                
                if let Some(session) = sessions.get_mut(&session_id) {
                    let block_id = u64::from_le_bytes(buf[9..17].try_into()?);
                    let seq_id = u32::from_le_bytes(buf[17..21].try_into()?);
                    let total_size = u32::from_le_bytes(buf[21..25].try_into()?);
                    let pkt_size = u16::from_le_bytes(buf[25..27].try_into()?);
                    let payload = &buf[27..amt];

                    // 1. Decoder Management
                    if let Some((active_id, _)) = session.decoder {
                        if block_id != active_id { session.decoder = None; }
                    }
                    if session.decoder.is_none() {
                        if let Ok(dec) = WirehairDecoder::new(total_size as u64, pkt_size as u32) {
                            session.decoder = Some((block_id, dec));
                        }
                    }

                    // 2. Decode
                    if let Some((_, ref mut decoder)) = session.decoder {
                        if let Ok(true) = decoder.decode(seq_id, payload) {
                            // Recovered!
                            if let Ok(protected) = decoder.recover() {
                                if let Ok(raw) = session.pipeline.restore_block(&protected, block_id) {
                                    
                                    // Block 0: Manifest
                                    if block_id == 0 {
                                        // ignore duplicate block 0 decodes
                                        if session.file.is_some() {
                                            session.decoder = None;
                                            continue;
                                        }
                                        if let Some(manifest) = SessionManifest::from_bytes(&raw) {
                                            println!("<<< [Session {:x}] File: '{}'", session_id, manifest.filename);
                                            let safe_name = Path::new(&manifest.filename).file_name().unwrap();
                                            let dest = Path::new(out_dir).join(safe_name);
                                            if let Ok(f) = File::create(dest) {
                                                session.file = Some((f, manifest.filename));
                                            }
                                        }
                                    } 
                                    // Block N: Data
                                    else if let Some((ref mut file, _)) = session.file {
                                        let _ = file.write_all(&raw);
                                        print!("\r  -> Block #{} Written.", block_id);
                                        std::io::stdout().flush()?;
                                    }
                                }
                            }
                            // Clear decoder to save memory
                            session.decoder = None;
                        }
                    }
                }
            }
            _ => {} // Unknown packet
        }
    }
}
