use clap::{Parser, Subcommand};
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::path::Path;
use std::thread;
use std::time::Duration;
use kyu2_core::{init, KyuPipeline, WirehairEncoder, WirehairDecoder, SessionManifest};

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
        /// Optional: Directory to save files (defaults to current dir)
        #[arg(long, short = 'd', default_value = ".")]
        out_dir: String,
    },
}

const BLOCK_SIZE: usize = 1024 * 64; 
const TARGET_PACKET_SIZE: usize = 1400;

fn main() -> Result<()> {
    init();
    let cli = Cli::parse();
    let secret_key = [0x77u8; 32];

    match cli.command {
        Commands::Send { input_file, dest, redundancy } => {
            send_file(&input_file, &dest, &secret_key, redundancy)
        }
        Commands::Recv { bind, out_dir } => {
            recv_file(&bind, &out_dir, &secret_key)
        }
    }
}

fn send_file(path: &str, dest: &str, key: &[u8; 32], redundancy: f32) -> Result<()> {
    let file_path = Path::new(path);
    let filename = file_path.file_name().unwrap().to_str().unwrap();
    let file_size = file_path.metadata()?.len();
    
    println!(">>> Sending '{}' ({}) to {}...", filename, file_size, dest);

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(dest)?;
    let mut pipeline = KyuPipeline::new(key);

    // --- STEP 1: Send Manifest (Block #0) ---
    // We send this with HIGHER redundancy (2.0x) to ensure it arrives first/fast.
    let manifest = SessionManifest::new(filename, file_size);
    let manifest_bytes = manifest.to_bytes();
    
    send_chunk(&socket, &mut pipeline, &manifest_bytes, 0, 2.0)?;
    println!("  -> [Meta] Manifest sent (Block #0)");

    // --- STEP 2: Send File Content (Block #1..N) ---
    let mut file = File::open(path)?;
    let mut buffer = vec![0u8; BLOCK_SIZE];
    let mut block_id = 1u64; // Data starts at 1

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 { break; }

        let chunk = &buffer[0..bytes_read];
        send_chunk(&socket, &mut pipeline, chunk, block_id, redundancy)?;
        
        // Progress Indicator
        let progress = (block_id as u64 * BLOCK_SIZE as u64).min(file_size);
        print!("\r  -> [Data] Sent {} / {} bytes...", progress, file_size);
        std::io::stdout().flush()?;

        block_id += 1;
    }

    println!("\n>>> Done. Sent {} blocks.", block_id);
    Ok(())
}

fn send_chunk(socket: &UdpSocket, pipeline: &mut KyuPipeline, data: &[u8], block_id: u64, redundancy: f32) -> Result<()> {
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
        
        let mut wire_packet = Vec::with_capacity(18 + packet_data.len());
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

fn recv_file(bind_addr: &str, out_dir: &str, key: &[u8; 32]) -> Result<()> {
    println!("<<< Listening on {}...", bind_addr);
    let socket = UdpSocket::bind(bind_addr)?;
    let pipeline = KyuPipeline::new(key);
    
    // State Machine
    let mut current_decoder: Option<(u64, WirehairDecoder)> = None;
    let mut active_file: Option<(File, String, u64)> = None; // File, Name, Size
    let mut buf = [0u8; 2048]; 

    loop {
        let (amt, _) = socket.recv_from(&mut buf)?;
        if amt < 18 { continue; }

        let block_id = u64::from_le_bytes(buf[0..8].try_into()?);
        let seq_id = u32::from_le_bytes(buf[8..12].try_into()?);
        let total_size = u32::from_le_bytes(buf[12..16].try_into()?);
        let pkt_size = u16::from_le_bytes(buf[16..18].try_into()?);
        let payload = &buf[18..amt];

        // 1. New Block Detection
        if let Some((active_id, _)) = current_decoder {
            if block_id != active_id {
                current_decoder = None; // Reset if ID changed
            }
        }

        // 2. Decoder Init
        if current_decoder.is_none() {
            let dec = WirehairDecoder::new(total_size as u64, pkt_size as u32)
                .map_err(|e| anyhow::anyhow!("Decoder Init: {:?}", e))?;
            current_decoder = Some((block_id, dec));
        }

        // 3. Process Packet
        if let Some((_, ref mut decoder)) = current_decoder {
            if let Ok(true) = decoder.decode(seq_id, payload) {
                // RECOVERY COMPLETE
                let protected = decoder.recover()?;
                let raw_data = pipeline.restore_block(&protected, block_id)?;

                // --- HANDLING BLOCK 0 (MANIFEST) ---
                if block_id == 0 {
                    if let Some(manifest) = SessionManifest::from_bytes(&raw_data) {
                        println!("<<< [Meta] Incoming File: '{}' ({})", manifest.filename, manifest.file_size);
                        
                        // Security: Sanitize filename (prevent "../../../etc/passwd")
                        let safe_name = Path::new(&manifest.filename).file_name().unwrap();
                        let dest_path = Path::new(out_dir).join(safe_name);
                        
                        let file = File::create(&dest_path)?;
                        active_file = Some((file, manifest.filename, manifest.file_size));
                        println!("  -> Created file at {:?}", dest_path);
                    }
                } 
                // --- HANDLING DATA BLOCKS (1..N) ---
                else {
                    if let Some((ref mut file, _, _)) = active_file {
                        file.write_all(&raw_data)?;
                        print!("\r  -> Block #{} Written.", block_id);
                        std::io::stdout().flush()?;
                    } else {
                        eprintln!("\nWarning: Received Block #{} but have no open file! (Missed Block 0?)", block_id);
                    }
                }
                
                // Done with this block, invalidate decoder so we don't process redundant packets
                current_decoder = None; 
            }
        }
    }
}
