use clap::{Parser, Subcommand};
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;
use kyu2_core::{init, KyuPipeline, WirehairEncoder, WirehairDecoder};

#[derive(Parser)]
#[command(name = "kyu2")]
#[command(about = "Zen-Mode UDP File Transfer Protocol")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a file to a destination
    Send {
        /// File path to send
        input_file: String,
        /// Destination address (e.g., 127.0.0.1:8080)
        #[arg(long, default_value = "127.0.0.1:8080")]
        dest: String,
        /// Redundancy multiplier (e.g., 1.2 = send 20% extra repair packets)
        #[arg(long, default_value_t = 1.1)]
        redundancy: f32,
    },
    /// Receive a file on a port
    Recv {
        /// Port to listen on (e.g., 8080)
        #[arg(long, default_value = "0.0.0.0:8080")]
        bind: String,
        /// Where to save the output
        #[arg(long, short = 'o')]
        output_file: String,
    },
}

// 64KB Block Size is a good sweet spot for UDP
const BLOCK_SIZE: usize = 1024 * 64; 
// 1400 bytes fits safely in a standard Ethernet MTU (1500)
const TARGET_PACKET_SIZE: usize = 1400;

fn main() -> Result<()> {
    init(); // Init Wirehair tables

    let cli = Cli::parse();
    let secret_key = [0x77u8; 32]; // Shared secret

    match cli.command {
        Commands::Send { input_file, dest, redundancy } => {
            send_file(&input_file, &dest, &secret_key, redundancy)
        }
        Commands::Recv { bind, output_file } => {
            recv_file(&bind, &output_file, &secret_key)
        }
    }
}

fn send_file(path: &str, dest: &str, key: &[u8; 32], redundancy: f32) -> Result<()> {
    println!(">>> Sending {} to {} (Redundancy: {}x)", path, dest, redundancy);
    
    let mut file = File::open(path).context("Could not open input file")?;
    let mut pipeline = KyuPipeline::new(key);
    let socket = UdpSocket::bind("0.0.0.0:0").context("Could not bind UDP socket")?;
    socket.connect(dest).context("Connect failed")?;

    let mut buffer = vec![0u8; BLOCK_SIZE];
    let mut block_id = 0u64;

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 { break; } // EOF

        let chunk = &buffer[0..bytes_read];
        println!("Processing Block #{} ({} bytes raw)...", block_id, bytes_read);

        // 1. Pipeline Protect (Compress + Encrypt)
        let protected = pipeline.protect_block(chunk, block_id)?;
        let total_size = protected.len() as u32;

        // 2. Dynamic Packet Sizing (The Fix)
        // Wirehair demands N >= 2. If data is small, shrink packet size.
        let mut actual_packet_size = TARGET_PACKET_SIZE as u32;
        if total_size <= actual_packet_size {
            actual_packet_size = (total_size + 1) / 2;
        }

        // 3. FEC Encode
        let encoder = WirehairEncoder::new(&protected, actual_packet_size)
            .map_err(|e| anyhow::anyhow!("FEC Init Error: {:?}", e))?;

        let needed_packets = (total_size + actual_packet_size - 1) / actual_packet_size;
        let total_packets = (needed_packets as f32 * redundancy).ceil() as u32;

        println!("  -> Size Encrypted: {} bytes (Packet Size: {})", total_size, actual_packet_size);
        println!("  -> Sending {} packets ({} systematic + repairs)", total_packets, needed_packets);

        // 4. Blast Packets
        for seq_id in 0..total_packets {
            let packet_data = encoder.encode(seq_id)
                .map_err(|e| anyhow::anyhow!("Encode Error: {:?}", e))?;
            
            // --- NEW HEADER FORMAT (18 bytes) ---
            // [BlockID: u64] [SeqID: u32] [TotalSize: u32] [PacketSize: u16] [Data...]
            let mut wire_packet = Vec::with_capacity(18 + packet_data.len());
            wire_packet.extend_from_slice(&block_id.to_le_bytes());
            wire_packet.extend_from_slice(&seq_id.to_le_bytes());
            wire_packet.extend_from_slice(&total_size.to_le_bytes());       // <--- NEW
            wire_packet.extend_from_slice(&(actual_packet_size as u16).to_le_bytes()); // <--- NEW
            wire_packet.extend_from_slice(&packet_data);

            socket.send(&wire_packet)?;
            thread::sleep(Duration::from_micros(10));
        }

        block_id += 1;
    }

    println!(">>> Done. Sent {} blocks.", block_id);
    Ok(())
}

fn recv_file(bind_addr: &str, out_path: &str, key: &[u8; 32]) -> Result<()> {
    println!("<<< Listening on {}...", bind_addr);
    
    let socket = UdpSocket::bind(bind_addr).context("Could not bind socket")?;
    let mut pipeline = KyuPipeline::new(key);
    let mut out_file = File::create(out_path).context("Could not create output file")?;
    
    let mut current_decoder: Option<(u64, WirehairDecoder)> = None;
    let mut current_block_complete = false;
    let mut buf = [0u8; 2048]; 

    loop {
        let (amt, _src) = socket.recv_from(&mut buf)?;
        if amt < 18 { continue; } // Header too small

        // --- PARSE NEW HEADER ---
        let block_id = u64::from_le_bytes(buf[0..8].try_into()?);
        let seq_id = u32::from_le_bytes(buf[8..12].try_into()?);
        let total_size = u32::from_le_bytes(buf[12..16].try_into()?); // <--- NEW
        let pkt_size = u16::from_le_bytes(buf[16..18].try_into()?);   // <--- NEW
        let payload = &buf[18..amt];

        // State Machine
        if let Some((active_id, _)) = current_decoder {
            if block_id > active_id {
                current_decoder = None; // Move to next block
                current_block_complete = false;
            } else if block_id < active_id || current_block_complete {
                continue; // Old or already done
            }
        }

        // Initialize Decoder with EXACT geometry from header
        if current_decoder.is_none() {
            println!("Receiving Block #{} (Size: {}, Pkt: {})...", block_id, total_size, pkt_size);
            
            let dec = WirehairDecoder::new(total_size as u64, pkt_size as u32)
                .map_err(|e| anyhow::anyhow!("Decoder Init: {:?}", e))?;
            current_decoder = Some((block_id, dec));
        }

        // Decode
        if let Some((_, ref mut decoder)) = current_decoder {
            match decoder.decode(seq_id, payload) {
                Ok(true) => {
                    println!("  -> Block #{} Recovered!", block_id);
                    let protected = decoder.recover().map_err(|e| anyhow::anyhow!("Recover: {:?}", e))?;
                    
                    // Restore (Decrypt + Decompress)
                    match pipeline.restore_block(&protected, block_id) {
                        Ok(raw) => {
                            out_file.write_all(&raw)?;
                            current_block_complete = true;
                            println!("  -> Wrote to disk.");
                        }
                        Err(e) => eprintln!("  -> Decrypt Error: {}", e),
                    }
                }
                Ok(false) => { /* Need more droplets */ }
                Err(e) => eprintln!("Decode Error: {:?}", e),
            }
        }
    }
}
