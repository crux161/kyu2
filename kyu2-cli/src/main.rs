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
    /// Receive a file (and optionally relay it)
    Recv {
        /// Port to listen on (e.g., 8080)
        #[arg(long, default_value = "0.0.0.0:8080")]
        bind: String,
        /// Where to save the output
        #[arg(long, short = 'o')]
        output_file: String,
        /// Optional: Relay recovered blocks to this address (e.g., 127.0.0.1:9090)
        #[arg(long)]
        relay: Option<String>,
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
        Commands::Recv { bind, output_file, relay } => {
            recv_file(&bind, &output_file, &secret_key, relay)
        }
    }
}

fn send_file(path: &str, dest: &str, key: &[u8; 32], redundancy: f32) -> Result<()> {
    println!(">>> Sending {} to {} (Redundancy: {}x)", path, dest, redundancy);
    
    let mut file = File::open(path).context("Could not open input file")?;
    let mut pipeline = KyuPipeline::new(key);
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(dest)?;

    let mut buffer = vec![0u8; BLOCK_SIZE];
    let mut block_id = 0u64;

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 { break; } 

        let chunk = &buffer[0..bytes_read];
        println!("Processing Block #{} ({} bytes)...", block_id, bytes_read);

        let protected = pipeline.protect_block(chunk, block_id)?;
        let total_size = protected.len() as u32;

        let mut actual_packet_size = TARGET_PACKET_SIZE as u32;
        if total_size <= actual_packet_size {
            actual_packet_size = (total_size + 1) / 2;
        }

        let encoder = WirehairEncoder::new(&protected, actual_packet_size)?;
        
        // Calculate packet counts
        let needed_packets = (total_size + actual_packet_size - 1) / actual_packet_size;
        let total_packets = (needed_packets as f32 * redundancy).ceil() as u32;

        println!("  -> Sending {} packets...", total_packets);

        for seq_id in 0..total_packets {
            send_packet(&socket, &encoder, block_id, seq_id, total_size, actual_packet_size as u16)?;
            thread::sleep(Duration::from_micros(10));
        }

        block_id += 1;
    }
    Ok(())
}

fn recv_file(bind_addr: &str, out_path: &str, key: &[u8; 32], relay_dest: Option<String>) -> Result<()> {
    println!("<<< Listening on {}...", bind_addr);
    if let Some(ref r) = relay_dest {
        println!("<<< [RELAY MODE ACTIVE] Forwarding to {}", r);
    }
    
    let socket = UdpSocket::bind(bind_addr)?;
    let mut pipeline = KyuPipeline::new(key);
    let mut out_file = File::create(out_path)?;
    
    let mut current_decoder: Option<(u64, WirehairDecoder)> = None;
    let mut current_block_complete = false;
    let mut buf = [0u8; 2048]; 

    loop {
        let (amt, _) = socket.recv_from(&mut buf)?;
        if amt < 18 { continue; }

        let block_id = u64::from_le_bytes(buf[0..8].try_into()?);
        let seq_id = u32::from_le_bytes(buf[8..12].try_into()?);
        let total_size = u32::from_le_bytes(buf[12..16].try_into()?);
        let pkt_size = u16::from_le_bytes(buf[16..18].try_into()?);
        let payload = &buf[18..amt];

        if let Some((active_id, _)) = current_decoder {
            if block_id > active_id {
                current_decoder = None; 
                current_block_complete = false;
            } else if block_id < active_id || current_block_complete {
                continue; 
            }
        }

        if current_decoder.is_none() {
            println!("Receiving Block #{}...", block_id);
            let dec = WirehairDecoder::new(total_size as u64, pkt_size as u32)
                .map_err(|e| anyhow::anyhow!("Decoder Init: {:?}", e))?;
            current_decoder = Some((block_id, dec));
        }

        if let Some((_, ref mut decoder)) = current_decoder {
            match decoder.decode(seq_id, payload) {
                Ok(true) => {
                    println!("  -> Block #{} Recovered!", block_id);
                    let protected = decoder.recover()?;
                    
                    // 1. Write to Disk
                    match pipeline.restore_block(&protected, block_id) {
                        Ok(raw) => {
                            out_file.write_all(&raw)?;
                            current_block_complete = true;
                            println!("  -> Wrote to disk.");

                            // 2. RELAY LOGIC (The New Part)
                            if let Some(ref dest) = relay_dest {
                                relay_block(dest, &protected, block_id, pkt_size as u32)?;
                            }
                        }
                        Err(e) => eprintln!("  -> Decrypt Error: {}", e),
                    }
                }
                Ok(false) => { /* Waiting */ }
                Err(e) => eprintln!("Decode Error: {:?}", e),
            }
        }
    }
}

/// Helper to generate FRESH packets and relay them
fn relay_block(dest: &str, protected_data: &[u8], block_id: u64, packet_size: u32) -> Result<()> {
    println!("  -> [RELAY] Regenerating packets for {}...", dest);
    
    // We create a NEW encoder from the recovered data
    let encoder = WirehairEncoder::new(protected_data, packet_size)?;
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(dest)?;

    let total_size = protected_data.len() as u32;
    let needed_packets = (total_size + packet_size - 1) / packet_size;
    // Relay sends 10% redundancy
    let total_packets = (needed_packets as f32 * 1.1).ceil() as u32;

    // We start seq_id at 100000 just to prove these are different packets 
    // (though mathematically it doesn't matter, Wirehair handles any ID)
    let seq_offset = 100000;

    for i in 0..total_packets {
        let seq_id = i + seq_offset;
        send_packet(&socket, &encoder, block_id, seq_id, total_size, packet_size as u16)?;
        // No sleep needed for relay usually, but good for safety
        thread::sleep(Duration::from_micros(5));
    }
    
    Ok(())
}

fn send_packet(socket: &UdpSocket, encoder: &WirehairEncoder, block_id: u64, seq_id: u32, total_size: u32, pkt_size: u16) -> Result<()> {
    let packet_data = encoder.encode(seq_id).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    
    let mut wire_packet = Vec::with_capacity(18 + packet_data.len());
    wire_packet.extend_from_slice(&block_id.to_le_bytes());
    wire_packet.extend_from_slice(&seq_id.to_le_bytes());
    wire_packet.extend_from_slice(&total_size.to_le_bytes());
    wire_packet.extend_from_slice(&pkt_size.to_le_bytes());
    wire_packet.extend_from_slice(&packet_data);

    socket.send(&wire_packet)?;
    Ok(())
}
