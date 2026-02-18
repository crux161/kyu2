use clap::{Parser, Subcommand};
use anyhow::Result;
use std::path::Path;
use std::io::Write; 
use std::time::Instant;
use kyu2_core::{init, KyuSender, KyuReceiver, KyuEvent};
use std::cell::RefCell;

#[derive(Parser)]
#[command(name = "kyu2", about = "Zen-Mode UDP File Transfer Engine")]
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
        /// Max bandwidth in Bytes per second (Default: 5 MB/s)
        #[arg(long, default_value_t = 5_000_000)]
        limit: u64,
    },
    Recv {
        #[arg(long, default_value = "0.0.0.0:8080")]
        bind: String,
        #[arg(long, short = 'd', default_value = ".")]
        out_dir: String,
    },
}

fn main() -> Result<()> {
    init();
    let cli = Cli::parse();

    match cli.command {
        // --- SENDER MODE ---
        Commands::Send { input_file, dest, redundancy, limit } => {
            let mut sender = KyuSender::new(&dest)?;
            let file_size = Path::new(&input_file).metadata()?.len();
            let start_time = Instant::now();
            
            println!(">>> Initiating Benchmark: target={} | limit={} B/s | redundancy={}x", dest, limit, redundancy);

            sender.send_file(Path::new(&input_file), redundancy, limit, |event| {
                match event {
                    KyuEvent::HandshakeComplete => {
                        println!(">>> [Handshake] Secure Tunnel Established in {:.2?}", start_time.elapsed());
                    },
                    KyuEvent::Progress { stream_id, current, total } => {
                        let elapsed = start_time.elapsed().as_secs_f64().max(0.001);
                        let mbps = (current as f64 * 8.0) / elapsed / 1_000_000.0;
                        print!("\r  -> [Stream {:x}] Sent {} / {} bytes ({:.2} Mbps) ...", stream_id, current, total, mbps);
                        let _ = std::io::stdout().flush();
                    },
                    KyuEvent::TransferComplete { stream_id, .. } => {
                        let elapsed = start_time.elapsed();
                        let mbps = (file_size as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0;
                        println!("\n\n>>> [Stream {:x}] DONE.", stream_id);
                        println!("    -> Time: {:.2?}", elapsed);
                        println!("    -> Avg Speed: {:.2} Mbps", mbps);
                    },
                    KyuEvent::EarlyTermination { stream_id } => {
                        println!("\n>>> [Stream {:x}] Target verified receipt. Terminating redundant tail early!", stream_id);
                    }
                    KyuEvent::Error(e) => eprintln!("\n!!! Error: {}", e),
                    _ => {}
                }
            })?;
        }
// --- RECEIVER MODE ---
        Commands::Recv { bind, out_dir } => {
            let receiver = KyuReceiver::new(&bind, Path::new(&out_dir))?;
            
            // Wrap the HashMap in a RefCell to allow interior mutability inside the Fn closure
            let start_times = RefCell::new(std::collections::HashMap::new());

            receiver.run_loop(|session_id, event| {
                match event {
                    KyuEvent::Log(msg) => println!("{}", msg),
                    KyuEvent::HandshakeComplete => {
                        println!("<<< [Handshake] Session #{:x} connected.", session_id);
                    }
                    KyuEvent::FileDetected { stream_id, name, size } => {
                        println!("\n<<< [Session {:x} | Stream {:x}] Incoming File: '{}' ({})", session_id, stream_id, name, size);
                        // Use .borrow_mut() to modify the map
                        start_times.borrow_mut().insert(stream_id, Instant::now());
                    }
                    KyuEvent::Progress { stream_id, current, total } => {
                        // Use .borrow() to read the map
                        if let Some(start) = start_times.borrow().get(&stream_id) {
                            let elapsed = start.elapsed().as_secs_f64().max(0.001);
                            let mbps = (current as f64 * 8.0) / elapsed / 1_000_000.0;
                            print!("\r  -> [Stream {:x}] {} / {} bytes ({:.2} Mbps) ...", stream_id, current, total, mbps);
                            let _ = std::io::stdout().flush();
                        }
                    }
                    KyuEvent::TransferComplete { stream_id, path } => {
                        // Use .borrow_mut() to remove the entry
                        if let Some(start) = start_times.borrow_mut().remove(&stream_id) {
                            let elapsed = start.elapsed();
                            let file_size = path.metadata().map(|m| m.len()).unwrap_or(0);
                            let mbps = (file_size as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0;
                            
                            println!("\n\n<<< [Stream {:x}] TRANSFER COMPLETE!", stream_id);
                            println!("    -> Saved to: {:?}", path);
                            println!("    -> Time: {:.2?}", elapsed);
                            println!("    -> Avg Speed: {:.2} Mbps", mbps);
                        }
                    }
                    KyuEvent::Error(e) => eprintln!("\n!!! Error: {}", e),
                    _ => {}
                }
            })?;
        }

    }

    Ok(())
}
