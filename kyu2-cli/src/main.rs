use clap::{Parser, Subcommand};
use anyhow::Result;
use std::path::Path;
use std::io::Write; // For flushing stdout
use kyu2_core::{init, KyuSender, KyuReceiver, KyuEvent};

#[derive(Parser)]
#[command(name = "kyu2")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a file to a destination
    Send {
        input_file: String,
        #[arg(long, default_value = "127.0.0.1:8080")]
        dest: String,
        #[arg(long, default_value_t = 1.1)]
        redundancy: f32,
    },
    /// Receive files on a port
    Recv {
        #[arg(long, default_value = "0.0.0.0:8080")]
        bind: String,
        #[arg(long, short = 'd', default_value = ".")]
        out_dir: String,
    },
}

fn main() -> Result<()> {
    // 1. Initialize Global State (Wirehair tables)
    init();

    let cli = Cli::parse();

    match cli.command {
        // --- SENDER MODE ---
        Commands::Send { input_file, dest, redundancy } => {
            let sender = KyuSender::new(&dest)?;
            
            // The "Event Loop" is a simple closure reacting to the library
            sender.send_file(Path::new(&input_file), redundancy, |event| {
                match event {
                    KyuEvent::Log(msg) => println!("{}", msg),
                    KyuEvent::HandshakeInitiated => println!(">>> [Handshake] Initiating..."),
                    KyuEvent::HandshakeComplete => println!(">>> [Handshake] Secure Tunnel Established."),
                    KyuEvent::Progress { stream_id, current, total } => {
                        print!("\r  -> [Stream {:x}] Sent {} / {} bytes...", stream_id, current, total);
                        let _ = std::io::stdout().flush();
                    },
                    KyuEvent::TransferComplete { stream_id, .. } => {
                        println!("\n>>> [Stream {:x}] Done.", stream_id);
                    },
                    KyuEvent::Error(e) => eprintln!("\n!!! Error: {}", e),
                    _ => {}
                }
            })?;
        }

        // --- RECEIVER MODE ---
        Commands::Recv { bind, out_dir } => {
            let receiver = KyuReceiver::new(&bind, Path::new(&out_dir))?;
            
            // The Receiver Loop runs forever (blocking)
            receiver.run_loop(|session_id, event| {
                match event {
                    KyuEvent::Log(msg) => println!("{}", msg),
                    KyuEvent::HandshakeComplete => {
                        println!("<<< [Handshake] Session #{:x}", session_id);
                    }
                    KyuEvent::FileDetected { stream_id, name, size } => {
                        println!("\n<<< [Session {:x} | Stream {:x}] Incoming File: '{}' ({})", session_id, stream_id, name, size);
                    }
                    KyuEvent::Progress { stream_id, current, total } => {
                        // We use carriage return (\r) to animate the progress bar
                        print!("\r  -> [Stream {:x}] {} / {} bytes...", stream_id, current, total);
                        let _ = std::io::stdout().flush();
                    }
                    KyuEvent::TransferComplete { stream_id, path } => {
                        println!("\n<<< [Stream {:x}] Transfer Complete! Saved to: {:?}", stream_id, path);
                    }
                    KyuEvent::Error(e) => eprintln!("\n!!! Error: {}", e),
                    _ => {}
                }
            })?;
        }
    }

    Ok(())
}
