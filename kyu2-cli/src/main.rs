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

fn main() -> Result<()> {
    // 1. Initialize Global State (Wirehair tables)
    init();

    let cli = Cli::parse();

    match cli.command {
        // --- SENDER MODE ---
        Commands::Send { input_file, dest, redundancy } => {
            let sender = KyuSender::new(&dest)?;
            
            // The "Event Loop" is now just a closure!
            sender.send_file(Path::new(&input_file), redundancy, |event| {
                match event {
                    KyuEvent::Log(msg) => println!("{}", msg),
                    KyuEvent::HandshakeInitiated => println!(">>> [Handshake] Initiating..."),
                    KyuEvent::HandshakeComplete => println!(">>> [Handshake] Secure Tunnel Established."),
                    KyuEvent::Progress { current, total } => {
                        print!("\r  -> [Data] Sent {} / {} bytes...", current, total);
                        let _ = std::io::stdout().flush();
                    },
                    KyuEvent::TransferComplete { .. } => println!("\n>>> Done."),
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
                        println!("<<< [Handshake] New Session Established: #{:x}", session_id);
                    }
                    KyuEvent::FileDetected { name, size } => {
                        println!("<<< [Session {:x}] Incoming File: '{}' ({})", session_id, name, size);
                    }
                    KyuEvent::Progress { current, total } => {
                        // We only show progress for the active session in this simple CLI
                        print!("\r  -> [Session {:x}] {} / {} bytes...", session_id, current, total);
                        let _ = std::io::stdout().flush();
                    }
                    KyuEvent::TransferComplete { path } => {
                        println!("\n<<< [Session {:x}] Transfer Complete! Saved to: {:?}", session_id, path);
                    }
                    KyuEvent::Error(e) => eprintln!("\n!!! Error: {}", e),
                    _ => {}
                }
            })?;
        }
    }

    Ok(())
}
