use anyhow::Result;
use clap::{Parser, Subcommand};
use kyu2_core::{init, parse_psk_hex, KyuEvent, KyuReceiver, KyuSender};
use std::cell::RefCell;
use std::io::Write;
use std::path::Path;
use std::time::Instant;

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
        /// 32-byte PSK in hex; falls back to KYU2_PSK env var when omitted.
        #[arg(long)]
        psk: Option<String>,
        #[arg(long, default_value_t = 1.2)]
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
        /// 32-byte PSK in hex; falls back to KYU2_PSK env var when omitted.
        #[arg(long)]
        psk: Option<String>,
    },
}

fn main() -> Result<()> {
    init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Send {
            input_file,
            dest,
            psk,
            redundancy,
            limit,
        } => {
            let mut sender = if let Some(psk_hex) = psk {
                KyuSender::new_with_psk(&dest, parse_psk_hex(&psk_hex)?)?
            } else {
                KyuSender::new(&dest)?
            };

            let file_size = Path::new(&input_file).metadata()?.len();
            let start_time = Instant::now();

            println!(
                ">>> Initiating transfer: target={} | limit={} B/s | redundancy={}x",
                dest, limit, redundancy
            );

            sender.send_file(Path::new(&input_file), redundancy, limit, |event| match event {
                KyuEvent::HandshakeComplete => {
                    println!(
                        ">>> [Handshake] Secure Tunnel Established in {:.2?}",
                        start_time.elapsed()
                    );
                }
                KyuEvent::Progress {
                    stream_id,
                    trace_id,
                    current,
                    total,
                } => {
                    let elapsed = start_time.elapsed().as_secs_f64().max(0.001);
                    let mbps = (current as f64 * 8.0) / elapsed / 1_000_000.0;
                    print!(
                        "\r  -> [Stream {:x} | Trace {:016x}] Sent {} / {} bytes ({:.2} Mbps) ...",
                        stream_id, trace_id, current, total, mbps
                    );
                    let _ = std::io::stdout().flush();
                }
                KyuEvent::TransferComplete {
                    stream_id,
                    trace_id,
                    ..
                } => {
                    let elapsed = start_time.elapsed();
                    let mbps = (file_size as f64 * 8.0) / elapsed.as_secs_f64().max(0.001) / 1_000_000.0;
                    println!("\n\n>>> [Stream {:x} | Trace {:016x}] DONE.", stream_id, trace_id);
                    println!("    -> Time: {:.2?}", elapsed);
                    println!("    -> Avg Speed: {:.2} Mbps", mbps);
                }
                KyuEvent::EarlyTermination {
                    stream_id,
                    trace_id,
                } => {
                    println!(
                        "\n>>> [Stream {:x} | Trace {:016x}] Target verified receipt. Terminating redundant tail early.",
                        stream_id, trace_id
                    );
                }
                KyuEvent::Fault {
                    code,
                    message,
                    stream_id,
                    trace_id,
                    ..
                } => {
                    eprintln!(
                        "\n!!! [{}] stream={:?} trace={:?}: {}",
                        code.as_str(),
                        stream_id,
                        trace_id.map(|v| format!("{:016x}", v)),
                        message
                    );
                }
                KyuEvent::Error(error) => eprintln!("\n!!! Error: {}", error),
                _ => {}
            })?;
        }
        Commands::Recv { bind, out_dir, psk } => {
            let receiver = if let Some(psk_hex) = psk {
                KyuReceiver::new_with_psk(&bind, Path::new(&out_dir), parse_psk_hex(&psk_hex)?)?
            } else {
                KyuReceiver::new(&bind, Path::new(&out_dir))?
            };

            let start_times = RefCell::new(std::collections::HashMap::new());
            receiver.run_loop(|session_id, event| match event {
                KyuEvent::Log(message) => println!("{}", message),
                KyuEvent::HandshakeComplete => {
                    println!("<<< [Handshake] Session #{:x} connected.", session_id);
                }
                KyuEvent::FileDetected {
                    stream_id,
                    trace_id,
                    name,
                    size,
                } => {
                    println!(
                        "\n<<< [Session {:x} | Stream {:x} | Trace {:016x}] Incoming file: '{}' ({})",
                        session_id, stream_id, trace_id, name, size
                    );
                    start_times.borrow_mut().insert(stream_id, Instant::now());
                }
                KyuEvent::Progress {
                    stream_id,
                    trace_id,
                    current,
                    total,
                } => {
                    if let Some(start) = start_times.borrow().get(&stream_id) {
                        let elapsed = start.elapsed().as_secs_f64().max(0.001);
                        let mbps = (current as f64 * 8.0) / elapsed / 1_000_000.0;
                        print!(
                            "\r  -> [Stream {:x} | Trace {:016x}] {} / {} bytes ({:.2} Mbps) ...",
                            stream_id, trace_id, current, total, mbps
                        );
                        let _ = std::io::stdout().flush();
                    }
                }
                KyuEvent::TransferComplete {
                    stream_id,
                    trace_id,
                    path,
                } => {
                    if let Some(start) = start_times.borrow_mut().remove(&stream_id) {
                        let elapsed = start.elapsed();
                        let file_size = path.metadata().map(|meta| meta.len()).unwrap_or(0);
                        let mbps =
                            (file_size as f64 * 8.0) / elapsed.as_secs_f64().max(0.001) / 1_000_000.0;

                        println!(
                            "\n\n<<< [Stream {:x} | Trace {:016x}] TRANSFER COMPLETE!",
                            stream_id, trace_id
                        );
                        println!("    -> Saved to: {:?}", path);
                        println!("    -> Time: {:.2?}", elapsed);
                        println!("    -> Avg Speed: {:.2} Mbps", mbps);
                    }
                }
                KyuEvent::Fault {
                    code,
                    message,
                    stream_id,
                    trace_id,
                    ..
                } => {
                    eprintln!(
                        "\n!!! [{}] session={:x} stream={:?} trace={:?}: {}",
                        code.as_str(),
                        session_id,
                        stream_id,
                        trace_id.map(|v| format!("{:016x}", v)),
                        message
                    );
                }
                KyuEvent::Error(error) => eprintln!("\n!!! Error: {}", error),
                KyuEvent::Metric { name, value, .. } => {
                    println!("[metric] {}={}", name, value);
                }
                KyuEvent::HandshakeInitiated | KyuEvent::EarlyTermination { .. } => {}
            })?;
        }
    }

    Ok(())
}
