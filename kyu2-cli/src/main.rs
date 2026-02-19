use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use kyu2_core::{init, parse_psk_hex, KyuEvent, KyuReceiver, KyuSender};
use serde_json::json;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "kyu2", about = "Zen-Mode UDP File Transfer Engine")]
struct Cli {
    /// Emit structured JSON logs instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Send {
        #[arg(required = true)]
        input_files: Vec<String>,
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
    Relay {
        #[arg(long, default_value = "0.0.0.0:8081")]
        bind: String,
        #[arg(long)]
        forward: String,
        #[arg(long, default_value = "./relay_spool")]
        spool_dir: String,
        /// 32-byte PSK in hex; falls back to KYU2_PSK env var when omitted.
        #[arg(long)]
        psk: Option<String>,
        #[arg(long, default_value_t = 1.5)]
        redundancy: f32,
        #[arg(long, default_value_t = 5_000_000)]
        limit: u64,
    },
}

#[derive(Debug, Clone, Copy)]
struct StreamUiState {
    started_at: Instant,
    last_total: u64,
    trace_id: u64,
}

fn unix_ms_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn print_event_json(mode: &str, session_id: Option<u64>, event: &KyuEvent) {
    let record = match event {
        KyuEvent::Log(message) => json!({
            "ts_ms": unix_ms_now(),
            "mode": mode,
            "type": "log",
            "message": message,
            "session_id": session_id,
        }),
        KyuEvent::HandshakeInitiated => json!({
            "ts_ms": unix_ms_now(),
            "mode": mode,
            "type": "handshake_initiated",
            "session_id": session_id,
        }),
        KyuEvent::HandshakeComplete => json!({
            "ts_ms": unix_ms_now(),
            "mode": mode,
            "type": "handshake_complete",
            "session_id": session_id,
        }),
        KyuEvent::FileDetected {
            stream_id,
            trace_id,
            name,
            size,
        } => json!({
            "ts_ms": unix_ms_now(),
            "mode": mode,
            "type": "file_detected",
            "session_id": session_id,
            "stream_id": stream_id,
            "trace_id": format!("{:016x}", trace_id),
            "name": name,
            "size": size,
        }),
        KyuEvent::Progress {
            stream_id,
            trace_id,
            current,
            total,
        } => json!({
            "ts_ms": unix_ms_now(),
            "mode": mode,
            "type": "progress",
            "session_id": session_id,
            "stream_id": stream_id,
            "trace_id": format!("{:016x}", trace_id),
            "current": current,
            "total": total,
        }),
        KyuEvent::TransferComplete {
            stream_id,
            trace_id,
            path,
        } => json!({
            "ts_ms": unix_ms_now(),
            "mode": mode,
            "type": "transfer_complete",
            "session_id": session_id,
            "stream_id": stream_id,
            "trace_id": format!("{:016x}", trace_id),
            "path": path,
        }),
        KyuEvent::EarlyTermination {
            stream_id,
            trace_id,
        } => json!({
            "ts_ms": unix_ms_now(),
            "mode": mode,
            "type": "early_termination",
            "session_id": session_id,
            "stream_id": stream_id,
            "trace_id": format!("{:016x}", trace_id),
        }),
        KyuEvent::Error(message) => json!({
            "ts_ms": unix_ms_now(),
            "mode": mode,
            "type": "error",
            "session_id": session_id,
            "message": message,
        }),
        KyuEvent::Fault {
            code,
            message,
            session_id: event_session,
            stream_id,
            trace_id,
        } => json!({
            "ts_ms": unix_ms_now(),
            "mode": mode,
            "type": "fault",
            "error_code": code.as_str(),
            "message": message,
            "session_id": event_session.or(session_id),
            "stream_id": stream_id,
            "trace_id": trace_id.map(|value| format!("{:016x}", value)),
        }),
        KyuEvent::Metric {
            name,
            value,
            session_id: event_session,
            stream_id,
            trace_id,
        } => json!({
            "ts_ms": unix_ms_now(),
            "mode": mode,
            "type": "metric",
            "name": name,
            "value": value,
            "session_id": event_session.or(session_id),
            "stream_id": stream_id,
            "trace_id": trace_id.map(|v| format!("{:016x}", v)),
        }),
    };

    println!("{}", record);
}

fn print_sender_event_human(event: &KyuEvent, states: &RefCell<HashMap<u32, StreamUiState>>) {
    match event {
        KyuEvent::Log(message) => println!(">>> {}", message),
        KyuEvent::HandshakeInitiated => println!(">>> [Handshake] Initiating..."),
        KyuEvent::HandshakeComplete => println!(">>> [Handshake] Secure tunnel established."),
        KyuEvent::Progress {
            stream_id,
            trace_id,
            current,
            total,
        } => {
            let mut map = states.borrow_mut();
            let entry = map.entry(*stream_id).or_insert(StreamUiState {
                started_at: Instant::now(),
                last_total: *total,
                trace_id: *trace_id,
            });
            entry.last_total = *total;
            entry.trace_id = *trace_id;

            let elapsed = entry.started_at.elapsed().as_secs_f64().max(0.001);
            let mbps = (*current as f64 * 8.0) / elapsed / 1_000_000.0;
            print!(
                "\r  -> [Stream {:x} | Trace {:016x}] Sent {} / {} bytes ({:.2} Mbps) ...",
                stream_id, trace_id, current, total, mbps
            );
            let _ = std::io::stdout().flush();
        }
        KyuEvent::TransferComplete {
            stream_id,
            trace_id,
            path,
        } => {
            let mut map = states.borrow_mut();
            let state = map.remove(stream_id).unwrap_or(StreamUiState {
                started_at: Instant::now(),
                last_total: path.metadata().map(|meta| meta.len()).unwrap_or(0),
                trace_id: *trace_id,
            });
            let elapsed = state.started_at.elapsed();
            let mbps =
                (state.last_total as f64 * 8.0) / elapsed.as_secs_f64().max(0.001) / 1_000_000.0;

            println!(
                "\n\n>>> [Stream {:x} | Trace {:016x}] DONE.",
                stream_id, trace_id
            );
            println!("    -> Path: {:?}", path);
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
        KyuEvent::Error(message) => eprintln!("\n!!! Error: {}", message),
        KyuEvent::Metric { .. } | KyuEvent::FileDetected { .. } => {}
    }
}

fn print_receiver_event_human(
    session_id: u64,
    event: &KyuEvent,
    states: &RefCell<HashMap<u32, StreamUiState>>,
) {
    match event {
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
            states.borrow_mut().insert(
                *stream_id,
                StreamUiState {
                    started_at: Instant::now(),
                    last_total: *size,
                    trace_id: *trace_id,
                },
            );
        }
        KyuEvent::Progress {
            stream_id,
            trace_id,
            current,
            total,
        } => {
            let mut map = states.borrow_mut();
            let entry = map.entry(*stream_id).or_insert(StreamUiState {
                started_at: Instant::now(),
                last_total: *total,
                trace_id: *trace_id,
            });
            entry.last_total = *total;
            entry.trace_id = *trace_id;

            let elapsed = entry.started_at.elapsed().as_secs_f64().max(0.001);
            let mbps = (*current as f64 * 8.0) / elapsed / 1_000_000.0;
            print!(
                "\r  -> [Stream {:x} | Trace {:016x}] {} / {} bytes ({:.2} Mbps) ...",
                stream_id, trace_id, current, total, mbps
            );
            let _ = std::io::stdout().flush();
        }
        KyuEvent::TransferComplete {
            stream_id,
            trace_id,
            path,
        } => {
            let mut map = states.borrow_mut();
            let state = map.remove(stream_id).unwrap_or(StreamUiState {
                started_at: Instant::now(),
                last_total: path.metadata().map(|meta| meta.len()).unwrap_or(0),
                trace_id: *trace_id,
            });
            let elapsed = state.started_at.elapsed();
            let mbps =
                (state.last_total as f64 * 8.0) / elapsed.as_secs_f64().max(0.001) / 1_000_000.0;

            println!(
                "\n\n<<< [Session {:x} | Stream {:x} | Trace {:016x}] TRANSFER COMPLETE!",
                session_id, stream_id, trace_id
            );
            println!("    -> Saved to: {:?}", path);
            println!("    -> Time: {:.2?}", elapsed);
            println!("    -> Avg Speed: {:.2} Mbps", mbps);
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
        KyuEvent::Error(message) => eprintln!("\n!!! Error: {}", message),
        KyuEvent::Metric { name, value, .. } => {
            println!("[metric] {}={}", name, value);
        }
        KyuEvent::HandshakeInitiated | KyuEvent::EarlyTermination { .. } => {}
    }
}

fn main() -> Result<()> {
    init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Send {
            input_files,
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

            let paths: Vec<PathBuf> = input_files.iter().map(PathBuf::from).collect();
            if !cli.json {
                println!(
                    ">>> Initiating transfer: files={} target={} limit={} B/s redundancy={}x",
                    paths.len(),
                    dest,
                    limit,
                    redundancy
                );
            }

            let stream_states: RefCell<HashMap<u32, StreamUiState>> = RefCell::new(HashMap::new());
            if paths.len() == 1 {
                sender.send_file(&paths[0], redundancy, limit, |event| {
                    if cli.json {
                        print_event_json("send", None, &event);
                    } else {
                        print_sender_event_human(&event, &stream_states);
                    }
                })?;
            } else {
                sender.send_files(&paths, redundancy, limit, |event| {
                    if cli.json {
                        print_event_json("send", None, &event);
                    } else {
                        print_sender_event_human(&event, &stream_states);
                    }
                })?;
            }
        }
        Commands::Recv { bind, out_dir, psk } => {
            let receiver = if let Some(psk_hex) = psk {
                KyuReceiver::new_with_psk(&bind, Path::new(&out_dir), parse_psk_hex(&psk_hex)?)?
            } else {
                KyuReceiver::new(&bind, Path::new(&out_dir))?
            };

            let stream_states: RefCell<HashMap<u32, StreamUiState>> = RefCell::new(HashMap::new());
            receiver.run_loop(|session_id, event| {
                if cli.json {
                    print_event_json("recv", Some(session_id), &event);
                } else {
                    print_receiver_event_human(session_id, &event, &stream_states);
                }
            })?;
        }
        Commands::Relay {
            bind,
            forward,
            spool_dir,
            psk,
            redundancy,
            limit,
        } => {
            std::fs::create_dir_all(&spool_dir)?;
            let psk_bytes = if let Some(psk_hex) = psk {
                parse_psk_hex(&psk_hex)?
            } else {
                let env_psk =
                    std::env::var("KYU2_PSK").context("Missing KYU2_PSK for relay mode")?;
                parse_psk_hex(&env_psk)?
            };

            let receiver = KyuReceiver::new_with_psk(&bind, Path::new(&spool_dir), psk_bytes)?;
            let forward_sender = RefCell::new(KyuSender::new_with_psk(&forward, psk_bytes)?);
            let relay_sender_states: RefCell<HashMap<u32, StreamUiState>> =
                RefCell::new(HashMap::new());

            if !cli.json {
                println!(
                    ">>> Relay active: recv={} forward={} spool={}",
                    bind, forward, spool_dir
                );
            }

            let stream_states: RefCell<HashMap<u32, StreamUiState>> = RefCell::new(HashMap::new());
            receiver.run_loop(|session_id, event| {
                if cli.json {
                    print_event_json("relay.recv", Some(session_id), &event);
                } else {
                    print_receiver_event_human(session_id, &event, &stream_states);
                }

                if let KyuEvent::TransferComplete {
                    stream_id,
                    trace_id,
                    path,
                } = &event
                {
                    if cli.json {
                        println!(
                            "{}",
                            json!({
                                "ts_ms": unix_ms_now(),
                                "mode": "relay.forward",
                                "type": "forward_start",
                                "stream_id": stream_id,
                                "trace_id": format!("{:016x}", trace_id),
                                "path": path,
                                "dest": forward,
                            })
                        );
                    } else {
                        println!(
                            ">>> [Relay] Forwarding stream {:x} trace {:016x} to {}",
                            stream_id, trace_id, forward
                        );
                    }

                    let result = forward_sender.borrow_mut().send_file(
                        path,
                        redundancy,
                        limit,
                        |forward_event| {
                            if cli.json {
                                print_event_json("relay.send", None, &forward_event);
                            } else {
                                print_sender_event_human(&forward_event, &relay_sender_states);
                            }
                        },
                    );

                    if let Err(error) = result {
                        if cli.json {
                            println!(
                                "{}",
                                json!({
                                    "ts_ms": unix_ms_now(),
                                    "mode": "relay.forward",
                                    "type": "forward_error",
                                    "stream_id": stream_id,
                                    "trace_id": format!("{:016x}", trace_id),
                                    "error": error.to_string(),
                                })
                            );
                        } else {
                            eprintln!(
                                "!!! [Relay] Forward failed for stream {:x} trace {:016x}: {}",
                                stream_id, trace_id, error
                            );
                        }
                    }
                }
            })?;
        }
    }

    Ok(())
}
