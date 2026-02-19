use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use kyu2_core::{init, parse_psk_hex, KyuEvent, KyuReceiver, KyuSender};
use rand::random;
use serde_json::json;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
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
        /// Optional 32-byte PSK in hex; otherwise uses KYU2_PSK or local auto-bootstrap lookup.
        #[arg(long)]
        psk: Option<String>,
        /// Load a previously exported resumption ticket from this path.
        #[arg(long)]
        ticket_in: Option<String>,
        /// Persist the latest resumption ticket to this path.
        #[arg(long)]
        ticket_out: Option<String>,
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
        /// Optional 32-byte PSK in hex; otherwise uses KYU2_PSK or generates ephemeral runtime key.
        #[arg(long)]
        psk: Option<String>,
        /// Optional 32-byte ticket key in hex; falls back to KYU2_TICKET_KEY or auto-generated value.
        #[arg(long)]
        ticket_key: Option<String>,
    },
    Relay {
        #[arg(long, default_value = "0.0.0.0:8081")]
        bind: String,
        #[arg(long)]
        forward: String,
        #[arg(long, default_value = "./relay_spool")]
        spool_dir: String,
        /// Optional 32-byte PSK in hex; falls back to KYU2_PSK env var when omitted.
        #[arg(long)]
        psk: Option<String>,
        /// 32-byte ticket key in hex; falls back to KYU2_TICKET_KEY, then PSK.
        #[arg(long)]
        ticket_key: Option<String>,
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

/// Local keyring location used for ephemeral CLI bootstrap secrets.
const LOCAL_KEYRING_DIR_NAME: &str = "kyu2-local-keyring-v1";
/// Entry lifetime for automatic local bootstrap records.
const LOCAL_KEYRING_TTL_SECS: u64 = 12 * 60 * 60;
/// Hard cap on keyring entry count to keep disk/memory bounded.
const LOCAL_KEYRING_MAX_ENTRIES: usize = 512;

/// On-disk bootstrap key material for local sender discovery.
#[derive(Debug, Clone, Copy)]
struct LocalBootstrapRecord {
    expires_at: u64,
    psk: [u8; 32],
    ticket_key: [u8; 32],
}

/// Resolved receiver authentication material with source metadata.
#[derive(Debug, Clone, Copy)]
struct ReceiverAuthMaterial {
    psk: [u8; 32],
    ticket_key: [u8; 32],
    generated_ephemeral: bool,
    registered_aliases: usize,
}

fn unix_ms_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn unix_secs_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Hex-encodes a fixed 32-byte key for local keyring storage.
fn encode_hex_32(input: &[u8; 32]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(64);
    for byte in input {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Converts endpoint text into a filesystem-safe keyring filename.
fn endpoint_key_file_name(endpoint: &str) -> String {
    use std::fmt::Write as _;

    let mut name = String::with_capacity(endpoint.len() * 2 + 4);
    for byte in endpoint.as_bytes() {
        let _ = write!(&mut name, "{byte:02x}");
    }
    name.push_str(".key");
    name
}

/// Returns the ephemeral keyring directory used by local CLI processes.
fn local_keyring_dir() -> PathBuf {
    std::env::temp_dir().join(LOCAL_KEYRING_DIR_NAME)
}

#[cfg(unix)]
fn set_secure_permissions(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;

    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn set_secure_permissions(_path: &Path, _mode: u32) {}

/// Parses a keyring record emitted by `serialize_local_bootstrap_record`.
fn parse_local_bootstrap_record(raw: &str) -> Option<LocalBootstrapRecord> {
    let mut expires_at: Option<u64> = None;
    let mut psk: Option<[u8; 32]> = None;
    let mut ticket_key: Option<[u8; 32]> = None;

    for line in raw.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "expires_at" => expires_at = value.parse::<u64>().ok(),
            "psk" => psk = parse_psk_hex(value).ok(),
            "ticket_key" => ticket_key = parse_psk_hex(value).ok(),
            _ => {}
        }
    }

    Some(LocalBootstrapRecord {
        expires_at: expires_at?,
        psk: psk?,
        ticket_key: ticket_key?,
    })
}

/// Serializes a local bootstrap record to an ASCII key/value payload.
fn serialize_local_bootstrap_record(record: LocalBootstrapRecord) -> String {
    format!(
        "version=1\nexpires_at={}\npsk={}\nticket_key={}\n",
        record.expires_at,
        encode_hex_32(&record.psk),
        encode_hex_32(&record.ticket_key),
    )
}

/// Keeps local keyring size bounded and removes expired/corrupt entries.
fn prune_local_keyring(now_secs: u64) -> Result<()> {
    let dir = local_keyring_dir();
    let Ok(read_dir) = fs::read_dir(&dir) else {
        return Ok(());
    };

    let mut retained = Vec::new();
    for entry in read_dir {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let raw = match fs::read_to_string(&path) {
            Ok(value) => value,
            Err(_) => {
                let _ = fs::remove_file(&path);
                continue;
            }
        };

        let Some(record) = parse_local_bootstrap_record(&raw) else {
            let _ = fs::remove_file(&path);
            continue;
        };

        if record.expires_at <= now_secs {
            let _ = fs::remove_file(&path);
            continue;
        }

        let modified_at = entry
            .metadata()
            .ok()
            .and_then(|meta| meta.modified().ok())
            .and_then(|mtime| mtime.duration_since(UNIX_EPOCH).ok())
            .map(|delta| delta.as_secs())
            .unwrap_or(now_secs);
        retained.push((modified_at, path));
    }

    if retained.len() > LOCAL_KEYRING_MAX_ENTRIES {
        retained.sort_by_key(|(modified_at, _)| *modified_at);
        let excess = retained.len().saturating_sub(LOCAL_KEYRING_MAX_ENTRIES);
        for (_, path) in retained.into_iter().take(excess) {
            let _ = fs::remove_file(path);
        }
    }

    Ok(())
}

/// Stores local bootstrap material for one endpoint alias.
fn store_local_bootstrap_record(endpoint: &str, record: LocalBootstrapRecord) -> Result<()> {
    let dir = local_keyring_dir();
    fs::create_dir_all(&dir)?;
    set_secure_permissions(&dir, 0o700);
    prune_local_keyring(unix_secs_now())?;

    let path = dir.join(endpoint_key_file_name(endpoint));
    fs::write(&path, serialize_local_bootstrap_record(record))?;
    set_secure_permissions(&path, 0o600);
    Ok(())
}

/// Loads one endpoint alias record if it exists and has not expired.
fn load_local_bootstrap_record(
    endpoint: &str,
    now_secs: u64,
) -> Result<Option<LocalBootstrapRecord>> {
    let path = local_keyring_dir().join(endpoint_key_file_name(endpoint));
    let Ok(raw) = fs::read_to_string(&path) else {
        return Ok(None);
    };

    let Some(record) = parse_local_bootstrap_record(&raw) else {
        let _ = fs::remove_file(path);
        return Ok(None);
    };
    if record.expires_at <= now_secs {
        let _ = fs::remove_file(path);
        return Ok(None);
    }

    Ok(Some(record))
}

/// Adds a value once while preserving insertion order.
fn push_unique(items: &mut Vec<String>, value: String) {
    if !items.iter().any(|item| item == &value) {
        items.push(value);
    }
}

/// Builds local endpoint aliases used when writing keyring records.
fn bind_aliases(bind: &str) -> Vec<String> {
    let mut aliases = Vec::new();
    if let Ok(addr) = bind.parse::<SocketAddr>() {
        push_unique(&mut aliases, addr.to_string());

        let port = addr.port();
        if addr.ip().is_loopback() || addr.ip().is_unspecified() {
            push_unique(
                &mut aliases,
                SocketAddr::from((Ipv4Addr::LOCALHOST, port)).to_string(),
            );
            push_unique(
                &mut aliases,
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).to_string(),
            );
            push_unique(
                &mut aliases,
                SocketAddr::from((Ipv6Addr::LOCALHOST, port)).to_string(),
            );
            push_unique(
                &mut aliases,
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).to_string(),
            );
            push_unique(&mut aliases, format!("localhost:{port}"));
        }
        return aliases;
    }

    if let Some(port) = bind
        .strip_prefix("localhost:")
        .and_then(|raw| raw.parse::<u16>().ok())
    {
        push_unique(&mut aliases, format!("localhost:{port}"));
        push_unique(
            &mut aliases,
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)).to_string(),
        );
        push_unique(
            &mut aliases,
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).to_string(),
        );
        push_unique(
            &mut aliases,
            SocketAddr::from((Ipv6Addr::LOCALHOST, port)).to_string(),
        );
        push_unique(
            &mut aliases,
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).to_string(),
        );
        return aliases;
    }

    push_unique(&mut aliases, bind.to_string());
    aliases
}

/// Builds sender-side alias candidates for local keyring lookup.
fn dest_aliases(dest: &str) -> Vec<String> {
    let mut aliases = Vec::new();
    if let Ok(addr) = dest.parse::<SocketAddr>() {
        push_unique(&mut aliases, addr.to_string());

        if addr.ip().is_loopback() {
            let port = addr.port();
            push_unique(
                &mut aliases,
                SocketAddr::from((Ipv4Addr::LOCALHOST, port)).to_string(),
            );
            push_unique(
                &mut aliases,
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).to_string(),
            );
            push_unique(
                &mut aliases,
                SocketAddr::from((Ipv6Addr::LOCALHOST, port)).to_string(),
            );
            push_unique(
                &mut aliases,
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).to_string(),
            );
            push_unique(&mut aliases, format!("localhost:{port}"));
        }
        return aliases;
    }

    if let Some(port) = dest
        .strip_prefix("localhost:")
        .and_then(|raw| raw.parse::<u16>().ok())
    {
        push_unique(&mut aliases, format!("localhost:{port}"));
        push_unique(
            &mut aliases,
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)).to_string(),
        );
        push_unique(
            &mut aliases,
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).to_string(),
        );
        push_unique(
            &mut aliases,
            SocketAddr::from((Ipv6Addr::LOCALHOST, port)).to_string(),
        );
        push_unique(
            &mut aliases,
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).to_string(),
        );
        return aliases;
    }

    push_unique(&mut aliases, dest.to_string());
    aliases
}

/// Returns whether a target endpoint is local and eligible for auto bootstrap lookup.
fn is_local_target(dest: &str) -> bool {
    if let Ok(addr) = dest.parse::<SocketAddr>() {
        return addr.ip().is_loopback() || addr.ip().is_unspecified();
    }
    dest.starts_with("localhost:")
}

/// Registers receiver bootstrap keys for all bind aliases.
fn register_local_bootstrap(bind: &str, psk: [u8; 32], ticket_key: [u8; 32]) -> Result<usize> {
    let now_secs = unix_secs_now();
    let record = LocalBootstrapRecord {
        expires_at: now_secs.saturating_add(LOCAL_KEYRING_TTL_SECS),
        psk,
        ticket_key,
    };

    let aliases = bind_aliases(bind);
    for alias in &aliases {
        store_local_bootstrap_record(alias, record)?;
    }
    Ok(aliases.len())
}

/// Attempts to resolve sender bootstrap PSK from the local keyring aliases.
fn resolve_local_bootstrap_psk(dest: &str) -> Result<Option<[u8; 32]>> {
    let now_secs = unix_secs_now();
    prune_local_keyring(now_secs)?;

    for alias in dest_aliases(dest) {
        if let Some(record) = load_local_bootstrap_record(&alias, now_secs)? {
            return Ok(Some(record.psk));
        }
    }
    Ok(None)
}

/// Resolves sender PSK from CLI flag, environment, or local bootstrap keyring.
fn resolve_sender_psk(dest: &str, psk_override: Option<&str>) -> Result<[u8; 32]> {
    if let Some(raw) = psk_override {
        return parse_psk_hex(raw);
    }
    if let Ok(raw) = std::env::var("KYU2_PSK") {
        return parse_psk_hex(&raw);
    }
    if let Some(psk) = resolve_local_bootstrap_psk(dest)? {
        return Ok(psk);
    }

    if is_local_target(dest) {
        bail!("No local bootstrap key found for {dest}. Start `kyu2 recv` first or provide --psk.");
    }

    bail!("Missing PSK for destination {dest}. Provide --psk or set KYU2_PSK.")
}

/// Resolves receiver PSK/ticket-key material and auto-registers local bootstrap aliases.
fn resolve_receiver_auth(
    bind: &str,
    psk_override: Option<&str>,
    ticket_key_override: Option<&str>,
) -> Result<ReceiverAuthMaterial> {
    let mut generated_ephemeral = false;
    let psk = if let Some(raw) = psk_override {
        parse_psk_hex(raw)?
    } else if let Ok(raw) = std::env::var("KYU2_PSK") {
        parse_psk_hex(&raw)?
    } else {
        generated_ephemeral = true;
        random::<[u8; 32]>()
    };

    let ticket_key = if let Some(raw) = ticket_key_override {
        parse_psk_hex(raw)?
    } else if let Ok(raw) = std::env::var("KYU2_TICKET_KEY") {
        parse_psk_hex(&raw)?
    } else if generated_ephemeral {
        random::<[u8; 32]>()
    } else {
        psk
    };

    let registered_aliases = register_local_bootstrap(bind, psk, ticket_key)?;
    Ok(ReceiverAuthMaterial {
        psk,
        ticket_key,
        generated_ephemeral,
        registered_aliases,
    })
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
            ticket_in,
            ticket_out,
            redundancy,
            limit,
        } => {
            let sender_psk = resolve_sender_psk(&dest, psk.as_deref())?;
            let mut sender = KyuSender::new_with_psk(&dest, sender_psk)?;

            if let Some(ticket_path) = &ticket_in {
                let blob = std::fs::read(ticket_path).with_context(|| {
                    format!("Failed to read resumption ticket file: {ticket_path}")
                })?;
                sender.import_resumption_ticket(&blob).with_context(|| {
                    format!("Failed to import resumption ticket from: {ticket_path}")
                })?;
            }

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

            if let Some(ticket_path) = &ticket_out {
                if let Some(blob) = sender.export_resumption_ticket()? {
                    std::fs::write(ticket_path, blob).with_context(|| {
                        format!("Failed to write resumption ticket file: {ticket_path}")
                    })?;
                    if !cli.json {
                        println!(">>> Saved resumption ticket: {}", ticket_path);
                    }
                }
            }
        }
        Commands::Recv {
            bind,
            out_dir,
            psk,
            ticket_key,
        } => {
            let auth = resolve_receiver_auth(&bind, psk.as_deref(), ticket_key.as_deref())?;
            if !cli.json && auth.generated_ephemeral {
                println!(
                    ">>> Generated ephemeral runtime bootstrap key for recv; local sender discovery aliases={}",
                    auth.registered_aliases
                );
            }

            let receiver = KyuReceiver::new_with_psk_and_ticket_key(
                &bind,
                Path::new(&out_dir),
                auth.psk,
                auth.ticket_key,
            )?;

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
            ticket_key,
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

            let receiver = if let Some(ticket_key_hex) = ticket_key {
                KyuReceiver::new_with_psk_and_ticket_key(
                    &bind,
                    Path::new(&spool_dir),
                    psk_bytes,
                    parse_psk_hex(&ticket_key_hex)?,
                )?
            } else {
                KyuReceiver::new_with_psk(&bind, Path::new(&spool_dir), psk_bytes)?
            };
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
