use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use kyu2_core::{
    init, parse_psk_hex, CompressionMode, FecPolicy, KyuEvent, KyuReceiver, KyuSender, PaddingMode,
    PipelineConfig, TransportConfig,
};
#[cfg(feature = "webrtc")]
use kyu2_core::{IceServerConfig, WebRtcConfig, WebRtcPeer};
use rand::random;
use serde_json::json;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
#[cfg(feature = "webrtc")]
use std::time::Duration;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
#[cfg(feature = "webrtc")]
use tokio::runtime::Builder as TokioRuntimeBuilder;

#[derive(Parser)]
#[command(name = "kyu2", about = "Zen-Mode UDP File Transfer Engine")]
struct Cli {
    /// Emit structured JSON logs instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CompressionArg {
    Zstd,
    Off,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PaddingArg {
    Fixed,
    Disabled,
    Adaptive,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FecArg {
    Adaptive,
    Fixed,
}

#[derive(Subcommand)]
enum Commands {
    Send {
        #[arg(required = true)]
        input_files: Vec<String>,
        #[arg(long, default_value = "127.0.0.1:8080")]
        dest: String,
        /// Trusted relay routes used when direct handshake fails. Repeat flag for a mesh list.
        #[arg(long = "relay")]
        relay_routes: Vec<String>,
        /// Optional 32-byte PSK in hex; otherwise uses KYU2_PSK or local auto-bootstrap lookup.
        #[arg(long)]
        psk: Option<String>,
        /// Load a previously exported resumption ticket from this path.
        #[arg(long)]
        ticket_in: Option<String>,
        /// Persist the latest resumption ticket to this path.
        #[arg(long)]
        ticket_out: Option<String>,
        /// Compression mode for outbound blocks.
        #[arg(long, value_enum, default_value_t = CompressionArg::Zstd)]
        compression: CompressionArg,
        /// Packet padding strategy.
        #[arg(long, value_enum, default_value_t = PaddingArg::Fixed)]
        padding: PaddingArg,
        /// Fixed padding target size when `--padding fixed`.
        #[arg(long, default_value_t = 1200)]
        padding_size: usize,
        /// Adaptive padding minimum packet size when `--padding adaptive`.
        #[arg(long, default_value_t = 256)]
        padding_min: usize,
        /// Adaptive padding maximum packet size when `--padding adaptive`.
        #[arg(long, default_value_t = 1200)]
        padding_max: usize,
        /// FEC strategy (`adaptive` uses receiver feedback; `fixed` keeps redundancy static).
        #[arg(long, value_enum, default_value_t = FecArg::Adaptive)]
        fec: FecArg,
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
    #[cfg(feature = "webrtc")]
    WebrtcSend {
        /// Source file to transfer over WebRTC data channel.
        #[arg(long)]
        input: String,
        /// Output file for local SDP offer JSON.
        #[arg(long)]
        signal_out: String,
        /// Input file containing remote SDP answer JSON.
        #[arg(long)]
        signal_in: String,
        /// Optional label for the negotiated data channel.
        #[arg(long, default_value = "kyu2-data")]
        channel_label: String,
        /// ICE servers (`stun:` or `turn:` URI). Repeat for multiple servers.
        #[arg(long = "ice")]
        ice_servers: Vec<String>,
        /// TURN username applied to TURN URIs when provided.
        #[arg(long)]
        turn_username: Option<String>,
        /// TURN credential applied to TURN URIs when provided.
        #[arg(long)]
        turn_credential: Option<String>,
        /// Emits one Opus sample over SRTP after connect to validate media path.
        #[arg(long, default_value_t = false)]
        srtp_probe: bool,
        /// Max wait for signaling + connectivity in seconds.
        #[arg(long, default_value_t = 90)]
        timeout_secs: u64,
    },
    #[cfg(feature = "webrtc")]
    WebrtcRecv {
        /// Directory where transferred files are written.
        #[arg(long, short = 'd', default_value = ".")]
        out_dir: String,
        /// Input file containing remote SDP offer JSON.
        #[arg(long)]
        signal_in: String,
        /// Output file for local SDP answer JSON.
        #[arg(long)]
        signal_out: String,
        /// Optional label filter for accepted data channels.
        #[arg(long, default_value = "kyu2-data")]
        channel_label: String,
        /// ICE servers (`stun:` or `turn:` URI). Repeat for multiple servers.
        #[arg(long = "ice")]
        ice_servers: Vec<String>,
        /// TURN username applied to TURN URIs when provided.
        #[arg(long)]
        turn_username: Option<String>,
        /// TURN credential applied to TURN URIs when provided.
        #[arg(long)]
        turn_credential: Option<String>,
        /// Captures inbound RTP payloads from remote SRTP tracks for observability.
        #[arg(long, default_value_t = false)]
        srtp_probe: bool,
        /// Max wait for signaling + connectivity in seconds.
        #[arg(long, default_value_t = 90)]
        timeout_secs: u64,
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
#[cfg(feature = "webrtc")]
const WEBRTC_FRAME_HEADER: u8 = 1;
#[cfg(feature = "webrtc")]
const WEBRTC_FRAME_CHUNK: u8 = 2;
#[cfg(feature = "webrtc")]
const WEBRTC_FRAME_FIN: u8 = 3;
#[cfg(feature = "webrtc")]
const WEBRTC_CHUNK_SIZE: usize = 16 * 1024;

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

fn build_transport_config(
    compression: CompressionArg,
    padding: PaddingArg,
    padding_size: usize,
    padding_min: usize,
    padding_max: usize,
    fec: FecArg,
) -> TransportConfig {
    let pipeline = PipelineConfig {
        compression: match compression {
            CompressionArg::Zstd => CompressionMode::Zstd { level: 1 },
            CompressionArg::Off => CompressionMode::Disabled,
        },
    };
    let padding = match padding {
        PaddingArg::Fixed => PaddingMode::Fixed(padding_size.max(1)),
        PaddingArg::Disabled => PaddingMode::Disabled,
        PaddingArg::Adaptive => PaddingMode::Adaptive {
            min: padding_min.max(1),
            max: padding_max.max(padding_min.max(1)),
        },
    };
    let fec = match fec {
        FecArg::Adaptive => FecPolicy::Adaptive {
            min: 1.0,
            max: 4.0,
            increase_step: 0.15,
            decrease_step: 0.05,
            high_watermark: 1.20,
            low_watermark: 1.05,
        },
        FecArg::Fixed => FecPolicy::Fixed,
    };
    TransportConfig {
        pipeline,
        padding,
        fec,
    }
}

#[cfg(feature = "webrtc")]
fn build_webrtc_config(
    ice_servers: Vec<String>,
    turn_username: Option<String>,
    turn_credential: Option<String>,
) -> Result<WebRtcConfig> {
    let mut resolved = Vec::new();
    let configured = if ice_servers.is_empty() {
        vec![kyu2_core::DEFAULT_STUN_SERVER.to_string()]
    } else {
        ice_servers
    };

    for url in configured {
        if url.starts_with("turn:") || url.starts_with("turns:") {
            let username = turn_username
                .as_ref()
                .context("TURN URI provided without --turn-username")?;
            let credential = turn_credential
                .as_ref()
                .context("TURN URI provided without --turn-credential")?;
            resolved.push(IceServerConfig::turn(
                url,
                username.to_owned(),
                credential.to_owned(),
            ));
        } else {
            resolved.push(IceServerConfig::stun(url));
        }
    }

    Ok(WebRtcConfig {
        ice_servers: resolved,
    })
}

#[cfg(feature = "webrtc")]
fn encode_webrtc_header(file_name: &str, file_size: u64) -> Result<Vec<u8>> {
    let safe_name = Path::new(file_name)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("payload.bin");
    let name_bytes = safe_name.as_bytes();
    if name_bytes.len() > u16::MAX as usize {
        bail!("file name too long for WebRTC transfer header");
    }

    let mut packet = Vec::with_capacity(1 + 2 + name_bytes.len() + 8);
    packet.push(WEBRTC_FRAME_HEADER);
    packet.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    packet.extend_from_slice(name_bytes);
    packet.extend_from_slice(&file_size.to_le_bytes());
    Ok(packet)
}

#[cfg(feature = "webrtc")]
fn decode_webrtc_header(packet: &[u8]) -> Result<(String, u64)> {
    if packet.len() < 1 + 2 + 8 {
        bail!("WebRTC header packet too short");
    }
    if packet[0] != WEBRTC_FRAME_HEADER {
        bail!("invalid WebRTC header packet type");
    }

    let name_len = u16::from_le_bytes([packet[1], packet[2]]) as usize;
    let header_len = 1 + 2 + name_len + 8;
    if packet.len() < header_len {
        bail!("truncated WebRTC header packet");
    }

    let name_raw =
        std::str::from_utf8(&packet[3..3 + name_len]).context("invalid UTF-8 file name")?;
    let safe_name = Path::new(name_raw)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("incoming.bin")
        .to_string();
    let size_start = 3 + name_len;
    let mut size_bytes = [0u8; 8];
    size_bytes.copy_from_slice(&packet[size_start..size_start + 8]);
    let file_size = u64::from_le_bytes(size_bytes);

    Ok((safe_name, file_size))
}

#[cfg(feature = "webrtc")]
async fn wait_for_signal_file(path: &Path, timeout: Duration) -> Result<String> {
    let started = Instant::now();
    loop {
        if let Ok(raw) = fs::read_to_string(path) {
            if !raw.trim().is_empty() {
                return Ok(raw);
            }
        }
        if started.elapsed() >= timeout {
            bail!("timed out waiting for signaling file: {}", path.display());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[cfg(feature = "webrtc")]
fn run_webrtc_send_command(
    json_logs: bool,
    input: String,
    signal_out: String,
    signal_in: String,
    channel_label: String,
    ice_servers: Vec<String>,
    turn_username: Option<String>,
    turn_credential: Option<String>,
    srtp_probe: bool,
    timeout_secs: u64,
) -> Result<()> {
    let runtime = TokioRuntimeBuilder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build Tokio runtime for WebRTC mode")?;

    runtime.block_on(async move {
        let timeout = Duration::from_secs(timeout_secs.max(1));
        let config = build_webrtc_config(ice_servers, turn_username, turn_credential)?;
        let peer = WebRtcPeer::new(config).await?;

        let data_channel = peer.create_data_channel(&channel_label).await?;
        let data_channel_open_wait = {
            let data_channel = data_channel.clone();
            tokio::spawn(
                async move { WebRtcPeer::wait_data_channel_open(&data_channel, timeout).await },
            )
        };
        let srtp_track = if srtp_probe {
            Some(peer.add_opus_track("kyu2-probe-audio", "kyu2").await?)
        } else {
            None
        };

        let offer = peer.create_offer_sdp().await?;
        fs::write(&signal_out, offer)
            .with_context(|| format!("failed to write local SDP offer: {signal_out}"))?;
        if !json_logs {
            println!(">>> WebRTC offer written: {}", signal_out);
            println!(">>> Waiting for remote SDP answer: {}", signal_in);
        }

        let answer = wait_for_signal_file(Path::new(&signal_in), timeout).await?;
        peer.set_remote_description_sdp(&answer).await?;
        peer.wait_connected(timeout).await?;
        data_channel_open_wait
            .await
            .context("data-channel open waiter task failed")??;

        if let Some(track) = srtp_track {
            WebRtcPeer::write_media_sample(&track, &[0xF8, 0xFF, 0xFE], Duration::from_millis(20))
                .await?;
            if !json_logs {
                println!(">>> SRTP probe sample emitted (Opus payload).");
            }
        }

        let input_path = PathBuf::from(&input);
        let payload = fs::read(&input_path)
            .with_context(|| format!("failed to read input file: {}", input_path.display()))?;
        let file_name = input_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("payload.bin");
        let header = encode_webrtc_header(file_name, payload.len() as u64)?;
        let _ = WebRtcPeer::send_data_channel_binary(&data_channel, &header).await?;

        let mut sent = 0usize;
        for chunk in payload.chunks(WEBRTC_CHUNK_SIZE) {
            let mut packet = Vec::with_capacity(1 + chunk.len());
            packet.push(WEBRTC_FRAME_CHUNK);
            packet.extend_from_slice(chunk);
            let _ = WebRtcPeer::send_data_channel_binary(&data_channel, &packet).await?;
            sent += chunk.len();
            if !json_logs {
                print!(
                    "\r>>> WebRTC send progress: {sent} / {} bytes",
                    payload.len()
                );
                let _ = std::io::stdout().flush();
            }
        }
        let _ = WebRtcPeer::send_data_channel_binary(&data_channel, &[WEBRTC_FRAME_FIN]).await?;
        if !json_logs {
            println!("\n>>> WebRTC transfer complete.");
        }

        peer.close().await?;
        Ok(())
    })
}

#[cfg(feature = "webrtc")]
fn run_webrtc_recv_command(
    json_logs: bool,
    out_dir: String,
    signal_in: String,
    signal_out: String,
    channel_label: String,
    ice_servers: Vec<String>,
    turn_username: Option<String>,
    turn_credential: Option<String>,
    srtp_probe: bool,
    timeout_secs: u64,
) -> Result<()> {
    let runtime = TokioRuntimeBuilder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build Tokio runtime for WebRTC mode")?;

    runtime.block_on(async move {
        let timeout = Duration::from_secs(timeout_secs.max(1));
        fs::create_dir_all(&out_dir)
            .with_context(|| format!("failed to create output directory: {out_dir}"))?;

        let config = build_webrtc_config(ice_servers, turn_username, turn_credential)?;
        let peer = WebRtcPeer::new(config).await?;
        let mut ingress = peer.install_data_channel_ingress(Some(channel_label.clone()), 4096);
        let mut rtp_ingress = if srtp_probe {
            Some(peer.install_inbound_rtp_bridge(512))
        } else {
            None
        };

        if !json_logs {
            println!(">>> Waiting for remote SDP offer: {}", signal_in);
        }
        let offer = wait_for_signal_file(Path::new(&signal_in), timeout).await?;
        let answer = peer.accept_offer_create_answer_sdp(&offer).await?;
        fs::write(&signal_out, answer)
            .with_context(|| format!("failed to write local SDP answer: {signal_out}"))?;
        if !json_logs {
            println!(">>> WebRTC answer written: {}", signal_out);
        }

        peer.wait_connected(timeout).await?;

        let mut target_file: Option<fs::File> = None;
        let mut target_path: Option<PathBuf> = None;
        let mut expected_size = 0u64;
        let mut received = 0u64;

        loop {
            if let Some(rtp_rx) = rtp_ingress.as_mut() {
                while let Ok(frame) = rtp_rx.try_recv() {
                    if !json_logs {
                        println!(
                            ">>> SRTP probe RTP frame: pt={} seq={} ts={} bytes={}",
                            frame.payload_type,
                            frame.sequence_number,
                            frame.timestamp,
                            frame.payload.len()
                        );
                    }
                }
            }

            let packet = tokio::time::timeout(timeout, ingress.recv())
                .await
                .context("timed out waiting for WebRTC data packet")?
                .context("WebRTC data channel closed before transfer completed")?;
            if packet.payload.is_empty() {
                continue;
            }

            match packet.payload[0] {
                WEBRTC_FRAME_HEADER => {
                    let (file_name, file_size) = decode_webrtc_header(&packet.payload)?;
                    expected_size = file_size;
                    let path = Path::new(&out_dir).join(file_name);
                    let file = fs::File::create(&path).with_context(|| {
                        format!("failed to create WebRTC output file: {}", path.display())
                    })?;
                    target_path = Some(path.clone());
                    target_file = Some(file);
                    if !json_logs {
                        println!(
                            ">>> Receiving '{}' ({} bytes) via data channel `{}`",
                            path.display(),
                            file_size,
                            packet.label
                        );
                    }
                }
                WEBRTC_FRAME_CHUNK => {
                    let Some(file) = target_file.as_mut() else {
                        bail!("received WebRTC chunk before header");
                    };
                    file.write_all(&packet.payload[1..])
                        .context("failed writing WebRTC chunk")?;
                    received = received.saturating_add((packet.payload.len() - 1) as u64);
                    if !json_logs {
                        print!("\r<<< WebRTC recv progress: {received} / {expected_size} bytes");
                        let _ = std::io::stdout().flush();
                    }
                }
                WEBRTC_FRAME_FIN => {
                    if !json_logs {
                        println!();
                    }
                    break;
                }
                _ => {}
            }
        }

        if let Some(mut file) = target_file {
            file.flush().context("failed flushing WebRTC output file")?;
        }

        if let Some(path) = target_path {
            if !json_logs {
                println!(
                    "<<< WebRTC transfer complete: {} ({} bytes received)",
                    path.display(),
                    received
                );
            }
        }

        if expected_size != 0 && received != expected_size {
            bail!(
                "incomplete WebRTC file transfer: received {} of {} bytes",
                received,
                expected_size
            );
        }

        peer.close().await?;
        Ok(())
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
            relay_routes,
            psk,
            ticket_in,
            ticket_out,
            compression,
            padding,
            padding_size,
            padding_min,
            padding_max,
            fec,
            redundancy,
            limit,
        } => {
            let sender_psk = resolve_sender_psk(&dest, psk.as_deref())?;
            let transport = build_transport_config(
                compression,
                padding,
                padding_size,
                padding_min,
                padding_max,
                fec,
            );
            let mut sender = KyuSender::new_with_psk_and_config(&dest, sender_psk, transport)?;
            sender.set_relay_routes(relay_routes);

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
        #[cfg(feature = "webrtc")]
        Commands::WebrtcSend {
            input,
            signal_out,
            signal_in,
            channel_label,
            ice_servers,
            turn_username,
            turn_credential,
            srtp_probe,
            timeout_secs,
        } => {
            run_webrtc_send_command(
                cli.json,
                input,
                signal_out,
                signal_in,
                channel_label,
                ice_servers,
                turn_username,
                turn_credential,
                srtp_probe,
                timeout_secs,
            )?;
        }
        #[cfg(feature = "webrtc")]
        Commands::WebrtcRecv {
            out_dir,
            signal_in,
            signal_out,
            channel_label,
            ice_servers,
            turn_username,
            turn_credential,
            srtp_probe,
            timeout_secs,
        } => {
            run_webrtc_recv_command(
                cli.json,
                out_dir,
                signal_in,
                signal_out,
                channel_label,
                ice_servers,
                turn_username,
                turn_credential,
                srtp_probe,
                timeout_secs,
            )?;
        }
    }

    Ok(())
}
