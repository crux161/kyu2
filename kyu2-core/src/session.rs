use crate::handshake::{DefaultHandshakeEngine, HandshakeEngine, ResumePacket, SessionTicket};
use crate::metadata::StreamSemantics;
use crate::pipeline::PipelineConfig;
use crate::{
    HandshakeContext, HandshakePacket, HandshakeRole, KeyExchange, KyuPipeline, PROTOCOL_VERSION,
    SessionKeys, SessionManifest, WirehairDecoder, WirehairEncoder,
};
use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, generic_array::GenericArray},
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Transfer block size for file chunking before encryption/FEC.
const BLOCK_SIZE: usize = 1024 * 64;
/// Legacy fixed UDP packet size for traffic-shape consistency.
pub const CONSTANT_UDP_SIZE: usize = 1200;
/// Default fixed padding target for compatibility.
pub const DEFAULT_PADDING_TARGET: usize = CONSTANT_UDP_SIZE;
/// Absolute wire packet size ceiling admitted by the sender.
const MAX_WIRE_PACKET_SIZE: usize = 1500;
/// Adaptive padding alignment unit.
const ADAPTIVE_PADDING_ALIGN: usize = 32;
/// Max payload bytes available for a Wirehair droplet after protocol headers.
const TARGET_PACKET_SIZE: usize = 1150;
/// Static size for the masked geometry header.
const GEOMETRY_HEADER_SIZE: usize = 22;
/// Type + session id + masked geometry.
const DATA_PREFIX_SIZE: usize = 1 + 8 + GEOMETRY_HEADER_SIZE;
/// ACK packet format: type + session id + stream id.
const ACK_PACKET_SIZE: usize = 1 + 8 + 4;
/// Enforced upper bound for a protected block reconstructed by FEC.
const MAX_PROTECTED_BLOCK_SIZE: u32 = 256 * 1024;
/// Hard cap to bound total session memory and state.
const MAX_SESSIONS: usize = 1024;
/// Hard cap to bound per-session stream growth.
const MAX_STREAMS_PER_SESSION: usize = 128;
/// Hard cap to bound sessions admitted from one source address.
const MAX_SESSIONS_PER_SOURCE: usize = 64;
/// Absolute cap to prevent unbounded FEC spray.
const MAX_REDUNDANCY: f32 = 4.0;
/// Handshake retransmit attempts before failing closed.
const HANDSHAKE_RETRIES: usize = 10;
/// Handshake receive timeout for each retry.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(500);
/// Default lifetime for issued 0-RTT session tickets.
const SESSION_TICKET_LIFETIME_SECS: u64 = 6 * 60 * 60;
/// Session timeout for garbage collection.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Periodic GC sweep interval.
const SESSION_GC_INTERVAL: Duration = Duration::from_secs(10);
/// Session-local budget for decoder allocations derived from packet headers.
const MAX_SESSION_DECODER_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
/// Global budget for all decoder allocations across every active session.
const MAX_TOTAL_DECODER_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
/// Source map capacity to prevent unbounded rate-limiter growth.
const MAX_TRACKED_SOURCES: usize = 4096;
/// Packets-per-second refill rate for each source token bucket.
const SOURCE_RATE_LIMIT_PACKETS_PER_SEC: f64 = 5000.0;
/// Burst packet budget per source.
const SOURCE_RATE_LIMIT_BURST: f64 = 10000.0;
/// Idle timeout before a source bucket is dropped.
const SOURCE_BUCKET_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Absolute cap on tracked 0-RTT binder tuples to keep anti-replay memory bounded.
const MAX_RESUME_REPLAY_ENTRIES: usize = 65_536;
/// Small skew allowance so near-expiry accepted tuples are still rejected if replayed.
const RESUME_REPLAY_SKEW_SECS: u64 = 30;
/// Absolute cap on tracked authenticated client IDs for 0-RTT lookup.
const MAX_KNOWN_CLIENTS: usize = 65_536;
/// Small skew allowance to avoid immediate churn when pruning known clients.
const KNOWN_CLIENT_SKEW_SECS: u64 = 30;

const TYPE_DATA: u8 = b'D';
const TYPE_HANDSHAKE: u8 = b'H';
const TYPE_RESUME: u8 = b'R';
const TYPE_ACK: u8 = b'A';
const TYPE_PING: u8 = b'P';
const TYPE_PONG: u8 = b'O';
const TYPE_FEC_FEEDBACK: u8 = b'F';
const TYPE_STREAM_FIN: u8 = b'E';

/// Stable error taxonomy emitted via `KyuEvent::Fault`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KyuErrorCode {
    Config,
    Socket,
    HandshakeAuth,
    VersionMismatch,
    SessionLimit,
    SourceRateLimit,
    StreamLimit,
    DecoderMemoryLimit,
    PacketMalformed,
    PacketRejected,
    Io,
    Internal,
}

impl KyuErrorCode {
    /// Short machine-readable code used by structured logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Config => "CONFIG",
            Self::Socket => "SOCKET",
            Self::HandshakeAuth => "HANDSHAKE_AUTH",
            Self::VersionMismatch => "VERSION_MISMATCH",
            Self::SessionLimit => "SESSION_LIMIT",
            Self::SourceRateLimit => "SOURCE_RATE_LIMIT",
            Self::StreamLimit => "STREAM_LIMIT",
            Self::DecoderMemoryLimit => "DECODER_MEMORY_LIMIT",
            Self::PacketMalformed => "PACKET_MALFORMED",
            Self::PacketRejected => "PACKET_REJECTED",
            Self::Io => "IO",
            Self::Internal => "INTERNAL",
        }
    }
}

/// Packet shaping policy used for optional obfuscation and bandwidth control.
#[derive(Debug, Clone, Copy)]
pub enum PaddingMode {
    Fixed(usize),
    Disabled,
    Adaptive { min: usize, max: usize },
}

impl Default for PaddingMode {
    fn default() -> Self {
        Self::Fixed(DEFAULT_PADDING_TARGET)
    }
}

/// Runtime FEC adaptation policy.
#[derive(Debug, Clone, Copy)]
pub enum FecPolicy {
    Fixed,
    Adaptive {
        min: f32,
        max: f32,
        increase_step: f32,
        decrease_step: f32,
        high_watermark: f32,
        low_watermark: f32,
    },
}

impl Default for FecPolicy {
    fn default() -> Self {
        Self::Adaptive {
            min: 1.0,
            max: MAX_REDUNDANCY,
            increase_step: 0.15,
            decrease_step: 0.05,
            high_watermark: 1.20,
            low_watermark: 1.05,
        }
    }
}

/// Sender/receiver transport behavior knobs.
#[derive(Debug, Clone, Copy, Default)]
pub struct TransportConfig {
    pub pipeline: PipelineConfig,
    pub padding: PaddingMode,
    pub fec: FecPolicy,
}

/// Sender-facing media frame representation.
#[derive(Debug, Clone)]
pub struct MediaFrame {
    pub payload: Vec<u8>,
    pub timestamp_us: u64,
    pub keyframe: bool,
}

impl MediaFrame {
    /// Creates a binary frame with default timing metadata.
    pub fn binary(payload: Vec<u8>) -> Self {
        Self {
            payload,
            timestamp_us: 0,
            keyframe: false,
        }
    }
}

/// Configuration for `KyuSender::send_stream_from_source`.
#[derive(Debug, Clone)]
pub struct FrameStreamConfig {
    pub stream_name: String,
    pub semantics: StreamSemantics,
    pub declared_size: Option<u64>,
    pub initial_redundancy: f32,
    pub max_bytes_per_sec: u64,
}

/// Trait-based source of outbound frames (supports channel/read adapters).
pub trait FrameSource {
    fn next_frame(&mut self) -> Result<Option<MediaFrame>>;
}

/// Adapter that turns any blocking reader into a frame source.
pub struct ReaderFrameSource<R: Read> {
    reader: R,
    chunk_size: usize,
}

impl<R: Read> ReaderFrameSource<R> {
    pub fn new(reader: R, chunk_size: usize) -> Self {
        Self {
            reader,
            chunk_size: chunk_size.max(1),
        }
    }
}

impl<R: Read> FrameSource for ReaderFrameSource<R> {
    fn next_frame(&mut self) -> Result<Option<MediaFrame>> {
        let mut buffer = vec![0u8; self.chunk_size];
        let bytes_read = self.reader.read(&mut buffer)?;
        if bytes_read == 0 {
            return Ok(None);
        }
        buffer.truncate(bytes_read);
        Ok(Some(MediaFrame::binary(buffer)))
    }
}

/// Adapter for channel-driven real-time frame ingestion.
pub struct ChannelFrameSource {
    receiver: mpsc::Receiver<MediaFrame>,
}

impl ChannelFrameSource {
    pub fn new(receiver: mpsc::Receiver<MediaFrame>) -> Self {
        Self { receiver }
    }
}

impl FrameSource for ChannelFrameSource {
    fn next_frame(&mut self) -> Result<Option<MediaFrame>> {
        match self.receiver.recv() {
            Ok(frame) => Ok(Some(frame)),
            Err(_) => Ok(None),
        }
    }
}

/// Receiver-facing frame payload emitted by frame-mode processing.
#[derive(Debug, Clone)]
pub struct InboundFrame {
    pub session_id: u64,
    pub stream_id: u32,
    pub trace_id: u64,
    pub block_id: u64,
    pub timestamp_us: u64,
    pub keyframe: bool,
    pub payload: Vec<u8>,
}

/// Sink interface for non-filesystem receiver integrations.
pub trait FrameSink {
    fn on_manifest(&mut self, _session_id: u64, _stream_id: u32, _manifest: &SessionManifest) {}
    fn on_frame(&mut self, frame: InboundFrame) -> Result<()>;
    fn on_stream_end(
        &mut self,
        _session_id: u64,
        _stream_id: u32,
        _trace_id: u64,
        _final_bytes: u64,
        _final_frames: u64,
    ) {
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct FrameEnvelope {
    timestamp_us: u64,
    keyframe: bool,
    payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct FecFeedbackPacket {
    session_id: u64,
    stream_id: u32,
    block_id: u64,
    ideal_packets: u32,
    used_packets: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct StreamFinPacket {
    session_id: u64,
    stream_id: u32,
    final_bytes: u64,
    final_frames: u64,
}

/// Converts a 64-char hex string into a 32-byte PSK.
pub fn parse_psk_hex(input: &str) -> Result<[u8; 32]> {
    let trimmed = input.trim();
    if trimmed.len() != 64 {
        bail!("PSK must be exactly 64 hex characters (32 bytes)");
    }

    let mut out = [0u8; 32];
    for (index, chunk) in trimmed.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk).context("PSK contains non-UTF8 bytes")?;
        out[index] = u8::from_str_radix(pair, 16)
            .with_context(|| format!("PSK has invalid hex at byte index {index}"))?;
    }
    Ok(out)
}

/// Loads the required handshake PSK from `KYU2_PSK`.
fn load_psk_from_env() -> Result<[u8; 32]> {
    let raw = std::env::var("KYU2_PSK")
        .context("Missing KYU2_PSK. Set a 64-char hex PSK for authenticated handshakes")?;
    parse_psk_hex(&raw)
}

/// Loads the optional ticket encryption key from `KYU2_TICKET_KEY`.
/// Falls back to the handshake PSK when unset.
fn load_ticket_key_from_env_or_psk(psk: [u8; 32]) -> Result<[u8; 32]> {
    let Ok(raw) = std::env::var("KYU2_TICKET_KEY") else {
        return Ok(psk);
    };
    parse_psk_hex(&raw)
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn parse_u64_le(bytes: &[u8]) -> Option<u64> {
    let array: [u8; 8] = bytes.try_into().ok()?;
    Some(u64::from_le_bytes(array))
}

fn parse_u32_le(bytes: &[u8]) -> Option<u32> {
    let array: [u8; 4] = bytes.try_into().ok()?;
    Some(u32::from_le_bytes(array))
}

fn parse_u16_le(bytes: &[u8]) -> Option<u16> {
    let array: [u8; 2] = bytes.try_into().ok()?;
    Some(u16::from_le_bytes(array))
}

fn parse_header_u32(header: &[u8; GEOMETRY_HEADER_SIZE], start: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&header[start..start + 4]);
    u32::from_le_bytes(bytes)
}

fn parse_header_u64(header: &[u8; GEOMETRY_HEADER_SIZE], start: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&header[start..start + 8]);
    u64::from_le_bytes(bytes)
}

fn clamp_padding_target(target: usize, min_len: usize) -> usize {
    target.max(min_len).min(MAX_WIRE_PACKET_SIZE)
}

fn target_packet_len(mode: PaddingMode, raw_len: usize) -> usize {
    match mode {
        PaddingMode::Disabled => raw_len,
        PaddingMode::Fixed(target) => clamp_padding_target(target, raw_len),
        PaddingMode::Adaptive { min, max } => {
            let aligned = raw_len.div_ceil(ADAPTIVE_PADDING_ALIGN) * ADAPTIVE_PADDING_ALIGN;
            clamp_padding_target(aligned.clamp(min.max(raw_len), max.max(min)), raw_len)
        }
    }
}

fn adjust_redundancy(current: f32, feedback: &FecFeedbackPacket, policy: FecPolicy) -> f32 {
    let observed = if feedback.ideal_packets == 0 {
        1.0
    } else {
        feedback.used_packets as f32 / feedback.ideal_packets as f32
    };

    match policy {
        FecPolicy::Fixed => current,
        FecPolicy::Adaptive {
            min,
            max,
            increase_step,
            decrease_step,
            high_watermark,
            low_watermark,
        } => {
            if observed > high_watermark {
                (current + increase_step).clamp(min, max)
            } else if observed < low_watermark {
                (current - decrease_step).clamp(min, max)
            } else {
                current.clamp(min, max)
            }
        }
    }
}

/// Generates a dynamic XOR mask for the 22-byte geometry header.
fn generate_header_mask(
    header_key: &[u8; 32],
    payload_sample: &[u8],
) -> [u8; GEOMETRY_HEADER_SIZE] {
    let key = GenericArray::from_slice(header_key);
    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; 12];
    let copy_len = payload_sample.len().min(12);
    nonce_bytes[..copy_len].copy_from_slice(&payload_sample[..copy_len]);

    let nonce = GenericArray::from_slice(&nonce_bytes);
    if let Ok(encrypted) = cipher.encrypt(nonce, [0u8; GEOMETRY_HEADER_SIZE].as_ref()) {
        let mut mask = [0u8; GEOMETRY_HEADER_SIZE];
        mask.copy_from_slice(&encrypted[..GEOMETRY_HEADER_SIZE]);
        return mask;
    }

    [0u8; GEOMETRY_HEADER_SIZE]
}

/// Paces outbound traffic toward a target throughput.
struct Pacer {
    target_bytes_per_sec: u64,
    start_time: Instant,
    bytes_sent: u64,
}

impl Pacer {
    /// Creates a new pacer using bytes-per-second as its throughput target.
    fn new(target_bytes_per_sec: u64) -> Self {
        Self {
            target_bytes_per_sec,
            start_time: Instant::now(),
            bytes_sent: 0,
        }
    }

    /// Sleeps just enough to keep emitted traffic under the configured target.
    fn pace(&mut self, packet_size: u64) {
        if self.target_bytes_per_sec == 0 {
            return;
        }

        self.bytes_sent += packet_size;
        let expected_duration =
            Duration::from_secs_f64(self.bytes_sent as f64 / self.target_bytes_per_sec as f64);
        let elapsed = self.start_time.elapsed();
        if expected_duration > elapsed {
            thread::sleep(expected_duration - elapsed);
        }
    }
}

/// Public event stream emitted by sender/receiver operations.
#[derive(Debug, Clone)]
pub enum KyuEvent {
    Log(String),
    HandshakeInitiated,
    HandshakeComplete,
    FileDetected {
        stream_id: u32,
        trace_id: u64,
        name: String,
        size: u64,
    },
    Progress {
        stream_id: u32,
        trace_id: u64,
        current: u64,
        total: u64,
    },
    TransferComplete {
        stream_id: u32,
        trace_id: u64,
        path: PathBuf,
    },
    EarlyTermination {
        stream_id: u32,
        trace_id: u64,
    },
    /// Legacy free-form error string kept for compatibility.
    Error(String),
    /// Structured fault with explicit taxonomy.
    Fault {
        code: KyuErrorCode,
        message: String,
        session_id: Option<u64>,
        stream_id: Option<u32>,
        trace_id: Option<u64>,
    },
    /// Lightweight metric suitable for dashboards and alerting.
    Metric {
        name: &'static str,
        value: u64,
        session_id: Option<u64>,
        stream_id: Option<u32>,
        trace_id: Option<u64>,
    },
}

/// Sender-side context reused across all packets in a stream.
#[derive(Debug, Clone, Copy)]
struct TxPacketContext {
    session_id: u64,
    stream_id: u32,
    header_key: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
struct SendChunkArgs<'a> {
    context: &'a TxPacketContext,
    data: &'a [u8],
    block_id: u64,
    redundancy: f32,
}

/// Mutable sender-side stream state for multiplexed sending.
struct OutboundStream {
    path: PathBuf,
    stream_id: u32,
    trace_id: u64,
    file_size: u64,
    file: File,
    buffer: Vec<u8>,
    next_block_id: u64,
    bytes_sent: u64,
    frames_sent: u64,
    redundancy: f32,
    finished: bool,
}

pub struct KyuSender {
    socket: UdpSocket,
    primary_dest: String,
    relay_routes: Vec<String>,
    psk: [u8; 32],
    transport: TransportConfig,
    handshake_engine: Arc<dyn HandshakeEngine>,
    resumption_ticket: Option<SessionTicket>,
    session_id: Option<u64>,
    session_keys: Option<SessionKeys>,
    next_stream_id: u32,
}

impl KyuSender {
    pub fn new(dest: &str) -> Result<Self> {
        let psk = load_psk_from_env()?;
        Self::new_with_psk(dest, psk)
    }

    /// Creates a sender with an explicit PSK instead of environment loading.
    pub fn new_with_psk(dest: &str, psk: [u8; 32]) -> Result<Self> {
        Self::new_with_psk_and_ticket(dest, psk, None)
    }

    /// Creates a sender with explicit transport behavior.
    pub fn new_with_psk_and_config(
        dest: &str,
        psk: [u8; 32],
        config: TransportConfig,
    ) -> Result<Self> {
        Self::new_with_psk_ticket_config_and_engine(
            dest,
            psk,
            None,
            config,
            Arc::new(DefaultHandshakeEngine),
        )
    }

    /// Creates a sender with an explicit PSK and optional persisted resumption ticket.
    pub fn new_with_psk_and_ticket(
        dest: &str,
        psk: [u8; 32],
        ticket: Option<SessionTicket>,
    ) -> Result<Self> {
        Self::new_with_psk_ticket_config_and_engine(
            dest,
            psk,
            ticket,
            TransportConfig::default(),
            Arc::new(DefaultHandshakeEngine),
        )
    }

    /// Creates a sender with explicit dependencies and pluggable handshake engine.
    pub fn new_with_psk_ticket_config_and_engine(
        dest: &str,
        psk: [u8; 32],
        ticket: Option<SessionTicket>,
        config: TransportConfig,
        handshake_engine: Arc<dyn HandshakeEngine>,
    ) -> Result<Self> {
        crate::init();
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(dest)?;
        socket.set_nonblocking(true)?;

        let seed = rand::random::<u32>().max(1);
        Ok(Self {
            socket,
            primary_dest: dest.to_string(),
            relay_routes: Vec::new(),
            psk,
            transport: config,
            handshake_engine,
            resumption_ticket: ticket,
            session_id: None,
            session_keys: None,
            next_stream_id: seed,
        })
    }

    /// Configures relay fallback routes tried when direct handshake fails.
    pub fn set_relay_routes<I, S>(&mut self, routes: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.relay_routes = routes.into_iter().map(Into::into).collect();
    }

    /// Replaces the runtime transport config for future streams.
    pub fn set_transport_config(&mut self, config: TransportConfig) {
        self.transport = config;
    }

    /// Imports a previously exported ticket blob (for example from iOS Keychain).
    pub fn import_resumption_ticket(&mut self, blob: &[u8]) -> Result<()> {
        let ticket = bincode::deserialize::<SessionTicket>(blob)
            .context("Failed to deserialize resumption ticket blob")?;
        self.resumption_ticket = Some(ticket);
        Ok(())
    }

    /// Exports the latest ticket blob suitable for app-side secure storage.
    pub fn export_resumption_ticket(&self) -> Result<Option<Vec<u8>>> {
        let Some(ticket) = &self.resumption_ticket else {
            return Ok(None);
        };
        Ok(Some(
            bincode::serialize(ticket).context("Failed to serialize resumption ticket")?,
        ))
    }

    /// Returns the local UDP socket address in use by the sender.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    fn allocate_stream_id(&mut self) -> Result<u32> {
        let stream_id = self.next_stream_id;
        self.next_stream_id = self
            .next_stream_id
            .checked_add(1)
            .context("Stream id space exhausted for this sender session")?;
        Ok(stream_id)
    }

    fn allocate_trace_id() -> u64 {
        let mut trace_id = rand::random::<u64>();
        if trace_id == 0 {
            trace_id = 1;
        }
        trace_id
    }

    pub fn ping(&self) -> Result<()> {
        let Some(session_id) = self.session_id else {
            return Ok(());
        };

        let mut packet = vec![TYPE_PING];
        packet.extend_from_slice(&session_id.to_le_bytes());
        self.socket.send(&packet)?;
        Ok(())
    }

    /// Sends one file using the same resilient pipeline as `send_files`.
    pub fn send_file<F>(
        &mut self,
        path: &Path,
        redundancy: f32,
        max_bytes_per_sec: u64,
        on_event: F,
    ) -> Result<()>
    where
        F: Fn(KyuEvent),
    {
        self.send_files(
            &[path.to_path_buf()],
            redundancy,
            max_bytes_per_sec,
            on_event,
        )
    }

    /// Sends one logical media stream from a generic frame source.
    ///
    /// This API decouples transport from filesystem paths and is suitable for
    /// channel-driven real-time producers (Opus/H.264/etc).
    pub fn send_stream_from_source<S, F>(
        &mut self,
        source: &mut S,
        config: FrameStreamConfig,
        on_event: F,
    ) -> Result<()>
    where
        S: FrameSource,
        F: Fn(KyuEvent),
    {
        if !(1.0..=MAX_REDUNDANCY).contains(&config.initial_redundancy) {
            bail!("Redundancy must be in [1.0, {MAX_REDUNDANCY}]");
        }

        if self.session_id.is_none() || self.session_keys.is_none() {
            on_event(KyuEvent::HandshakeInitiated);
            let (session_id, session_keys) = self.perform_handshake()?;
            self.session_id = Some(session_id);
            self.session_keys = Some(session_keys);
            on_event(KyuEvent::HandshakeComplete);
        }

        let session_id = self
            .session_id
            .context("Sender missing session id after handshake")?;
        let session_keys = self
            .session_keys
            .context("Sender missing session keys after handshake")?;
        let stream_id = self.allocate_stream_id()?;
        let trace_id = Self::allocate_trace_id();
        let tx_context = TxPacketContext {
            session_id,
            stream_id,
            header_key: session_keys.header_tx,
        };

        let mut pipeline =
            KyuPipeline::new_with_config(&session_keys.payload_tx, self.transport.pipeline);
        let mut pacer = Pacer::new(config.max_bytes_per_sec);
        let mut redundancy = config.initial_redundancy.clamp(1.0, MAX_REDUNDANCY);

        let manifest = SessionManifest::new_stream(
            &config.stream_name,
            trace_id,
            config.declared_size,
            config.semantics,
        );
        let manifest_bytes = manifest.to_bytes()?;
        let manifest_redundancy = redundancy.clamp(2.0, MAX_REDUNDANCY);

        let continue_transfer = self.send_chunk(
            &mut pipeline,
            &mut pacer,
            SendChunkArgs {
                context: &tx_context,
                data: &manifest_bytes,
                block_id: 0,
                redundancy: manifest_redundancy,
            },
            |_| {},
        )?;
        if !continue_transfer {
            on_event(KyuEvent::EarlyTermination {
                stream_id,
                trace_id,
            });
            return Ok(());
        }

        let mut block_id = 1u64;
        let mut total_bytes = 0u64;
        let mut total_frames = 0u64;

        while let Some(frame) = source.next_frame()? {
            let frame_len = frame.payload.len() as u64;
            let envelope = FrameEnvelope {
                timestamp_us: frame.timestamp_us,
                keyframe: frame.keyframe,
                payload: frame.payload,
            };
            let frame_bytes = bincode::serialize(&envelope)
                .context("Failed to serialize media frame envelope")?;

            let continue_transfer = self.send_chunk(
                &mut pipeline,
                &mut pacer,
                SendChunkArgs {
                    context: &tx_context,
                    data: &frame_bytes,
                    block_id,
                    redundancy,
                },
                |feedback| {
                    if feedback.stream_id == stream_id {
                        redundancy = adjust_redundancy(redundancy, &feedback, self.transport.fec);
                    }
                },
            )?;
            if !continue_transfer {
                on_event(KyuEvent::EarlyTermination {
                    stream_id,
                    trace_id,
                });
                break;
            }

            total_bytes = total_bytes.saturating_add(frame_len);
            total_frames = total_frames.saturating_add(1);
            on_event(KyuEvent::Progress {
                stream_id,
                trace_id,
                current: total_bytes,
                total: config.declared_size.unwrap_or(total_bytes),
            });
            block_id = block_id.saturating_add(1);
        }

        self.send_stream_fin(session_id, stream_id, total_bytes, total_frames)?;
        on_event(KyuEvent::TransferComplete {
            stream_id,
            trace_id,
            path: PathBuf::from(format!("stream-{stream_id:x}.media")),
        });
        on_event(KyuEvent::Metric {
            name: "sender.stream.frames_total",
            value: total_frames,
            session_id: Some(session_id),
            stream_id: Some(stream_id),
            trace_id: Some(trace_id),
        });

        Ok(())
    }

    /// Sends multiple files over one UDP session with round-robin stream multiplexing.
    pub fn send_files<F>(
        &mut self,
        paths: &[PathBuf],
        redundancy: f32,
        max_bytes_per_sec: u64,
        on_event: F,
    ) -> Result<()>
    where
        F: Fn(KyuEvent),
    {
        if paths.is_empty() {
            bail!("send_files requires at least one input path");
        }
        if !(1.0..=MAX_REDUNDANCY).contains(&redundancy) {
            bail!("Redundancy must be in [1.0, {MAX_REDUNDANCY}]");
        }

        if self.session_id.is_none() || self.session_keys.is_none() {
            on_event(KyuEvent::HandshakeInitiated);
            let (session_id, session_keys) = self.perform_handshake()?;
            self.session_id = Some(session_id);
            self.session_keys = Some(session_keys);
            on_event(KyuEvent::HandshakeComplete);
        }

        let session_id = self
            .session_id
            .context("Sender missing session id after handshake")?;
        let session_keys = self
            .session_keys
            .context("Sender missing session keys after handshake")?;

        let mut pipeline =
            KyuPipeline::new_with_config(&session_keys.payload_tx, self.transport.pipeline);
        let mut pacer = Pacer::new(max_bytes_per_sec);
        let mut redundancy_by_stream: HashMap<u32, f32> = HashMap::new();

        let mut streams = Vec::with_capacity(paths.len());
        for path in paths {
            let filename = path
                .file_name()
                .context("Input path has no file name")?
                .to_string_lossy()
                .to_string();
            let file_size = path.metadata()?.len();
            let stream_id = self.allocate_stream_id()?;
            let trace_id = Self::allocate_trace_id();

            on_event(KyuEvent::Log(format!(
                "Starting transfer: {filename} (stream={stream_id:x}, trace={trace_id:016x})"
            )));

            let tx_context = TxPacketContext {
                session_id,
                stream_id,
                header_key: session_keys.header_tx,
            };
            let manifest = SessionManifest::new(&filename, file_size, trace_id);
            let manifest_bytes = manifest.to_bytes()?;
            let manifest_redundancy = redundancy.clamp(2.0, MAX_REDUNDANCY);

            let continue_transfer = self.send_chunk(
                &mut pipeline,
                &mut pacer,
                SendChunkArgs {
                    context: &tx_context,
                    data: &manifest_bytes,
                    block_id: 0,
                    redundancy: manifest_redundancy,
                },
                |_| {},
            )?;
            if !continue_transfer {
                on_event(KyuEvent::EarlyTermination {
                    stream_id,
                    trace_id,
                });
                continue;
            }

            streams.push(OutboundStream {
                path: path.clone(),
                stream_id,
                trace_id,
                file_size,
                file: File::open(path)?,
                buffer: vec![0u8; BLOCK_SIZE],
                next_block_id: 1,
                bytes_sent: 0,
                frames_sent: 0,
                redundancy: redundancy.clamp(1.0, MAX_REDUNDANCY),
                finished: false,
            });
            redundancy_by_stream.insert(stream_id, redundancy.clamp(1.0, MAX_REDUNDANCY));
        }

        if streams.is_empty() {
            return Ok(());
        }

        loop {
            let mut active_streams = 0usize;
            for stream in &mut streams {
                if stream.finished {
                    continue;
                }
                active_streams += 1;

                let bytes_read = stream.file.read(&mut stream.buffer)?;
                if bytes_read == 0 {
                    stream.finished = true;
                    let _ = self.send_stream_fin(
                        session_id,
                        stream.stream_id,
                        stream.bytes_sent,
                        stream.frames_sent,
                    );
                    on_event(KyuEvent::TransferComplete {
                        stream_id: stream.stream_id,
                        trace_id: stream.trace_id,
                        path: stream.path.clone(),
                    });
                    on_event(KyuEvent::Metric {
                        name: "sender.stream.bytes_total",
                        value: stream.file_size,
                        session_id: Some(session_id),
                        stream_id: Some(stream.stream_id),
                        trace_id: Some(stream.trace_id),
                    });
                    continue;
                }

                let tx_context = TxPacketContext {
                    session_id,
                    stream_id: stream.stream_id,
                    header_key: session_keys.header_tx,
                };
                let stream_id = stream.stream_id;
                let current_redundancy = *redundancy_by_stream
                    .get(&stream_id)
                    .unwrap_or(&stream.redundancy);

                let continue_transfer = self.send_chunk(
                    &mut pipeline,
                    &mut pacer,
                    SendChunkArgs {
                        context: &tx_context,
                        data: &stream.buffer[..bytes_read],
                        block_id: stream.next_block_id,
                        redundancy: current_redundancy,
                    },
                    |feedback| {
                        if feedback.stream_id == stream_id {
                            let current = redundancy_by_stream
                                .entry(stream_id)
                                .or_insert(current_redundancy);
                            *current = adjust_redundancy(*current, &feedback, self.transport.fec);
                        }
                    },
                )?;

                if !continue_transfer {
                    stream.finished = true;
                    on_event(KyuEvent::EarlyTermination {
                        stream_id: stream.stream_id,
                        trace_id: stream.trace_id,
                    });
                    continue;
                }

                stream.bytes_sent += bytes_read as u64;
                stream.frames_sent = stream.frames_sent.saturating_add(1);
                on_event(KyuEvent::Progress {
                    stream_id: stream.stream_id,
                    trace_id: stream.trace_id,
                    current: stream.bytes_sent.min(stream.file_size),
                    total: stream.file_size,
                });
                stream.next_block_id += 1;
            }

            if active_streams == 0 {
                break;
            }
        }

        Ok(())
    }

    /// Performs a 0-RTT resume when a valid ticket is present, otherwise falls back to 1-RTT.
    fn perform_handshake(&mut self) -> Result<(u64, SessionKeys)> {
        if let Some(ticket) = self.resumption_ticket.clone() {
            match self.perform_resumption_0rtt(&ticket) {
                Ok(resumed) => return Ok(resumed),
                Err(_) => {
                    // Drop stale/invalid ticket and continue with full 1-RTT bootstrap.
                    self.resumption_ticket = None;
                }
            }
        }

        let mut routes = Vec::with_capacity(1 + self.relay_routes.len());
        routes.push(self.primary_dest.clone());
        for route in &self.relay_routes {
            if !routes.iter().any(|existing| existing == route) {
                routes.push(route.clone());
            }
        }

        let mut last_error: Option<anyhow::Error> = None;
        for route in routes {
            if let Err(error) = self.socket.connect(&route) {
                last_error = Some(error.into());
                continue;
            }
            match self.perform_full_handshake_on_current_route() {
                Ok(result) => {
                    self.primary_dest = route;
                    return Ok(result);
                }
                Err(error) => {
                    last_error = Some(error);
                }
            }
        }

        if let Some(error) = last_error {
            return Err(error);
        }
        bail!("Handshake failed on all configured routes");
    }

    fn perform_full_handshake_on_current_route(&mut self) -> Result<(u64, SessionKeys)> {
        self.socket.set_nonblocking(false)?;
        self.socket.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;

        let handshake_result = (|| -> Result<(u64, SessionKeys)> {
            let my_keys = KeyExchange::new();
            let my_public = *my_keys.public.as_bytes();
            let session_id = rand::random::<u64>();

            let hello = self
                .handshake_engine
                .build_client_hello(session_id, my_public, &self.psk);
            let mut packet = vec![TYPE_HANDSHAKE];
            packet.extend(bincode::serialize(&hello)?);

            let mut buf = [0u8; 1024];
            for _ in 0..HANDSHAKE_RETRIES {
                self.socket.send(&packet)?;
                let Ok((amt, _src)) = self.socket.recv_from(&mut buf) else {
                    continue;
                };
                if amt <= 1 || buf[0] != TYPE_HANDSHAKE {
                    continue;
                }

                let Ok(server_hello) = bincode::deserialize::<HandshakePacket>(&buf[1..amt]) else {
                    continue;
                };
                if server_hello.session_id != session_id {
                    continue;
                }
                if server_hello.protocol_version != PROTOCOL_VERSION {
                    continue;
                }
                if !self
                    .handshake_engine
                    .verify_server_hello(&server_hello, &self.psk, my_public)
                {
                    continue;
                }

                let shared_secret = my_keys.derive_shared_secret(server_hello.public_key);
                let context = HandshakeContext {
                    protocol_version: server_hello.protocol_version,
                    capabilities: server_hello.capabilities,
                    session_id,
                    client_public: my_public,
                    server_public: server_hello.public_key,
                };
                let keys = self.handshake_engine.derive_session_keys(
                    shared_secret,
                    &self.psk,
                    HandshakeRole::Client,
                    &context,
                )?;

                if let Some(ticket) = server_hello.session_ticket
                    && ticket.expires_at > unix_now_secs()
                {
                    self.resumption_ticket = Some(ticket);
                }
                return Ok((session_id, keys));
            }

            bail!("Handshake timed out or authentication failed")
        })();

        self.socket.set_nonblocking(true)?;
        self.socket.set_read_timeout(None)?;
        handshake_result
    }

    /// Sends a resumable client hello and immediately derives 0-RTT session keys.
    fn perform_resumption_0rtt(&self, ticket: &SessionTicket) -> Result<(u64, SessionKeys)> {
        if ticket.expires_at <= unix_now_secs() {
            bail!("Resumption ticket is expired");
        }

        let session_id = rand::random::<u64>();
        let resume = self
            .handshake_engine
            .build_resume_packet(session_id, ticket);
        let mut packet = vec![TYPE_RESUME];
        packet.extend(bincode::serialize(&resume)?);
        self.socket.send(&packet)?;

        let keys = self.handshake_engine.derive_resumption_session_keys(
            ticket.resumption_secret,
            HandshakeRole::Client,
            session_id,
            resume.client_nonce,
        )?;
        Ok((session_id, keys))
    }

    /// Emits an explicit stream finalization control packet.
    fn send_stream_fin(
        &self,
        session_id: u64,
        stream_id: u32,
        final_bytes: u64,
        final_frames: u64,
    ) -> Result<()> {
        let fin = StreamFinPacket {
            session_id,
            stream_id,
            final_bytes,
            final_frames,
        };
        let mut packet = vec![TYPE_STREAM_FIN];
        packet.extend(bincode::serialize(&fin)?);
        self.socket.send(&packet)?;
        Ok(())
    }

    /// Returns false if the receiver ACKed completion and requested early stop.
    fn send_chunk(
        &self,
        pipeline: &mut KyuPipeline,
        pacer: &mut Pacer,
        args: SendChunkArgs<'_>,
        mut on_feedback: impl FnMut(FecFeedbackPacket),
    ) -> Result<bool> {
        let protected = pipeline.protect_block(args.data, args.context.stream_id, args.block_id)?;
        let total_size =
            u32::try_from(protected.len()).context("Protected block exceeded u32 length")?;

        if total_size == 0 || total_size > MAX_PROTECTED_BLOCK_SIZE {
            bail!(
                "Protected block size {total_size} outside allowed range (1..={MAX_PROTECTED_BLOCK_SIZE})"
            );
        }

        let mut pkt_size = TARGET_PACKET_SIZE as u32;
        if total_size <= pkt_size {
            pkt_size = total_size.div_ceil(2).max(1);
        }

        let encoder = WirehairEncoder::new(&protected, pkt_size)?;
        let needed_packets = total_size.div_ceil(pkt_size);
        let bounded_redundancy = args.redundancy.clamp(1.0, MAX_REDUNDANCY);
        let total_packets = ((needed_packets as f32) * bounded_redundancy).ceil() as u32;

        let mut control_buf = [0u8; 256];
        for seq_id in 0..total_packets {
            loop {
                match self.socket.recv_from(&mut control_buf) {
                    Ok((amt, _)) if amt >= 1 => match control_buf[0] {
                        TYPE_ACK if amt == ACK_PACKET_SIZE => {
                            let ack_session = control_buf.get(1..9).and_then(parse_u64_le);
                            let ack_stream = control_buf.get(9..13).and_then(parse_u32_le);
                            if ack_session == Some(args.context.session_id)
                                && ack_stream == Some(args.context.stream_id)
                            {
                                return Ok(false);
                            }
                        }
                        TYPE_FEC_FEEDBACK => {
                            if let Ok(feedback) =
                                bincode::deserialize::<FecFeedbackPacket>(&control_buf[1..amt])
                                && feedback.session_id == args.context.session_id
                            {
                                on_feedback(feedback);
                            }
                        }
                        _ => {}
                    },
                    Ok(_) => break,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == ErrorKind::TimedOut => break,
                    Err(error) => return Err(error.into()),
                }
            }

            let packet_data = encoder
                .encode(seq_id)
                .map_err(|error| anyhow::anyhow!("{error:?}"))?;

            let mut plain_header = [0u8; GEOMETRY_HEADER_SIZE];
            plain_header[0..4].copy_from_slice(&args.context.stream_id.to_le_bytes());
            plain_header[4..12].copy_from_slice(&args.block_id.to_le_bytes());
            plain_header[12..16].copy_from_slice(&seq_id.to_le_bytes());
            plain_header[16..20].copy_from_slice(&total_size.to_le_bytes());
            plain_header[20..22].copy_from_slice(&(pkt_size as u16).to_le_bytes());

            let mask = generate_header_mask(&args.context.header_key, &packet_data);
            for index in 0..GEOMETRY_HEADER_SIZE {
                plain_header[index] ^= mask[index];
            }

            let mut wire_packet = Vec::with_capacity(CONSTANT_UDP_SIZE);
            wire_packet.push(TYPE_DATA);
            wire_packet.extend_from_slice(&args.context.session_id.to_le_bytes());
            wire_packet.extend_from_slice(&plain_header);
            wire_packet.extend_from_slice(&packet_data);
            let target_len = target_packet_len(self.transport.padding, wire_packet.len());
            if wire_packet.len() < target_len {
                wire_packet.resize(target_len, 0u8);
            }

            loop {
                match self.socket.send(&wire_packet) {
                    Ok(_) => break,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_micros(100));
                    }
                    Err(error) => return Err(error.into()),
                }
            }

            pacer.pace(wire_packet.len() as u64);
        }

        on_metric_sender(args.context, args.data.len() as u64);
        Ok(true)
    }
}

/// Emits sender-side metrics currently tracked outside the public event stream.
fn on_metric_sender(_context: &TxPacketContext, _chunk_bytes: u64) {
    // Placeholder hook for future sender-internal metric sinks.
}

/// Receiver-side file writing state for a stream.
struct FileState {
    file: File,
    total_bytes: u64,
    trace_id: u64,
    path: PathBuf,
}

/// Receiver-side decoder state for one block of one stream.
struct DecoderState {
    block_id: u64,
    allocated_bytes: u64,
    decoder: WirehairDecoder,
}

/// Receiver-side stream aggregation state.
struct StreamState {
    file_state: Option<FileState>,
    decoder_state: Option<DecoderState>,
    manifest: Option<SessionManifest>,
    expected_size: Option<u64>,
    trace_id: u64,
    final_bytes: Option<u64>,
    final_frames: Option<u64>,
    fin_received: bool,
    frames_received: u64,
    bytes_received: u64,
    /// Monotonic block cursor to prevent duplicate/out-of-order block replays.
    next_block_id: u64,
}

/// Receiver-side session state keyed by sender-chosen session id.
struct SessionState {
    source_ip: IpAddr,
    keys: SessionKeys,
    pipeline: KyuPipeline,
    streams: HashMap<u32, StreamState>,
    decoder_memory_bytes: u64,
    last_active: Instant,
}

/// Sliding token bucket state for a single source address.
#[derive(Debug, Clone)]
struct SourceBucket {
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
}

/// Per-source packet admission controller.
#[derive(Debug, Default)]
struct SourceRateLimiter {
    buckets: HashMap<IpAddr, SourceBucket>,
}

impl SourceRateLimiter {
    /// Returns true if a packet from `source` should be processed.
    fn allow(&mut self, source: IpAddr, now: Instant) -> bool {
        if !self.buckets.contains_key(&source) {
            if self.buckets.len() >= MAX_TRACKED_SOURCES {
                return false;
            }
            self.buckets.insert(
                source,
                SourceBucket {
                    tokens: SOURCE_RATE_LIMIT_BURST,
                    last_refill: now,
                    last_seen: now,
                },
            );
        }
        let Some(bucket) = self.buckets.get_mut(&source) else {
            return false;
        };

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * SOURCE_RATE_LIMIT_PACKETS_PER_SEC)
            .min(SOURCE_RATE_LIMIT_BURST);
        bucket.last_refill = now;
        bucket.last_seen = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Removes idle buckets to keep source map memory bounded.
    fn sweep_idle(&mut self, now: Instant) {
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_seen) <= SOURCE_BUCKET_IDLE_TIMEOUT);
    }
}

/// Interval metrics emitted by the receiver loop.
#[derive(Debug, Default)]
struct ReceiverCounters {
    packets_in: u64,
    packets_rate_limited: u64,
    packets_malformed: u64,
    packets_rejected: u64,
    handshakes_accepted: u64,
    handshakes_rejected: u64,
    resume_replay_rejected: u64,
    known_client_registered: u64,
    stream_limit_rejected: u64,
    decoder_memory_rejected: u64,
}

/// Replay key identifying one accepted 0-RTT binder tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ResumeReplayKey {
    ticket_id: [u8; 16],
    client_nonce: [u8; 24],
}

/// Mutable receiver runtime state maintained between loop iterations.
#[derive(Default)]
struct ReceiverRuntime {
    sessions: HashMap<u64, SessionState>,
    known_clients: HashMap<[u8; 16], u64>,
    known_client_order: VecDeque<[u8; 16]>,
    resume_replay: HashMap<ResumeReplayKey, u64>,
    resume_replay_order: VecDeque<ResumeReplayKey>,
    total_decoder_memory_bytes: u64,
    last_gc_sweep: Option<Instant>,
    rate_limiter: SourceRateLimiter,
    counters: ReceiverCounters,
}

impl ReceiverRuntime {
    /// Creates loop state initialized with a GC timestamp baseline.
    fn new() -> Self {
        Self {
            last_gc_sweep: Some(Instant::now()),
            ..Self::default()
        }
    }

    fn interval_elapsed(&self) -> bool {
        self.last_gc_sweep
            .map(|instant| instant.elapsed() > SESSION_GC_INTERVAL)
            .unwrap_or(true)
    }

    fn reset_interval(&mut self) {
        self.last_gc_sweep = Some(Instant::now());
        self.counters = ReceiverCounters::default();
    }

    /// Records a validated ticket/binder tuple and returns false on replay.
    fn register_resume_nonce(
        &mut self,
        ticket_id: [u8; 16],
        client_nonce: [u8; 24],
        expires_at: u64,
        now_secs: u64,
    ) -> bool {
        self.sweep_resume_replay(now_secs);

        let key = ResumeReplayKey {
            ticket_id,
            client_nonce,
        };
        if let Some(stored_expires_at) = self.resume_replay.get_mut(&key) {
            if *stored_expires_at >= now_secs {
                return false;
            }
            *stored_expires_at = expires_at.saturating_add(RESUME_REPLAY_SKEW_SECS);
            return true;
        }

        self.resume_replay
            .insert(key, expires_at.saturating_add(RESUME_REPLAY_SKEW_SECS));
        self.resume_replay_order.push_back(key);

        while self.resume_replay.len() > MAX_RESUME_REPLAY_ENTRIES {
            let Some(oldest) = self.resume_replay_order.pop_front() else {
                break;
            };
            self.resume_replay.remove(&oldest);
        }

        true
    }

    /// Drops expired anti-replay tuples and keeps ordering state in sync.
    fn sweep_resume_replay(&mut self, now_secs: u64) {
        self.resume_replay
            .retain(|_, expires_at| *expires_at >= now_secs);
        self.resume_replay_order
            .retain(|key| self.resume_replay.contains_key(key));
    }

    /// Tracks a recently authenticated client ID with bounded memory and expiry.
    fn register_known_client(&mut self, client_id: [u8; 16], expires_at: u64, now_secs: u64) {
        self.sweep_known_clients(now_secs);

        let expiry = expires_at.saturating_add(KNOWN_CLIENT_SKEW_SECS);
        if let Some(stored_expiry) = self.known_clients.get_mut(&client_id) {
            *stored_expiry = (*stored_expiry).max(expiry);
            return;
        }

        self.known_clients.insert(client_id, expiry);
        self.known_client_order.push_back(client_id);
        self.counters.known_client_registered =
            self.counters.known_client_registered.saturating_add(1);

        while self.known_clients.len() > MAX_KNOWN_CLIENTS {
            let Some(oldest_client_id) = self.known_client_order.pop_front() else {
                break;
            };
            self.known_clients.remove(&oldest_client_id);
        }
    }

    /// Removes expired known-client entries and compacts ordering metadata.
    fn sweep_known_clients(&mut self, now_secs: u64) {
        self.known_clients
            .retain(|_, expires_at| *expires_at >= now_secs);
        self.known_client_order
            .retain(|client_id| self.known_clients.contains_key(client_id));
    }
}

pub struct KyuReceiver {
    socket: UdpSocket,
    out_dir: PathBuf,
    psk: [u8; 32],
    ticket_key: [u8; 32],
    transport: TransportConfig,
    handshake_engine: Arc<dyn HandshakeEngine>,
}

impl KyuReceiver {
    pub fn new(bind_addr: &str, out_dir: &Path) -> Result<Self> {
        let psk = load_psk_from_env()?;
        let ticket_key = load_ticket_key_from_env_or_psk(psk)?;
        Self::new_with_psk_and_ticket_key(bind_addr, out_dir, psk, ticket_key)
    }

    /// Creates a receiver with an explicit PSK instead of environment loading.
    pub fn new_with_psk(bind_addr: &str, out_dir: &Path, psk: [u8; 32]) -> Result<Self> {
        Self::new_with_psk_and_ticket_key(bind_addr, out_dir, psk, psk)
    }

    /// Creates a receiver with explicit bootstrap PSK and ticket encryption key.
    pub fn new_with_psk_and_ticket_key(
        bind_addr: &str,
        out_dir: &Path,
        psk: [u8; 32],
        ticket_key: [u8; 32],
    ) -> Result<Self> {
        Self::new_with_psk_ticket_key_config_and_engine(
            bind_addr,
            out_dir,
            psk,
            ticket_key,
            TransportConfig::default(),
            Arc::new(DefaultHandshakeEngine),
        )
    }

    /// Creates a receiver with explicit transport behavior.
    pub fn new_with_psk_ticket_key_and_config(
        bind_addr: &str,
        out_dir: &Path,
        psk: [u8; 32],
        ticket_key: [u8; 32],
        config: TransportConfig,
    ) -> Result<Self> {
        Self::new_with_psk_ticket_key_config_and_engine(
            bind_addr,
            out_dir,
            psk,
            ticket_key,
            config,
            Arc::new(DefaultHandshakeEngine),
        )
    }

    /// Creates a receiver with explicit dependencies and pluggable handshake engine.
    pub fn new_with_psk_ticket_key_config_and_engine(
        bind_addr: &str,
        out_dir: &Path,
        psk: [u8; 32],
        ticket_key: [u8; 32],
        config: TransportConfig,
        handshake_engine: Arc<dyn HandshakeEngine>,
    ) -> Result<Self> {
        crate::init();
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;

        Ok(Self {
            socket,
            out_dir: out_dir.to_path_buf(),
            psk,
            ticket_key,
            transport: config,
            handshake_engine,
        })
    }

    /// Returns the local UDP socket address in use by the receiver.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    /// Runs indefinitely until an unrecoverable socket error is hit.
    pub fn run_loop<F>(&self, on_event: F) -> Result<()>
    where
        F: Fn(u64, KyuEvent),
    {
        self.run_loop_until(on_event, || false)
    }

    /// Runs until `should_stop` returns true or an unrecoverable socket error is hit.
    pub fn run_loop_until<F, S>(&self, on_event: F, mut should_stop: S) -> Result<()>
    where
        F: Fn(u64, KyuEvent),
        S: FnMut() -> bool,
    {
        let mut buf = [0u8; 2048];
        let mut runtime = ReceiverRuntime::new();

        on_event(
            0,
            KyuEvent::Log(format!("Listening on {:?}", self.socket.local_addr()?)),
        );

        loop {
            if should_stop() {
                break;
            }

            if runtime.interval_elapsed() {
                self.sweep_runtime(&mut runtime, &on_event);
            }

            match self.socket.recv_from(&mut buf) {
                Ok((amt, src)) => {
                    if amt == 0 {
                        continue;
                    }

                    let now = Instant::now();
                    if !runtime.rate_limiter.allow(src.ip(), now) {
                        runtime.counters.packets_rate_limited += 1;
                        continue;
                    }
                    runtime.counters.packets_in += 1;

                    let packet = &buf[..amt];
                    match packet[0] {
                        TYPE_HANDSHAKE => {
                            self.handle_handshake_packet(&mut runtime, packet, src, &on_event)
                        }
                        TYPE_RESUME => {
                            self.handle_resume_packet(&mut runtime, packet, src, &on_event)
                        }
                        TYPE_STREAM_FIN => {
                            self.handle_stream_fin_packet(&mut runtime, packet, src, &on_event)
                        }
                        TYPE_PING => self.handle_ping_packet(&mut runtime, packet, src),
                        TYPE_DATA => self.handle_data_packet(&mut runtime, packet, src, &on_event),
                        TYPE_FEC_FEEDBACK => {}
                        _ => {
                            runtime.counters.packets_rejected += 1;
                        }
                    }
                }
                Err(error)
                    if error.kind() == ErrorKind::WouldBlock
                        || error.kind() == ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(error) => {
                    on_event(
                        0,
                        KyuEvent::Fault {
                            code: KyuErrorCode::Socket,
                            message: format!("Socket error: {error}"),
                            session_id: None,
                            stream_id: None,
                            trace_id: None,
                        },
                    );
                    on_event(0, KyuEvent::Error(format!("Socket error: {error}")));
                    break;
                }
            }
        }

        Ok(())
    }

    /// Runs a receiver loop that emits decoded media frames to an arbitrary sink.
    pub fn run_loop_frames<S, F>(&self, sink: &mut S, on_event: F) -> Result<()>
    where
        S: FrameSink,
        F: Fn(u64, KyuEvent),
    {
        self.run_loop_frames_until(sink, on_event, || false)
    }

    /// Runs a frame-mode receiver loop until `should_stop` returns true.
    pub fn run_loop_frames_until<S, F, Stop>(
        &self,
        sink: &mut S,
        on_event: F,
        mut should_stop: Stop,
    ) -> Result<()>
    where
        S: FrameSink,
        F: Fn(u64, KyuEvent),
        Stop: FnMut() -> bool,
    {
        let mut buf = [0u8; 2048];
        let mut runtime = ReceiverRuntime::new();

        on_event(
            0,
            KyuEvent::Log(format!(
                "Listening (frame mode) on {:?}",
                self.socket.local_addr()?
            )),
        );

        loop {
            if should_stop() {
                break;
            }

            if runtime.interval_elapsed() {
                self.sweep_runtime(&mut runtime, &on_event);
            }

            match self.socket.recv_from(&mut buf) {
                Ok((amt, src)) => {
                    if amt == 0 {
                        continue;
                    }

                    let now = Instant::now();
                    if !runtime.rate_limiter.allow(src.ip(), now) {
                        runtime.counters.packets_rate_limited += 1;
                        continue;
                    }
                    runtime.counters.packets_in += 1;

                    let packet = &buf[..amt];
                    match packet[0] {
                        TYPE_HANDSHAKE => {
                            self.handle_handshake_packet(&mut runtime, packet, src, &on_event)
                        }
                        TYPE_RESUME => {
                            self.handle_resume_packet(&mut runtime, packet, src, &on_event)
                        }
                        TYPE_STREAM_FIN => self.handle_stream_fin_packet_frames(
                            &mut runtime,
                            packet,
                            src,
                            sink,
                            &on_event,
                        ),
                        TYPE_PING => self.handle_ping_packet(&mut runtime, packet, src),
                        TYPE_DATA => self.handle_data_packet_frames(
                            &mut runtime,
                            packet,
                            src,
                            sink,
                            &on_event,
                        ),
                        TYPE_FEC_FEEDBACK => {}
                        _ => {
                            runtime.counters.packets_rejected += 1;
                        }
                    }
                }
                Err(error)
                    if error.kind() == ErrorKind::WouldBlock
                        || error.kind() == ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(error) => {
                    on_event(
                        0,
                        KyuEvent::Fault {
                            code: KyuErrorCode::Socket,
                            message: format!("Socket error: {error}"),
                            session_id: None,
                            stream_id: None,
                            trace_id: None,
                        },
                    );
                    on_event(0, KyuEvent::Error(format!("Socket error: {error}")));
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handles periodic runtime cleanup and metric emission.
    fn sweep_runtime<F>(&self, runtime: &mut ReceiverRuntime, on_event: &F)
    where
        F: Fn(u64, KyuEvent),
    {
        let now = Instant::now();
        let now_secs = unix_now_secs();
        let mut reclaimed_memory = 0u64;

        runtime.sessions.retain(|session_id, session| {
            let alive = session.last_active.elapsed() < SESSION_IDLE_TIMEOUT;
            if !alive {
                reclaimed_memory += session.decoder_memory_bytes;
                on_event(
                    *session_id,
                    KyuEvent::Log("Session dropped due to inactivity timeout".to_string()),
                );
            }
            alive
        });

        runtime.total_decoder_memory_bytes = runtime
            .total_decoder_memory_bytes
            .saturating_sub(reclaimed_memory);
        runtime.rate_limiter.sweep_idle(now);
        runtime.sweep_known_clients(now_secs);
        runtime.sweep_resume_replay(now_secs);

        on_event(
            0,
            KyuEvent::Metric {
                name: "receiver.packets_in",
                value: runtime.counters.packets_in,
                session_id: None,
                stream_id: None,
                trace_id: None,
            },
        );
        on_event(
            0,
            KyuEvent::Metric {
                name: "receiver.packets_rate_limited",
                value: runtime.counters.packets_rate_limited,
                session_id: None,
                stream_id: None,
                trace_id: None,
            },
        );
        on_event(
            0,
            KyuEvent::Metric {
                name: "receiver.packets_malformed",
                value: runtime.counters.packets_malformed,
                session_id: None,
                stream_id: None,
                trace_id: None,
            },
        );
        on_event(
            0,
            KyuEvent::Metric {
                name: "receiver.packets_rejected",
                value: runtime.counters.packets_rejected,
                session_id: None,
                stream_id: None,
                trace_id: None,
            },
        );
        on_event(
            0,
            KyuEvent::Metric {
                name: "receiver.handshakes_accepted",
                value: runtime.counters.handshakes_accepted,
                session_id: None,
                stream_id: None,
                trace_id: None,
            },
        );
        on_event(
            0,
            KyuEvent::Metric {
                name: "receiver.handshakes_rejected",
                value: runtime.counters.handshakes_rejected,
                session_id: None,
                stream_id: None,
                trace_id: None,
            },
        );
        on_event(
            0,
            KyuEvent::Metric {
                name: "receiver.resume_replay_rejected",
                value: runtime.counters.resume_replay_rejected,
                session_id: None,
                stream_id: None,
                trace_id: None,
            },
        );
        on_event(
            0,
            KyuEvent::Metric {
                name: "receiver.known_client_registered",
                value: runtime.counters.known_client_registered,
                session_id: None,
                stream_id: None,
                trace_id: None,
            },
        );
        on_event(
            0,
            KyuEvent::Metric {
                name: "receiver.known_clients_active",
                value: runtime.known_clients.len() as u64,
                session_id: None,
                stream_id: None,
                trace_id: None,
            },
        );
        on_event(
            0,
            KyuEvent::Metric {
                name: "receiver.decoder_memory_bytes",
                value: runtime.total_decoder_memory_bytes,
                session_id: None,
                stream_id: None,
                trace_id: None,
            },
        );

        runtime.reset_interval();
    }

    fn handle_handshake_packet<F>(
        &self,
        runtime: &mut ReceiverRuntime,
        packet: &[u8],
        src: SocketAddr,
        on_event: &F,
    ) where
        F: Fn(u64, KyuEvent),
    {
        let Ok(client_hello) = bincode::deserialize::<HandshakePacket>(&packet[1..]) else {
            runtime.counters.handshakes_rejected += 1;
            runtime.counters.packets_malformed += 1;
            return;
        };

        if !self
            .handshake_engine
            .verify_client_hello(&client_hello, &self.psk)
        {
            runtime.counters.handshakes_rejected += 1;
            on_event(
                client_hello.session_id,
                KyuEvent::Fault {
                    code: KyuErrorCode::HandshakeAuth,
                    message: "Rejected unauthenticated handshake".to_string(),
                    session_id: Some(client_hello.session_id),
                    stream_id: None,
                    trace_id: None,
                },
            );
            return;
        }

        let is_new_session = !runtime.sessions.contains_key(&client_hello.session_id);
        if is_new_session && runtime.sessions.len() >= MAX_SESSIONS {
            runtime.counters.handshakes_rejected += 1;
            on_event(
                client_hello.session_id,
                KyuEvent::Fault {
                    code: KyuErrorCode::SessionLimit,
                    message: "Session limit reached; rejecting new handshake".to_string(),
                    session_id: Some(client_hello.session_id),
                    stream_id: None,
                    trace_id: None,
                },
            );
            return;
        }

        if is_new_session {
            let source_session_count = runtime
                .sessions
                .values()
                .filter(|session| session.source_ip == src.ip())
                .count();
            if source_session_count >= MAX_SESSIONS_PER_SOURCE {
                runtime.counters.handshakes_rejected += 1;
                on_event(
                    client_hello.session_id,
                    KyuEvent::Fault {
                        code: KyuErrorCode::SessionLimit,
                        message: "Per-source session limit reached; rejecting handshake"
                            .to_string(),
                        session_id: Some(client_hello.session_id),
                        stream_id: None,
                        trace_id: None,
                    },
                );
                return;
            }
        }

        let server_keys = KeyExchange::new();
        let server_public = *server_keys.public.as_bytes();
        let now_secs = unix_now_secs();
        let session_ticket = self
            .handshake_engine
            .issue_session_ticket(&self.ticket_key, SESSION_TICKET_LIFETIME_SECS)
            .ok();
        if let Some(ticket) = session_ticket.as_ref()
            && let Some(validated) = self.handshake_engine.validate_ticket_identity(
                &self.ticket_key,
                &ticket.identity,
                now_secs,
            )
        {
            runtime.register_known_client(validated.client_id, validated.expires_at, now_secs);
        }
        let reply = self.handshake_engine.build_server_hello(
            client_hello.session_id,
            server_public,
            client_hello.public_key,
            &self.psk,
            session_ticket,
        );

        let mut response = vec![TYPE_HANDSHAKE];
        let Ok(serialized_reply) = bincode::serialize(&reply) else {
            runtime.counters.handshakes_rejected += 1;
            on_event(
                client_hello.session_id,
                KyuEvent::Fault {
                    code: KyuErrorCode::Internal,
                    message: "Failed to serialize handshake response".to_string(),
                    session_id: Some(client_hello.session_id),
                    stream_id: None,
                    trace_id: None,
                },
            );
            return;
        };
        response.extend(serialized_reply);
        let _ = self.socket.send_to(&response, src);

        let shared_secret = server_keys.derive_shared_secret(client_hello.public_key);
        let context = HandshakeContext {
            protocol_version: PROTOCOL_VERSION,
            capabilities: client_hello.capabilities,
            session_id: client_hello.session_id,
            client_public: client_hello.public_key,
            server_public,
        };

        let Ok(session_keys) = self.handshake_engine.derive_session_keys(
            shared_secret,
            &self.psk,
            HandshakeRole::Server,
            &context,
        ) else {
            runtime.counters.handshakes_rejected += 1;
            on_event(
                client_hello.session_id,
                KyuEvent::Fault {
                    code: KyuErrorCode::Internal,
                    message: "Failed to derive session keys".to_string(),
                    session_id: Some(client_hello.session_id),
                    stream_id: None,
                    trace_id: None,
                },
            );
            return;
        };

        if let Some(previous) = runtime.sessions.remove(&client_hello.session_id) {
            runtime.total_decoder_memory_bytes = runtime
                .total_decoder_memory_bytes
                .saturating_sub(previous.decoder_memory_bytes);
        }

        runtime.sessions.insert(
            client_hello.session_id,
            SessionState {
                source_ip: src.ip(),
                keys: session_keys,
                pipeline: KyuPipeline::new_with_config(
                    &session_keys.payload_rx,
                    self.transport.pipeline,
                ),
                streams: HashMap::new(),
                decoder_memory_bytes: 0,
                last_active: Instant::now(),
            },
        );
        runtime.counters.handshakes_accepted += 1;
        on_event(client_hello.session_id, KyuEvent::HandshakeComplete);
    }

    fn handle_resume_packet<F>(
        &self,
        runtime: &mut ReceiverRuntime,
        packet: &[u8],
        src: SocketAddr,
        on_event: &F,
    ) where
        F: Fn(u64, KyuEvent),
    {
        let Ok(resume) = bincode::deserialize::<ResumePacket>(&packet[1..]) else {
            runtime.counters.handshakes_rejected += 1;
            runtime.counters.packets_malformed += 1;
            return;
        };

        if resume.protocol_version != PROTOCOL_VERSION {
            runtime.counters.handshakes_rejected += 1;
            on_event(
                resume.session_id,
                KyuEvent::Fault {
                    code: KyuErrorCode::VersionMismatch,
                    message: "Rejected resume packet due to protocol version mismatch".to_string(),
                    session_id: Some(resume.session_id),
                    stream_id: None,
                    trace_id: None,
                },
            );
            return;
        }

        let now_secs = unix_now_secs();
        let Some(validated_ticket) = self.handshake_engine.validate_ticket_identity(
            &self.ticket_key,
            &resume.ticket_identity,
            now_secs,
        ) else {
            runtime.counters.handshakes_rejected += 1;
            on_event(
                resume.session_id,
                KyuEvent::Fault {
                    code: KyuErrorCode::HandshakeAuth,
                    message: "Rejected invalid or expired resumption ticket".to_string(),
                    session_id: Some(resume.session_id),
                    stream_id: None,
                    trace_id: None,
                },
            );
            return;
        };

        if validated_ticket.expires_at != resume.expires_at
            || !self.handshake_engine.verify_resume_packet(
                &resume,
                &validated_ticket.resumption_secret,
                now_secs,
            )
        {
            runtime.counters.handshakes_rejected += 1;
            on_event(
                resume.session_id,
                KyuEvent::Fault {
                    code: KyuErrorCode::HandshakeAuth,
                    message: "Rejected resume binder verification".to_string(),
                    session_id: Some(resume.session_id),
                    stream_id: None,
                    trace_id: None,
                },
            );
            return;
        }

        if !runtime.register_resume_nonce(
            validated_ticket.ticket_id,
            resume.client_nonce,
            validated_ticket.expires_at,
            now_secs,
        ) {
            runtime.counters.handshakes_rejected += 1;
            runtime.counters.resume_replay_rejected += 1;
            on_event(
                resume.session_id,
                KyuEvent::Fault {
                    code: KyuErrorCode::HandshakeAuth,
                    message: "Rejected replayed 0-RTT resume packet".to_string(),
                    session_id: Some(resume.session_id),
                    stream_id: None,
                    trace_id: None,
                },
            );
            return;
        }

        let is_new_session = !runtime.sessions.contains_key(&resume.session_id);
        if is_new_session && runtime.sessions.len() >= MAX_SESSIONS {
            runtime.counters.handshakes_rejected += 1;
            on_event(
                resume.session_id,
                KyuEvent::Fault {
                    code: KyuErrorCode::SessionLimit,
                    message: "Session limit reached; rejecting resumed session".to_string(),
                    session_id: Some(resume.session_id),
                    stream_id: None,
                    trace_id: None,
                },
            );
            return;
        }

        if is_new_session {
            let source_session_count = runtime
                .sessions
                .values()
                .filter(|session| session.source_ip == src.ip())
                .count();
            if source_session_count >= MAX_SESSIONS_PER_SOURCE {
                runtime.counters.handshakes_rejected += 1;
                on_event(
                    resume.session_id,
                    KyuEvent::Fault {
                        code: KyuErrorCode::SessionLimit,
                        message: "Per-source session limit reached; rejecting resume".to_string(),
                        session_id: Some(resume.session_id),
                        stream_id: None,
                        trace_id: None,
                    },
                );
                return;
            }
        }

        let Ok(session_keys) = self.handshake_engine.derive_resumption_session_keys(
            validated_ticket.resumption_secret,
            HandshakeRole::Server,
            resume.session_id,
            resume.client_nonce,
        ) else {
            runtime.counters.handshakes_rejected += 1;
            on_event(
                resume.session_id,
                KyuEvent::Fault {
                    code: KyuErrorCode::Internal,
                    message: "Failed to derive resumption session keys".to_string(),
                    session_id: Some(resume.session_id),
                    stream_id: None,
                    trace_id: None,
                },
            );
            return;
        };

        runtime.register_known_client(
            validated_ticket.client_id,
            validated_ticket.expires_at,
            now_secs,
        );

        if let Some(previous) = runtime.sessions.remove(&resume.session_id) {
            runtime.total_decoder_memory_bytes = runtime
                .total_decoder_memory_bytes
                .saturating_sub(previous.decoder_memory_bytes);
        }

        runtime.sessions.insert(
            resume.session_id,
            SessionState {
                source_ip: src.ip(),
                keys: session_keys,
                pipeline: KyuPipeline::new_with_config(
                    &session_keys.payload_rx,
                    self.transport.pipeline,
                ),
                streams: HashMap::new(),
                decoder_memory_bytes: 0,
                last_active: Instant::now(),
            },
        );
        runtime.counters.handshakes_accepted += 1;
        on_event(resume.session_id, KyuEvent::HandshakeComplete);
    }

    fn handle_stream_fin_packet<F>(
        &self,
        runtime: &mut ReceiverRuntime,
        packet: &[u8],
        src: SocketAddr,
        on_event: &F,
    ) where
        F: Fn(u64, KyuEvent),
    {
        let Ok(fin) = bincode::deserialize::<StreamFinPacket>(&packet[1..]) else {
            runtime.counters.packets_malformed += 1;
            return;
        };

        let Some(session) = runtime.sessions.get_mut(&fin.session_id) else {
            runtime.counters.packets_rejected += 1;
            return;
        };
        if session.source_ip != src.ip() {
            runtime.counters.packets_rejected += 1;
            return;
        }

        let (complete_stream, complete_path, complete_trace) =
            if let Some(stream) = session.streams.get_mut(&fin.stream_id) {
                stream.fin_received = true;
                stream.final_bytes = Some(fin.final_bytes);
                stream.final_frames = Some(fin.final_frames);
                let mut complete_stream = false;
                let mut complete_path: Option<PathBuf> = None;
                if stream.bytes_received >= fin.final_bytes {
                    complete_stream = true;
                    if let Some(file_state) = stream.file_state.as_ref() {
                        complete_path = Some(file_state.path.clone());
                    }
                }
                (complete_stream, complete_path, stream.trace_id)
            } else {
                runtime.counters.packets_rejected += 1;
                return;
            };

        if complete_stream {
            if let Some(path) = complete_path {
                on_event(
                    fin.session_id,
                    KyuEvent::TransferComplete {
                        stream_id: fin.stream_id,
                        trace_id: complete_trace,
                        path: path.clone(),
                    },
                );
            }

            let mut ack = vec![TYPE_ACK];
            ack.extend_from_slice(&fin.session_id.to_le_bytes());
            ack.extend_from_slice(&fin.stream_id.to_le_bytes());
            let _ = self.socket.send_to(&ack, src);

            if let Some(removed) = session.streams.remove(&fin.stream_id)
                && let Some(decoder_state) = removed.decoder_state
            {
                session.decoder_memory_bytes = session
                    .decoder_memory_bytes
                    .saturating_sub(decoder_state.allocated_bytes);
                runtime.total_decoder_memory_bytes = runtime
                    .total_decoder_memory_bytes
                    .saturating_sub(decoder_state.allocated_bytes);
            }
        }
    }

    fn handle_stream_fin_packet_frames<S, F>(
        &self,
        runtime: &mut ReceiverRuntime,
        packet: &[u8],
        src: SocketAddr,
        sink: &mut S,
        on_event: &F,
    ) where
        S: FrameSink,
        F: Fn(u64, KyuEvent),
    {
        let Ok(fin) = bincode::deserialize::<StreamFinPacket>(&packet[1..]) else {
            runtime.counters.packets_malformed += 1;
            return;
        };

        let Some(session) = runtime.sessions.get_mut(&fin.session_id) else {
            runtime.counters.packets_rejected += 1;
            return;
        };
        if session.source_ip != src.ip() {
            runtime.counters.packets_rejected += 1;
            return;
        }

        let Some(stream) = session.streams.get_mut(&fin.stream_id) else {
            runtime.counters.packets_rejected += 1;
            return;
        };
        stream.fin_received = true;
        stream.final_bytes = Some(fin.final_bytes);
        stream.final_frames = Some(fin.final_frames);

        if stream.bytes_received < fin.final_bytes {
            return;
        }

        sink.on_stream_end(
            fin.session_id,
            fin.stream_id,
            stream.trace_id,
            fin.final_bytes,
            fin.final_frames,
        );
        on_event(
            fin.session_id,
            KyuEvent::Metric {
                name: "receiver.stream.completed",
                value: 1,
                session_id: Some(fin.session_id),
                stream_id: Some(fin.stream_id),
                trace_id: Some(stream.trace_id),
            },
        );

        let mut ack = vec![TYPE_ACK];
        ack.extend_from_slice(&fin.session_id.to_le_bytes());
        ack.extend_from_slice(&fin.stream_id.to_le_bytes());
        let _ = self.socket.send_to(&ack, src);

        if let Some(removed) = session.streams.remove(&fin.stream_id)
            && let Some(decoder_state) = removed.decoder_state
        {
            session.decoder_memory_bytes = session
                .decoder_memory_bytes
                .saturating_sub(decoder_state.allocated_bytes);
            runtime.total_decoder_memory_bytes = runtime
                .total_decoder_memory_bytes
                .saturating_sub(decoder_state.allocated_bytes);
        }
    }

    fn handle_ping_packet(&self, runtime: &mut ReceiverRuntime, packet: &[u8], src: SocketAddr) {
        let Some(session_id) = packet.get(1..9).and_then(parse_u64_le) else {
            runtime.counters.packets_malformed += 1;
            return;
        };
        let Some(session) = runtime.sessions.get_mut(&session_id) else {
            runtime.counters.packets_rejected += 1;
            return;
        };

        session.last_active = Instant::now();
        let mut pong = vec![TYPE_PONG];
        pong.extend_from_slice(&session_id.to_le_bytes());
        let _ = self.socket.send_to(&pong, src);
    }

    fn handle_data_packet<F>(
        &self,
        runtime: &mut ReceiverRuntime,
        packet: &[u8],
        src: SocketAddr,
        on_event: &F,
    ) where
        F: Fn(u64, KyuEvent),
    {
        if packet.len() < DATA_PREFIX_SIZE {
            runtime.counters.packets_malformed += 1;
            return;
        }

        let Some(session_id) = packet.get(1..9).and_then(parse_u64_le) else {
            runtime.counters.packets_malformed += 1;
            return;
        };
        let Some(session) = runtime.sessions.get_mut(&session_id) else {
            runtime.counters.packets_rejected += 1;
            return;
        };

        session.last_active = Instant::now();

        let Some(masked_header) = packet.get(9..DATA_PREFIX_SIZE) else {
            runtime.counters.packets_malformed += 1;
            return;
        };
        let Some(payload_with_padding) = packet.get(DATA_PREFIX_SIZE..) else {
            runtime.counters.packets_malformed += 1;
            return;
        };
        if payload_with_padding.is_empty() {
            runtime.counters.packets_malformed += 1;
            return;
        }

        let mask = generate_header_mask(&session.keys.header_rx, payload_with_padding);
        let mut plain_header = [0u8; GEOMETRY_HEADER_SIZE];
        for index in 0..GEOMETRY_HEADER_SIZE {
            plain_header[index] = masked_header[index] ^ mask[index];
        }

        let stream_id = parse_header_u32(&plain_header, 0);
        let block_id = parse_header_u64(&plain_header, 4);
        let seq_id = parse_header_u32(&plain_header, 12);
        let total_size = parse_header_u32(&plain_header, 16);
        let Some(pkt_size) = parse_u16_le(&plain_header[20..22]) else {
            runtime.counters.packets_malformed += 1;
            return;
        };

        if total_size == 0 || total_size > MAX_PROTECTED_BLOCK_SIZE {
            runtime.counters.packets_rejected += 1;
            return;
        }
        if pkt_size == 0 || usize::from(pkt_size) > TARGET_PACKET_SIZE {
            runtime.counters.packets_rejected += 1;
            return;
        }

        let payload_len = usize::from(pkt_size).min(payload_with_padding.len());
        if payload_len == 0 {
            runtime.counters.packets_malformed += 1;
            return;
        }
        let payload = &payload_with_padding[..payload_len];

        if !session.streams.contains_key(&stream_id)
            && session.streams.len() >= MAX_STREAMS_PER_SESSION
        {
            runtime.counters.stream_limit_rejected += 1;
            on_event(
                session_id,
                KyuEvent::Fault {
                    code: KyuErrorCode::StreamLimit,
                    message: "Stream limit reached; dropping packet".to_string(),
                    session_id: Some(session_id),
                    stream_id: Some(stream_id),
                    trace_id: None,
                },
            );
            return;
        }

        let mut should_remove_stream = false;
        let mut completed_path: Option<PathBuf> = None;
        let mut completed_trace_id: Option<u64> = None;

        {
            let stream = session
                .streams
                .entry(stream_id)
                .or_insert_with(|| StreamState {
                    file_state: None,
                    decoder_state: None,
                    manifest: None,
                    expected_size: None,
                    trace_id: 0,
                    final_bytes: None,
                    final_frames: None,
                    fin_received: false,
                    frames_received: 0,
                    bytes_received: 0,
                    next_block_id: 0,
                });

            if block_id != stream.next_block_id {
                runtime.counters.packets_rejected += 1;
                return;
            }

            if stream
                .decoder_state
                .as_ref()
                .is_some_and(|state| state.block_id != block_id)
                && let Some(state) = stream.decoder_state.take()
            {
                session.decoder_memory_bytes = session
                    .decoder_memory_bytes
                    .saturating_sub(state.allocated_bytes);
                runtime.total_decoder_memory_bytes = runtime
                    .total_decoder_memory_bytes
                    .saturating_sub(state.allocated_bytes);
            }

            if stream.decoder_state.is_none() {
                let needed_bytes = u64::from(total_size);
                let would_exceed_session =
                    session.decoder_memory_bytes + needed_bytes > MAX_SESSION_DECODER_MEMORY_BYTES;
                let would_exceed_global = runtime.total_decoder_memory_bytes + needed_bytes
                    > MAX_TOTAL_DECODER_MEMORY_BYTES;

                if would_exceed_session || would_exceed_global {
                    runtime.counters.decoder_memory_rejected += 1;
                    on_event(
                        session_id,
                        KyuEvent::Fault {
                            code: KyuErrorCode::DecoderMemoryLimit,
                            message: "Decoder memory budget exceeded; dropping packet".to_string(),
                            session_id: Some(session_id),
                            stream_id: Some(stream_id),
                            trace_id: stream.file_state.as_ref().map(|state| state.trace_id),
                        },
                    );
                    return;
                }

                let Ok(decoder) = WirehairDecoder::new(total_size as u64, u32::from(pkt_size))
                else {
                    runtime.counters.packets_rejected += 1;
                    return;
                };

                stream.decoder_state = Some(DecoderState {
                    block_id,
                    allocated_bytes: needed_bytes,
                    decoder,
                });
                session.decoder_memory_bytes += needed_bytes;
                runtime.total_decoder_memory_bytes += needed_bytes;
            }

            let mut recovered: Option<Vec<u8>> = None;
            let mut decode_failed = false;
            let mut decode_complete = false;
            let mut used_packets: Option<u32> = None;
            let ideal_packets = total_size.div_ceil(u32::from(pkt_size));
            if let Some(decoder_state) = stream.decoder_state.as_mut() {
                match decoder_state.decoder.decode(seq_id, payload) {
                    Ok(true) => {
                        if let Ok(protected) = decoder_state.decoder.recover() {
                            recovered = Some(protected);
                        }
                        decode_complete = true;
                        used_packets = Some(seq_id.saturating_add(1));
                    }
                    Ok(false) => {}
                    Err(_) => {
                        decode_failed = true;
                    }
                }
            }

            if (decode_complete || decode_failed)
                && let Some(state) = stream.decoder_state.take()
            {
                session.decoder_memory_bytes = session
                    .decoder_memory_bytes
                    .saturating_sub(state.allocated_bytes);
                runtime.total_decoder_memory_bytes = runtime
                    .total_decoder_memory_bytes
                    .saturating_sub(state.allocated_bytes);
            }

            if decode_failed {
                runtime.counters.packets_rejected += 1;
                return;
            }

            if let Some(used_packets) = used_packets {
                let feedback = FecFeedbackPacket {
                    session_id,
                    stream_id,
                    block_id,
                    ideal_packets,
                    used_packets,
                };
                if let Ok(serialized) = bincode::serialize(&feedback) {
                    let mut control = vec![TYPE_FEC_FEEDBACK];
                    control.extend(serialized);
                    let _ = self.socket.send_to(&control, src);
                }
            }

            let Some(protected) = recovered else {
                return;
            };
            let Ok(raw) = session
                .pipeline
                .restore_block(&protected, stream_id, block_id)
            else {
                runtime.counters.packets_rejected += 1;
                return;
            };

            if block_id == 0 {
                if stream.file_state.is_none() {
                    let Some(meta) = SessionManifest::from_bytes(&raw) else {
                        runtime.counters.packets_malformed += 1;
                        return;
                    };
                    stream.trace_id = meta.trace_id;
                    stream.expected_size = meta.expected_size();
                    stream.manifest = Some(meta.clone());

                    let Some(safe_name) = Path::new(&meta.filename).file_name() else {
                        runtime.counters.packets_rejected += 1;
                        on_event(
                            session_id,
                            KyuEvent::Fault {
                                code: KyuErrorCode::PacketRejected,
                                message: "Manifest file name is invalid".to_string(),
                                session_id: Some(session_id),
                                stream_id: Some(stream_id),
                                trace_id: Some(meta.trace_id),
                            },
                        );
                        return;
                    };

                    let path = self.out_dir.join(safe_name);
                    match File::create(&path) {
                        Ok(file) => {
                            stream.file_state = Some(FileState {
                                file,
                                total_bytes: meta.expected_size().unwrap_or(0),
                                trace_id: meta.trace_id,
                                path,
                            });
                            let event_size = meta.expected_size().unwrap_or(0);
                            on_event(
                                session_id,
                                KyuEvent::FileDetected {
                                    stream_id,
                                    trace_id: meta.trace_id,
                                    name: meta.filename,
                                    size: event_size,
                                },
                            );
                            stream.next_block_id = 1;
                        }
                        Err(error) => {
                            on_event(
                                session_id,
                                KyuEvent::Fault {
                                    code: KyuErrorCode::Io,
                                    message: format!(
                                        "Failed to create output file for stream {stream_id:x}: {error}"
                                    ),
                                    session_id: Some(session_id),
                                    stream_id: Some(stream_id),
                                    trace_id: Some(meta.trace_id),
                                },
                            );
                        }
                    }
                }
                return;
            }

            if let Some(file_state) = stream.file_state.as_mut() {
                let write_len = if file_state.total_bytes == 0 {
                    raw.len()
                } else {
                    let remaining = file_state.total_bytes.saturating_sub(stream.bytes_received);
                    remaining.min(raw.len() as u64) as usize
                };
                if write_len > 0 && file_state.file.write_all(&raw[..write_len]).is_err() {
                    on_event(
                        session_id,
                        KyuEvent::Fault {
                            code: KyuErrorCode::Io,
                            message: format!("Failed writing stream {stream_id:x} to disk"),
                            session_id: Some(session_id),
                            stream_id: Some(stream_id),
                            trace_id: Some(file_state.trace_id),
                        },
                    );
                    return;
                }

                stream.bytes_received += write_len as u64;
                stream.frames_received = stream.frames_received.saturating_add(1);
                let progress_total = if file_state.total_bytes == 0 {
                    stream.bytes_received
                } else {
                    file_state.total_bytes
                };
                on_event(
                    session_id,
                    KyuEvent::Progress {
                        stream_id,
                        trace_id: file_state.trace_id,
                        current: stream.bytes_received,
                        total: progress_total,
                    },
                );
                stream.next_block_id = stream.next_block_id.saturating_add(1);

                let reached_declared =
                    file_state.total_bytes > 0 && stream.bytes_received >= file_state.total_bytes;
                let reached_fin = stream.final_bytes.is_some_and(|final_bytes| {
                    stream.fin_received && stream.bytes_received >= final_bytes
                });
                if reached_declared || reached_fin {
                    let _ = file_state.file.sync_all();
                    completed_path = Some(file_state.path.clone());
                    completed_trace_id = Some(file_state.trace_id);
                    should_remove_stream = true;
                }
            }
        }

        if let Some(path) = completed_path {
            let trace_id = completed_trace_id.unwrap_or_default();
            on_event(
                session_id,
                KyuEvent::TransferComplete {
                    stream_id,
                    trace_id,
                    path: path.clone(),
                },
            );
            on_event(
                session_id,
                KyuEvent::Metric {
                    name: "receiver.stream.completed",
                    value: 1,
                    session_id: Some(session_id),
                    stream_id: Some(stream_id),
                    trace_id: Some(trace_id),
                },
            );

            let mut ack = vec![TYPE_ACK];
            ack.extend_from_slice(&session_id.to_le_bytes());
            ack.extend_from_slice(&stream_id.to_le_bytes());
            for _ in 0..3 {
                let _ = self.socket.send_to(&ack, src);
            }
        }

        if should_remove_stream
            && let Some(removed) = session.streams.remove(&stream_id)
            && let Some(decoder_state) = removed.decoder_state
        {
            session.decoder_memory_bytes = session
                .decoder_memory_bytes
                .saturating_sub(decoder_state.allocated_bytes);
            runtime.total_decoder_memory_bytes = runtime
                .total_decoder_memory_bytes
                .saturating_sub(decoder_state.allocated_bytes);
        }
    }

    fn handle_data_packet_frames<S, F>(
        &self,
        runtime: &mut ReceiverRuntime,
        packet: &[u8],
        src: SocketAddr,
        sink: &mut S,
        on_event: &F,
    ) where
        S: FrameSink,
        F: Fn(u64, KyuEvent),
    {
        if packet.len() < DATA_PREFIX_SIZE {
            runtime.counters.packets_malformed += 1;
            return;
        }

        let Some(session_id) = packet.get(1..9).and_then(parse_u64_le) else {
            runtime.counters.packets_malformed += 1;
            return;
        };
        let Some(session) = runtime.sessions.get_mut(&session_id) else {
            runtime.counters.packets_rejected += 1;
            return;
        };
        if session.source_ip != src.ip() {
            runtime.counters.packets_rejected += 1;
            return;
        }

        session.last_active = Instant::now();

        let Some(masked_header) = packet.get(9..DATA_PREFIX_SIZE) else {
            runtime.counters.packets_malformed += 1;
            return;
        };
        let Some(payload_with_padding) = packet.get(DATA_PREFIX_SIZE..) else {
            runtime.counters.packets_malformed += 1;
            return;
        };
        if payload_with_padding.is_empty() {
            runtime.counters.packets_malformed += 1;
            return;
        }

        let mask = generate_header_mask(&session.keys.header_rx, payload_with_padding);
        let mut plain_header = [0u8; GEOMETRY_HEADER_SIZE];
        for index in 0..GEOMETRY_HEADER_SIZE {
            plain_header[index] = masked_header[index] ^ mask[index];
        }

        let stream_id = parse_header_u32(&plain_header, 0);
        let block_id = parse_header_u64(&plain_header, 4);
        let seq_id = parse_header_u32(&plain_header, 12);
        let total_size = parse_header_u32(&plain_header, 16);
        let Some(pkt_size) = parse_u16_le(&plain_header[20..22]) else {
            runtime.counters.packets_malformed += 1;
            return;
        };

        if total_size == 0 || total_size > MAX_PROTECTED_BLOCK_SIZE {
            runtime.counters.packets_rejected += 1;
            return;
        }
        if pkt_size == 0 || usize::from(pkt_size) > TARGET_PACKET_SIZE {
            runtime.counters.packets_rejected += 1;
            return;
        }

        let payload_len = usize::from(pkt_size).min(payload_with_padding.len());
        if payload_len == 0 {
            runtime.counters.packets_malformed += 1;
            return;
        }
        let payload = &payload_with_padding[..payload_len];

        if !session.streams.contains_key(&stream_id)
            && session.streams.len() >= MAX_STREAMS_PER_SESSION
        {
            runtime.counters.stream_limit_rejected += 1;
            return;
        }

        let mut completion: Option<(u64, u64, u64)> = None;
        {
            let stream = session
                .streams
                .entry(stream_id)
                .or_insert_with(|| StreamState {
                    file_state: None,
                    decoder_state: None,
                    manifest: None,
                    expected_size: None,
                    trace_id: 0,
                    final_bytes: None,
                    final_frames: None,
                    fin_received: false,
                    frames_received: 0,
                    bytes_received: 0,
                    next_block_id: 0,
                });

            if block_id != stream.next_block_id {
                runtime.counters.packets_rejected += 1;
                return;
            }

            if stream
                .decoder_state
                .as_ref()
                .is_some_and(|state| state.block_id != block_id)
                && let Some(state) = stream.decoder_state.take()
            {
                session.decoder_memory_bytes = session
                    .decoder_memory_bytes
                    .saturating_sub(state.allocated_bytes);
                runtime.total_decoder_memory_bytes = runtime
                    .total_decoder_memory_bytes
                    .saturating_sub(state.allocated_bytes);
            }

            if stream.decoder_state.is_none() {
                let needed_bytes = u64::from(total_size);
                let would_exceed_session =
                    session.decoder_memory_bytes + needed_bytes > MAX_SESSION_DECODER_MEMORY_BYTES;
                let would_exceed_global = runtime.total_decoder_memory_bytes + needed_bytes
                    > MAX_TOTAL_DECODER_MEMORY_BYTES;
                if would_exceed_session || would_exceed_global {
                    runtime.counters.decoder_memory_rejected += 1;
                    return;
                }

                let Ok(decoder) = WirehairDecoder::new(total_size as u64, u32::from(pkt_size))
                else {
                    runtime.counters.packets_rejected += 1;
                    return;
                };
                stream.decoder_state = Some(DecoderState {
                    block_id,
                    allocated_bytes: needed_bytes,
                    decoder,
                });
                session.decoder_memory_bytes += needed_bytes;
                runtime.total_decoder_memory_bytes += needed_bytes;
            }

            let mut recovered: Option<Vec<u8>> = None;
            let mut decode_failed = false;
            let mut used_packets: Option<u32> = None;
            let ideal_packets = total_size.div_ceil(u32::from(pkt_size));
            if let Some(decoder_state) = stream.decoder_state.as_mut() {
                match decoder_state.decoder.decode(seq_id, payload) {
                    Ok(true) => {
                        if let Ok(protected) = decoder_state.decoder.recover() {
                            recovered = Some(protected);
                        }
                        used_packets = Some(seq_id.saturating_add(1));
                    }
                    Ok(false) => {}
                    Err(_) => {
                        decode_failed = true;
                    }
                }
            }

            if (recovered.is_some() || decode_failed)
                && let Some(state) = stream.decoder_state.take()
            {
                session.decoder_memory_bytes = session
                    .decoder_memory_bytes
                    .saturating_sub(state.allocated_bytes);
                runtime.total_decoder_memory_bytes = runtime
                    .total_decoder_memory_bytes
                    .saturating_sub(state.allocated_bytes);
            }

            if decode_failed {
                runtime.counters.packets_rejected += 1;
                return;
            }
            if let Some(used_packets) = used_packets {
                let feedback = FecFeedbackPacket {
                    session_id,
                    stream_id,
                    block_id,
                    ideal_packets,
                    used_packets,
                };
                if let Ok(serialized) = bincode::serialize(&feedback) {
                    let mut control = vec![TYPE_FEC_FEEDBACK];
                    control.extend(serialized);
                    let _ = self.socket.send_to(&control, src);
                }
            }

            let Some(protected) = recovered else {
                return;
            };
            let Ok(raw) = session
                .pipeline
                .restore_block(&protected, stream_id, block_id)
            else {
                runtime.counters.packets_rejected += 1;
                return;
            };

            if block_id == 0 {
                let Some(meta) = SessionManifest::from_bytes(&raw) else {
                    runtime.counters.packets_malformed += 1;
                    return;
                };
                stream.trace_id = meta.trace_id;
                stream.expected_size = meta.expected_size();
                stream.manifest = Some(meta.clone());
                sink.on_manifest(session_id, stream_id, &meta);
                let event_size = meta.expected_size().unwrap_or(0);
                on_event(
                    session_id,
                    KyuEvent::FileDetected {
                        stream_id,
                        trace_id: meta.trace_id,
                        name: meta.filename,
                        size: event_size,
                    },
                );
                stream.next_block_id = 1;
                return;
            }

            let manifest_semantics = stream
                .manifest
                .as_ref()
                .map(|manifest| manifest.semantics)
                .unwrap_or(StreamSemantics::MediaFrames);
            let frame = if manifest_semantics == StreamSemantics::MediaFrames {
                match bincode::deserialize::<FrameEnvelope>(&raw) {
                    Ok(envelope) => InboundFrame {
                        session_id,
                        stream_id,
                        trace_id: stream.trace_id,
                        block_id,
                        timestamp_us: envelope.timestamp_us,
                        keyframe: envelope.keyframe,
                        payload: envelope.payload,
                    },
                    Err(_) => {
                        runtime.counters.packets_malformed += 1;
                        return;
                    }
                }
            } else {
                InboundFrame {
                    session_id,
                    stream_id,
                    trace_id: stream.trace_id,
                    block_id,
                    timestamp_us: 0,
                    keyframe: false,
                    payload: raw,
                }
            };

            let frame_payload_len = frame.payload.len() as u64;
            if sink.on_frame(frame).is_err() {
                runtime.counters.packets_rejected += 1;
                return;
            }

            stream.bytes_received = stream.bytes_received.saturating_add(frame_payload_len);
            stream.frames_received = stream.frames_received.saturating_add(1);
            stream.next_block_id = stream.next_block_id.saturating_add(1);

            on_event(
                session_id,
                KyuEvent::Progress {
                    stream_id,
                    trace_id: stream.trace_id,
                    current: stream.bytes_received,
                    total: stream.expected_size.unwrap_or(stream.bytes_received),
                },
            );

            let expected_done = stream
                .expected_size
                .is_some_and(|expected| stream.bytes_received >= expected);
            let fin_done = stream.final_bytes.is_some_and(|final_bytes| {
                stream.fin_received && stream.bytes_received >= final_bytes
            });
            if expected_done || fin_done {
                completion = Some((
                    stream.trace_id,
                    stream.final_bytes.unwrap_or(stream.bytes_received),
                    stream.final_frames.unwrap_or(stream.frames_received),
                ));
            }
        }

        if let Some((completed_trace_id, final_bytes, final_frames)) = completion {
            sink.on_stream_end(
                session_id,
                stream_id,
                completed_trace_id,
                final_bytes,
                final_frames,
            );
            on_event(
                session_id,
                KyuEvent::Metric {
                    name: "receiver.stream.completed",
                    value: 1,
                    session_id: Some(session_id),
                    stream_id: Some(stream_id),
                    trace_id: Some(completed_trace_id),
                },
            );

            let mut ack = vec![TYPE_ACK];
            ack.extend_from_slice(&session_id.to_le_bytes());
            ack.extend_from_slice(&stream_id.to_le_bytes());
            let _ = self.socket.send_to(&ack, src);

            if let Some(removed) = session.streams.remove(&stream_id)
                && let Some(decoder_state) = removed.decoder_state
            {
                session.decoder_memory_bytes = session
                    .decoder_memory_bytes
                    .saturating_sub(decoder_state.allocated_bytes);
                runtime.total_decoder_memory_bytes = runtime
                    .total_decoder_memory_bytes
                    .saturating_sub(decoder_state.allocated_bytes);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        KyuErrorCode, KyuEvent, KyuReceiver, ReceiverRuntime, SOURCE_RATE_LIMIT_BURST,
        SOURCE_RATE_LIMIT_PACKETS_PER_SEC, SourceRateLimiter, TYPE_RESUME, parse_psk_hex,
    };
    use crate::handshake::{ResumePacket, issue_session_ticket};
    use rand::RngExt;
    use std::fs;
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kyu2-{label}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).expect("temp dir should be created");
        dir
    }

    #[test]
    fn parse_psk_hex_accepts_32_byte_value() {
        let parsed =
            parse_psk_hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
                .expect("valid 32-byte hex should parse");
        assert_eq!(parsed[0], 0x00);
        assert_eq!(parsed[31], 0xFF);
    }

    #[test]
    fn parse_psk_hex_rejects_wrong_length() {
        let result = parse_psk_hex("abcd");
        assert!(result.is_err());
    }

    #[test]
    fn source_limiter_enforces_burst_budget() {
        let mut limiter = SourceRateLimiter::default();
        let source_ip: std::net::IpAddr = "127.0.0.1".parse().expect("ip should parse");
        let now = Instant::now();

        let mut allowed = 0usize;
        for _ in 0..(SOURCE_RATE_LIMIT_BURST as usize + 1000) {
            if limiter.allow(source_ip, now) {
                allowed += 1;
            }
        }

        assert!(allowed <= SOURCE_RATE_LIMIT_BURST as usize);
    }

    #[test]
    fn malformed_packets_do_not_panic() {
        let out_dir = temp_dir("malformed-packets");
        let receiver = match KyuReceiver::new_with_psk("127.0.0.1:0", &out_dir, [0x11; 32]) {
            Ok(receiver) => receiver,
            Err(error) if error.to_string().contains("Operation not permitted") => return,
            Err(error) => panic!("receiver should be created: {error}"),
        };

        let mut runtime = ReceiverRuntime::new();
        let src: SocketAddr = "127.0.0.1:34567".parse().expect("socket addr should parse");
        let mut rng = rand::rng();

        for _ in 0..5000 {
            let len = rng.random_range(1..1800);
            let mut packet = vec![0u8; len];
            rng.fill(packet.as_mut_slice());

            match packet[0] {
                b'H' => receiver.handle_handshake_packet(&mut runtime, &packet, src, &|_, _| {}),
                b'R' => receiver.handle_resume_packet(&mut runtime, &packet, src, &|_, _| {}),
                b'D' => receiver.handle_data_packet(&mut runtime, &packet, src, &|_, _| {}),
                b'P' => receiver.handle_ping_packet(&mut runtime, &packet, src),
                _ => {}
            }
        }

        receiver.sweep_runtime(&mut runtime, &|_, event| {
            if let KyuEvent::Fault { .. } = event {}
        });
    }

    #[test]
    fn replayed_resume_packet_is_rejected() {
        let out_dir = temp_dir("resume-replay");
        let psk = [0x42; 32];
        let ticket_key = [0x24; 32];
        let receiver = match KyuReceiver::new_with_psk_and_ticket_key(
            "127.0.0.1:0",
            &out_dir,
            psk,
            ticket_key,
        ) {
            Ok(receiver) => receiver,
            Err(error) if error.to_string().contains("Operation not permitted") => return,
            Err(error) => panic!("receiver should be created: {error}"),
        };

        let ticket = issue_session_ticket(&ticket_key, 60).expect("ticket should be issued");
        let resume = ResumePacket::new_client(0xDEAD_BEEF, &ticket);
        let mut wire_packet = vec![TYPE_RESUME];
        wire_packet
            .extend(bincode::serialize(&resume).expect("resume packet should serialize for test"));

        let src: SocketAddr = "127.0.0.1:34568".parse().expect("socket addr should parse");
        let mut runtime = ReceiverRuntime::new();
        let events = std::cell::RefCell::new(Vec::new());

        receiver.handle_resume_packet(&mut runtime, &wire_packet, src, &|_, event| {
            events.borrow_mut().push(event);
        });
        receiver.handle_resume_packet(&mut runtime, &wire_packet, src, &|_, event| {
            events.borrow_mut().push(event);
        });

        assert_eq!(runtime.counters.handshakes_accepted, 1);
        assert_eq!(runtime.counters.handshakes_rejected, 1);
        assert_eq!(runtime.counters.resume_replay_rejected, 1);

        let has_replay_fault = events.borrow().iter().any(|event| match event {
            KyuEvent::Fault { code, message, .. } => {
                *code == KyuErrorCode::HandshakeAuth && message.contains("replayed")
            }
            _ => false,
        });
        assert!(has_replay_fault, "expected replay rejection fault event");
    }

    #[test]
    fn replay_nonce_entry_expires_and_can_be_reused() {
        let mut runtime = ReceiverRuntime::new();
        let ticket_id = [0xAA; 16];
        let nonce = [0xBB; 24];
        let now_secs = 1_000;

        assert!(runtime.register_resume_nonce(ticket_id, nonce, now_secs + 1, now_secs));
        assert!(!runtime.register_resume_nonce(ticket_id, nonce, now_secs + 1, now_secs));

        let expiry_with_skew = now_secs + 1 + super::RESUME_REPLAY_SKEW_SECS;
        assert!(runtime.register_resume_nonce(
            ticket_id,
            nonce,
            now_secs + 10,
            expiry_with_skew + 1
        ));
    }

    #[test]
    fn source_limiter_refills_after_elapsed_time() {
        let mut limiter = SourceRateLimiter::default();
        let source_ip: std::net::IpAddr = "127.0.0.1".parse().expect("ip should parse");
        let now = Instant::now();

        for _ in 0..(SOURCE_RATE_LIMIT_BURST as usize) {
            assert!(limiter.allow(source_ip, now));
        }
        assert!(!limiter.allow(source_ip, now));

        let refill_time = now + Duration::from_secs(1);
        let expected_refill = SOURCE_RATE_LIMIT_PACKETS_PER_SEC as usize;
        let mut refilled = 0usize;
        for _ in 0..expected_refill {
            if limiter.allow(source_ip, refill_time) {
                refilled += 1;
            }
        }
        assert!(refilled > 0);
    }
}
