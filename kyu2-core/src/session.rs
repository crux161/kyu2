use crate::handshake::derive_session_keys;
use crate::{
    HandshakeContext, HandshakePacket, HandshakeRole, KeyExchange, KyuPipeline, PROTOCOL_VERSION,
    SessionKeys, SessionManifest, WirehairDecoder, WirehairEncoder,
};
use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, generic_array::GenericArray},
};
use std::collections::HashMap;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

/// Transfer block size for file chunking before encryption/FEC.
const BLOCK_SIZE: usize = 1024 * 64;
/// Fixed UDP packet size for traffic-shape consistency.
pub const CONSTANT_UDP_SIZE: usize = 1200;
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

const TYPE_DATA: u8 = b'D';
const TYPE_HANDSHAKE: u8 = b'H';
const TYPE_ACK: u8 = b'A';
const TYPE_PING: u8 = b'P';
const TYPE_PONG: u8 = b'O';

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
    finished: bool,
}

pub struct KyuSender {
    socket: UdpSocket,
    psk: [u8; 32],
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
        crate::init();
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(dest)?;
        socket.set_nonblocking(true)?;

        let seed = rand::random::<u32>().max(1);
        Ok(Self {
            socket,
            psk,
            session_id: None,
            session_keys: None,
            next_stream_id: seed,
        })
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

        let mut pipeline = KyuPipeline::new(&session_keys.payload_tx);
        let mut pacer = Pacer::new(max_bytes_per_sec);

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
                &tx_context,
                &manifest_bytes,
                0,
                manifest_redundancy,
                &mut pacer,
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
                finished: false,
            });
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

                let continue_transfer = self.send_chunk(
                    &mut pipeline,
                    &tx_context,
                    &stream.buffer[..bytes_read],
                    stream.next_block_id,
                    redundancy,
                    &mut pacer,
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

    /// Performs a PSK-authenticated handshake and derives directional session keys.
    fn perform_handshake(&self) -> Result<(u64, SessionKeys)> {
        self.socket.set_nonblocking(false)?;
        self.socket.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;

        let handshake_result = (|| -> Result<(u64, SessionKeys)> {
            let my_keys = KeyExchange::new();
            let my_public = *my_keys.public.as_bytes();
            let session_id = rand::random::<u64>();

            let hello = HandshakePacket::new_client(session_id, my_public, &self.psk);
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
                if !server_hello.verify_server(&self.psk, my_public) {
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
                let keys =
                    derive_session_keys(shared_secret, &self.psk, HandshakeRole::Client, &context)?;
                return Ok((session_id, keys));
            }

            bail!("Handshake timed out or authentication failed")
        })();

        self.socket.set_nonblocking(true)?;
        self.socket.set_read_timeout(None)?;
        handshake_result
    }

    /// Returns false if the receiver ACKed completion and requested early stop.
    fn send_chunk(
        &self,
        pipeline: &mut KyuPipeline,
        context: &TxPacketContext,
        data: &[u8],
        block_id: u64,
        redundancy: f32,
        pacer: &mut Pacer,
    ) -> Result<bool> {
        let protected = pipeline.protect_block(data, context.stream_id, block_id)?;
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
        let bounded_redundancy = redundancy.clamp(1.0, MAX_REDUNDANCY);
        let total_packets = ((needed_packets as f32) * bounded_redundancy).ceil() as u32;

        let mut ack_buf = [0u8; 32];
        for seq_id in 0..total_packets {
            if let Ok((amt, _)) = self.socket.recv_from(&mut ack_buf)
                && amt == ACK_PACKET_SIZE
                && ack_buf[0] == TYPE_ACK
            {
                let ack_session = ack_buf.get(1..9).and_then(parse_u64_le);
                let ack_stream = ack_buf.get(9..13).and_then(parse_u32_le);
                if ack_session == Some(context.session_id) && ack_stream == Some(context.stream_id)
                {
                    return Ok(false);
                }
            }

            let packet_data = encoder
                .encode(seq_id)
                .map_err(|error| anyhow::anyhow!("{error:?}"))?;

            let mut plain_header = [0u8; GEOMETRY_HEADER_SIZE];
            plain_header[0..4].copy_from_slice(&context.stream_id.to_le_bytes());
            plain_header[4..12].copy_from_slice(&block_id.to_le_bytes());
            plain_header[12..16].copy_from_slice(&seq_id.to_le_bytes());
            plain_header[16..20].copy_from_slice(&total_size.to_le_bytes());
            plain_header[20..22].copy_from_slice(&(pkt_size as u16).to_le_bytes());

            let mask = generate_header_mask(&context.header_key, &packet_data);
            for index in 0..GEOMETRY_HEADER_SIZE {
                plain_header[index] ^= mask[index];
            }

            let mut wire_packet = Vec::with_capacity(CONSTANT_UDP_SIZE);
            wire_packet.push(TYPE_DATA);
            wire_packet.extend_from_slice(&context.session_id.to_le_bytes());
            wire_packet.extend_from_slice(&plain_header);
            wire_packet.extend_from_slice(&packet_data);
            if wire_packet.len() < CONSTANT_UDP_SIZE {
                wire_packet.resize(CONSTANT_UDP_SIZE, 0u8);
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

        on_metric_sender(context, data.len() as u64);
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
    stream_limit_rejected: u64,
    decoder_memory_rejected: u64,
}

/// Mutable receiver runtime state maintained between loop iterations.
#[derive(Default)]
struct ReceiverRuntime {
    sessions: HashMap<u64, SessionState>,
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
}

pub struct KyuReceiver {
    socket: UdpSocket,
    out_dir: PathBuf,
    psk: [u8; 32],
}

impl KyuReceiver {
    pub fn new(bind_addr: &str, out_dir: &Path) -> Result<Self> {
        let psk = load_psk_from_env()?;
        Self::new_with_psk(bind_addr, out_dir, psk)
    }

    /// Creates a receiver with an explicit PSK instead of environment loading.
    pub fn new_with_psk(bind_addr: &str, out_dir: &Path, psk: [u8; 32]) -> Result<Self> {
        crate::init();
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;

        Ok(Self {
            socket,
            out_dir: out_dir.to_path_buf(),
            psk,
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
                        TYPE_PING => self.handle_ping_packet(&mut runtime, packet, src),
                        TYPE_DATA => self.handle_data_packet(&mut runtime, packet, src, &on_event),
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

        if !client_hello.verify_client(&self.psk) {
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
        let reply = HandshakePacket::new_server(
            client_hello.session_id,
            server_public,
            client_hello.public_key,
            &self.psk,
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

        let Ok(session_keys) =
            derive_session_keys(shared_secret, &self.psk, HandshakeRole::Server, &context)
        else {
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
                pipeline: KyuPipeline::new(&session_keys.payload_rx),
                streams: HashMap::new(),
                decoder_memory_bytes: 0,
                last_active: Instant::now(),
            },
        );
        runtime.counters.handshakes_accepted += 1;
        on_event(client_hello.session_id, KyuEvent::HandshakeComplete);
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
            if let Some(decoder_state) = stream.decoder_state.as_mut() {
                match decoder_state.decoder.decode(seq_id, payload) {
                    Ok(true) => {
                        if let Ok(protected) = decoder_state.decoder.recover() {
                            recovered = Some(protected);
                        }
                        decode_complete = true;
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
                                total_bytes: meta.file_size,
                                trace_id: meta.trace_id,
                                path,
                            });
                            on_event(
                                session_id,
                                KyuEvent::FileDetected {
                                    stream_id,
                                    trace_id: meta.trace_id,
                                    name: meta.filename,
                                    size: meta.file_size,
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
                let remaining = file_state.total_bytes.saturating_sub(stream.bytes_received);
                let write_len = remaining.min(raw.len() as u64) as usize;
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
                on_event(
                    session_id,
                    KyuEvent::Progress {
                        stream_id,
                        trace_id: file_state.trace_id,
                        current: stream.bytes_received,
                        total: file_state.total_bytes,
                    },
                );
                stream.next_block_id = stream.next_block_id.saturating_add(1);

                if stream.bytes_received >= file_state.total_bytes {
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
}

#[cfg(test)]
mod tests {
    use super::{
        KyuEvent, KyuReceiver, ReceiverRuntime, SOURCE_RATE_LIMIT_BURST, SourceRateLimiter,
        parse_psk_hex,
    };
    use rand::RngExt;
    use std::fs;
    use std::net::SocketAddr;
    use std::time::Instant;

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
                b'D' => receiver.handle_data_packet(&mut runtime, &packet, src, &|_, _| {}),
                b'P' => receiver.handle_ping_packet(&mut runtime, &packet, src),
                _ => {}
            }
        }

        receiver.sweep_runtime(&mut runtime, &|_, event| {
            if let KyuEvent::Fault { .. } = event {}
        });
    }
}
