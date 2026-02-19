use crate::handshake::{DefaultHandshakeEngine, HandshakeEngine, ResumePacket, SessionTicket};
use crate::pipeline::{PipelineConfig, SankakuPipeline, VideoPayloadKind};
use crate::{
    HandshakeContext, HandshakePacket, HandshakeRole, KeyExchange, PROTOCOL_VERSION, SessionKeys,
    ValidatedTicket, WirehairDecoder, WirehairEncoder,
};
use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, generic_array::GenericArray},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

const MAX_REDUNDANCY: f32 = 4.0;
const HANDSHAKE_RETRIES: usize = 10;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(500);
const SESSION_TICKET_LIFETIME_SECS: u64 = 6 * 60 * 60;
const MAX_PROTECTED_BLOCK_SIZE: u32 = 512 * 1024;
const MAX_WIRE_PACKET_SIZE: usize = 65_507;
const TARGET_PACKET_SIZE: usize = 1150;
const ADAPTIVE_PADDING_ALIGN: usize = 32;
const GEOMETRY_HEADER_SIZE: usize = 23;
const DATA_PREFIX_SIZE: usize = 1 + 8 + GEOMETRY_HEADER_SIZE;

const TYPE_DATA: u8 = b'D';
const TYPE_HANDSHAKE: u8 = b'H';
const TYPE_RESUME: u8 = b'R';
const TYPE_ACK: u8 = b'A';
const TYPE_PING: u8 = b'P';
const TYPE_PONG: u8 = b'O';
const TYPE_FEC_FEEDBACK: u8 = b'F';
const TYPE_STREAM_FIN: u8 = b'E';
const TYPE_TELEMETRY: u8 = b'T';

/// Stable error taxonomy surfaced by stream APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KyuErrorCode {
    Config,
    Socket,
    HandshakeAuth,
    VersionMismatch,
    PacketMalformed,
    PacketRejected,
    Internal,
}

impl KyuErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Config => "CONFIG",
            Self::Socket => "SOCKET",
            Self::HandshakeAuth => "HANDSHAKE_AUTH",
            Self::VersionMismatch => "VERSION_MISMATCH",
            Self::PacketMalformed => "PACKET_MALFORMED",
            Self::PacketRejected => "PACKET_REJECTED",
            Self::Internal => "INTERNAL",
        }
    }
}

/// Lightweight event stream for embeddings that need observability.
#[derive(Debug, Clone)]
pub enum KyuEvent {
    Log(String),
    HandshakeInitiated,
    HandshakeComplete,
    Progress {
        stream_id: u32,
        frame_index: u64,
        bytes: u64,
        frames: u64,
    },
    Fault {
        code: KyuErrorCode,
        message: String,
        session_id: Option<u64>,
        stream_id: Option<u32>,
    },
}

/// Indicates how the current sender session keys were bootstrapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionBootstrapMode {
    Unknown,
    FullHandshake,
    ZeroRttResume,
}

/// Packet shaping policy for optional obfuscation.
#[derive(Debug, Clone, Copy)]
pub enum PaddingMode {
    Disabled,
    Fixed(usize),
    Adaptive { min: usize, max: usize },
}

impl Default for PaddingMode {
    fn default() -> Self {
        Self::Disabled
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
#[derive(Debug, Clone, Copy)]
pub struct TransportConfig {
    pub pipeline: PipelineConfig,
    pub padding: PaddingMode,
    pub fec: FecPolicy,
    pub initial_redundancy: f32,
    pub max_bytes_per_sec: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            pipeline: PipelineConfig::default(),
            padding: PaddingMode::Disabled,
            fec: FecPolicy::default(),
            initial_redundancy: 1.1,
            max_bytes_per_sec: 20_000_000,
        }
    }
}

/// Outbound frame data accepted by the sender.
#[derive(Debug, Clone)]
pub struct VideoFrame {
    pub timestamp_us: u64,
    pub keyframe: bool,
    pub kind: VideoPayloadKind,
    pub payload: Vec<u8>,
}

impl VideoFrame {
    pub fn nal(payload: Vec<u8>, timestamp_us: u64, keyframe: bool) -> Self {
        Self {
            timestamp_us,
            keyframe,
            kind: VideoPayloadKind::NalUnit,
            payload,
        }
    }

    pub fn sao(payload: Vec<u8>, timestamp_us: u64) -> Self {
        Self {
            timestamp_us,
            keyframe: false,
            kind: VideoPayloadKind::SaoParameters,
            payload,
        }
    }
}

/// Inbound frame data emitted by the receiver.
#[derive(Debug, Clone)]
pub struct InboundVideoFrame {
    pub session_id: u64,
    pub stream_id: u32,
    pub frame_index: u64,
    pub timestamp_us: u64,
    pub keyframe: bool,
    pub kind: VideoPayloadKind,
    pub payload: Vec<u8>,
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
    frame_index: u64,
    ideal_packets: u32,
    used_packets: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct TelemetryPacket {
    session_id: u64,
    stream_id: u32,
    frame_index: u64,
    packet_loss_ppm: u32,
    jitter_us: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct StreamFinPacket {
    session_id: u64,
    stream_id: u32,
    final_bytes: u64,
    final_frames: u64,
}

/// Converts a 64-char hex string into a 32-byte key.
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

fn load_psk_from_env() -> Result<[u8; 32]> {
    let raw = std::env::var("SANKAKU_PSK")
        .or_else(|_| std::env::var("KYU2_PSK"))
        .context("Missing SANKAKU_PSK (or KYU2_PSK) 64-char hex key")?;
    parse_psk_hex(&raw)
}

fn load_ticket_key_from_env_or_psk(psk: [u8; 32]) -> Result<[u8; 32]> {
    let raw = std::env::var("SANKAKU_TICKET_KEY")
        .or_else(|_| std::env::var("KYU2_TICKET_KEY"))
        .ok();
    if let Some(raw) = raw {
        return parse_psk_hex(&raw);
    }
    Ok(psk)
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

fn adjust_redundancy_with_telemetry(
    current: f32,
    telemetry: &TelemetryPacket,
    policy: FecPolicy,
) -> f32 {
    let synthetic = if telemetry.packet_loss_ppm >= 150_000 || telemetry.jitter_us >= 20_000 {
        FecFeedbackPacket {
            session_id: telemetry.session_id,
            stream_id: telemetry.stream_id,
            frame_index: telemetry.frame_index,
            ideal_packets: 100,
            used_packets: 150,
        }
    } else if telemetry.packet_loss_ppm <= 20_000 && telemetry.jitter_us <= 5_000 {
        FecFeedbackPacket {
            session_id: telemetry.session_id,
            stream_id: telemetry.stream_id,
            frame_index: telemetry.frame_index,
            ideal_packets: 100,
            used_packets: 100,
        }
    } else {
        FecFeedbackPacket {
            session_id: telemetry.session_id,
            stream_id: telemetry.stream_id,
            frame_index: telemetry.frame_index,
            ideal_packets: 100,
            used_packets: 110,
        }
    };
    adjust_redundancy(current, &synthetic, policy)
}

/// Generates a dynamic mask for the geometry header.
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

struct Pacer {
    target_bytes_per_sec: u64,
    max_burst_bytes: f64,
    tokens: f64,
    last_refill: Instant,
}

impl Pacer {
    fn new(target_bytes_per_sec: u64) -> Self {
        let max_burst_bytes = ((target_bytes_per_sec as f64) * 0.25).max(16_384.0);
        Self {
            target_bytes_per_sec,
            max_burst_bytes,
            tokens: max_burst_bytes,
            last_refill: Instant::now(),
        }
    }

    async fn pace(&mut self, packet_size: usize, keyframe: bool, jitter_us: u32) {
        if self.target_bytes_per_sec == 0 {
            return;
        }

        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.tokens =
            (self.tokens + elapsed * self.target_bytes_per_sec as f64).min(self.max_burst_bytes);

        let keyframe_budget = if keyframe { 2.5 } else { 1.0 };
        let jitter_penalty = 1.0 + (jitter_us as f64 / 200_000.0);
        let budget = (self.max_burst_bytes * keyframe_budget / jitter_penalty).max(1500.0);
        if self.tokens > budget {
            self.tokens = budget;
        }

        let needed = packet_size as f64;
        if self.tokens < needed {
            let deficit = needed - self.tokens;
            let sleep_secs = deficit / self.target_bytes_per_sec as f64;
            sleep(Duration::from_secs_f64(sleep_secs)).await;

            let now_after = Instant::now();
            let elapsed_after = now_after.duration_since(self.last_refill).as_secs_f64();
            self.last_refill = now_after;
            self.tokens = (self.tokens + elapsed_after * self.target_bytes_per_sec as f64)
                .min(self.max_burst_bytes);
        }

        self.tokens = (self.tokens - needed).max(0.0);
    }
}

#[derive(Debug, Clone, Copy)]
struct TxPacketContext {
    session_id: u64,
    stream_id: u32,
    header_key: [u8; 32],
}

#[derive(Debug, Clone)]
struct SenderStreamState {
    next_frame_index: u64,
    redundancy: f32,
    jitter_us: u32,
    bytes_sent: u64,
    frames_sent: u64,
}

pub struct SankakuSender {
    socket: UdpSocket,
    psk: [u8; 32],
    transport: TransportConfig,
    handshake_engine: Arc<dyn HandshakeEngine>,
    resumption_ticket: Option<SessionTicket>,
    session_id: Option<u64>,
    session_keys: Option<SessionKeys>,
    pipeline: Option<SankakuPipeline>,
    compression_graph: Vec<u8>,
    bootstrap_mode: SessionBootstrapMode,
    next_stream_id: u32,
    streams: HashMap<u32, SenderStreamState>,
    pacer: Pacer,
}

impl SankakuSender {
    pub async fn new(dest: &str) -> Result<Self> {
        let psk = load_psk_from_env()?;
        Self::new_with_psk(dest, psk).await
    }

    pub async fn new_with_psk(dest: &str, psk: [u8; 32]) -> Result<Self> {
        Self::new_with_psk_and_ticket(dest, psk, None).await
    }

    pub async fn new_with_psk_and_ticket(
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
        .await
    }

    pub async fn new_with_psk_and_config(
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
        .await
    }

    pub async fn new_with_psk_ticket_config_and_engine(
        dest: &str,
        psk: [u8; 32],
        ticket: Option<SessionTicket>,
        config: TransportConfig,
        handshake_engine: Arc<dyn HandshakeEngine>,
    ) -> Result<Self> {
        crate::init();

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(dest).await?;
        let seed = rand::random::<u32>().max(1);

        Ok(Self {
            socket,
            psk,
            transport: config,
            handshake_engine,
            resumption_ticket: ticket,
            session_id: None,
            session_keys: None,
            pipeline: None,
            compression_graph: Vec::new(),
            bootstrap_mode: SessionBootstrapMode::Unknown,
            next_stream_id: seed,
            streams: HashMap::new(),
            pacer: Pacer::new(config.max_bytes_per_sec),
        })
    }

    pub fn set_transport_config(&mut self, config: TransportConfig) {
        self.transport = config;
        self.pacer = Pacer::new(config.max_bytes_per_sec);
    }

    pub fn import_resumption_ticket(&mut self, blob: &[u8]) -> Result<()> {
        let ticket = bincode::deserialize::<SessionTicket>(blob)
            .context("Failed to deserialize resumption ticket blob")?;
        self.resumption_ticket = Some(ticket);
        Ok(())
    }

    pub fn export_resumption_ticket(&self) -> Result<Option<Vec<u8>>> {
        let Some(ticket) = &self.resumption_ticket else {
            return Ok(None);
        };
        Ok(Some(
            bincode::serialize(ticket).context("Failed to serialize resumption ticket")?,
        ))
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    pub fn session_id(&self) -> Option<u64> {
        self.session_id
    }

    pub fn bootstrap_mode(&self) -> SessionBootstrapMode {
        self.bootstrap_mode
    }

    pub fn stream_redundancy(&self, stream_id: u32) -> Option<f32> {
        self.streams.get(&stream_id).map(|state| state.redundancy)
    }

    pub fn update_compression_graph(&mut self, serialized_graph: &[u8]) -> Result<()> {
        self.compression_graph.clear();
        self.compression_graph.extend_from_slice(serialized_graph);
        if let Some(pipeline) = self.pipeline.as_mut() {
            pipeline.update_compression_graph(serialized_graph)?;
        }
        Ok(())
    }

    /// Applies external RTCP-style telemetry (for example from app-managed feedback channels).
    pub fn apply_network_telemetry(
        &mut self,
        stream_id: u32,
        packet_loss_ppm: u32,
        jitter_us: u32,
    ) {
        let Some(state) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let telemetry = TelemetryPacket {
            session_id: self.session_id.unwrap_or(0),
            stream_id,
            frame_index: state.next_frame_index,
            packet_loss_ppm,
            jitter_us,
        };
        state.redundancy =
            adjust_redundancy_with_telemetry(state.redundancy, &telemetry, self.transport.fec);
        state.jitter_us = jitter_us;
    }

    pub fn open_stream(&mut self) -> Result<u32> {
        let stream_id = self.next_stream_id;
        self.next_stream_id = self
            .next_stream_id
            .checked_add(1)
            .context("Stream id space exhausted for this sender session")?;
        self.streams.insert(
            stream_id,
            SenderStreamState {
                next_frame_index: 0,
                redundancy: self.transport.initial_redundancy.clamp(1.0, MAX_REDUNDANCY),
                jitter_us: 0,
                bytes_sent: 0,
                frames_sent: 0,
            },
        );
        Ok(stream_id)
    }

    pub async fn send_frame(&mut self, stream_id: u32, frame: VideoFrame) -> Result<u64> {
        self.ensure_handshake().await?;
        if !self.streams.contains_key(&stream_id) {
            self.streams.insert(
                stream_id,
                SenderStreamState {
                    next_frame_index: 0,
                    redundancy: self.transport.initial_redundancy.clamp(1.0, MAX_REDUNDANCY),
                    jitter_us: 0,
                    bytes_sent: 0,
                    frames_sent: 0,
                },
            );
        }

        let frame_index = self
            .streams
            .get(&stream_id)
            .map(|state| state.next_frame_index)
            .unwrap_or(0);

        let envelope = FrameEnvelope {
            timestamp_us: frame.timestamp_us,
            keyframe: frame.keyframe,
            payload: frame.payload,
        };
        let raw = bincode::serialize(&envelope).context("Failed to serialize frame envelope")?;

        let session_id = self
            .session_id
            .context("Sender missing session id after handshake")?;
        let session_keys = self
            .session_keys
            .context("Sender missing session keys after handshake")?;
        let tx_context = TxPacketContext {
            session_id,
            stream_id,
            header_key: session_keys.header_tx,
        };

        let (mut redundancy, mut jitter_us) = {
            let state = self
                .streams
                .get(&stream_id)
                .expect("sender stream state should exist");
            (state.redundancy, state.jitter_us)
        };

        self.send_chunk(
            tx_context,
            &raw,
            frame.kind,
            frame_index,
            frame.keyframe,
            &mut redundancy,
            &mut jitter_us,
        )
        .await?;

        if let Some(state) = self.streams.get_mut(&stream_id) {
            state.redundancy = redundancy.clamp(1.0, MAX_REDUNDANCY);
            state.jitter_us = jitter_us;
            state.bytes_sent = state.bytes_sent.saturating_add(raw.len() as u64);
            state.frames_sent = state.frames_sent.saturating_add(1);
            state.next_frame_index = state.next_frame_index.saturating_add(1);
        }

        Ok(frame_index)
    }

    pub async fn send_stream_fin(
        &self,
        stream_id: u32,
        final_bytes: u64,
        final_frames: u64,
    ) -> Result<()> {
        let session_id = self
            .session_id
            .context("Sender missing session id after handshake")?;
        let fin = StreamFinPacket {
            session_id,
            stream_id,
            final_bytes,
            final_frames,
        };
        let mut packet = vec![TYPE_STREAM_FIN];
        packet.extend(bincode::serialize(&fin)?);
        self.socket.send(&packet).await?;
        Ok(())
    }

    async fn ensure_handshake(&mut self) -> Result<()> {
        if self.session_id.is_some() && self.session_keys.is_some() && self.pipeline.is_some() {
            return Ok(());
        }
        let (session_id, session_keys) = self.perform_handshake().await?;
        let mut pipeline =
            SankakuPipeline::new_with_config(&session_keys.payload_tx, self.transport.pipeline);
        if !self.compression_graph.is_empty() {
            pipeline.update_compression_graph(&self.compression_graph)?;
        }
        self.pipeline = Some(pipeline);
        self.session_id = Some(session_id);
        self.session_keys = Some(session_keys);
        Ok(())
    }

    async fn perform_handshake(&mut self) -> Result<(u64, SessionKeys)> {
        if let Some(ticket) = self.resumption_ticket.clone() {
            match self.perform_resumption_0rtt(&ticket).await {
                Ok(resumed) => {
                    self.bootstrap_mode = SessionBootstrapMode::ZeroRttResume;
                    return Ok(resumed);
                }
                Err(_) => {
                    self.resumption_ticket = None;
                }
            }
        }
        self.bootstrap_mode = SessionBootstrapMode::FullHandshake;
        self.perform_full_handshake().await
    }

    async fn perform_full_handshake(&mut self) -> Result<(u64, SessionKeys)> {
        let my_keys = KeyExchange::new();
        let my_public = *my_keys.public.as_bytes();
        let session_id = rand::random::<u64>();

        let hello = self
            .handshake_engine
            .build_client_hello(session_id, my_public, &self.psk);
        let mut packet = vec![TYPE_HANDSHAKE];
        packet.extend(bincode::serialize(&hello)?);

        let mut buf = [0u8; 4096];
        for _ in 0..HANDSHAKE_RETRIES {
            self.socket.send(&packet).await?;

            let recv = timeout(HANDSHAKE_TIMEOUT, self.socket.recv(&mut buf)).await;
            let Ok(Ok(amt)) = recv else {
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
    }

    async fn perform_resumption_0rtt(&self, ticket: &SessionTicket) -> Result<(u64, SessionKeys)> {
        if ticket.expires_at <= unix_now_secs() {
            bail!("Resumption ticket is expired");
        }

        let session_id = rand::random::<u64>();
        let resume = self
            .handshake_engine
            .build_resume_packet(session_id, ticket);
        let mut packet = vec![TYPE_RESUME];
        packet.extend(bincode::serialize(&resume)?);
        self.socket.send(&packet).await?;

        let keys = self.handshake_engine.derive_resumption_session_keys(
            ticket.resumption_secret,
            HandshakeRole::Client,
            session_id,
            resume.client_nonce,
        )?;
        Ok((session_id, keys))
    }

    async fn send_chunk(
        &mut self,
        context: TxPacketContext,
        data: &[u8],
        kind: VideoPayloadKind,
        frame_index: u64,
        keyframe: bool,
        redundancy: &mut f32,
        jitter_us: &mut u32,
    ) -> Result<()> {
        let protected = self
            .pipeline
            .as_mut()
            .context("Sender pipeline not initialized")?
            .protect_frame(data, kind, context.stream_id, frame_index)?;

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

        for seq_id in 0..total_packets {
            self.drain_control(
                context.session_id,
                context.stream_id,
                frame_index,
                redundancy,
                jitter_us,
            )
            .await?;

            let packet_data = encoder
                .encode(seq_id)
                .map_err(|error| anyhow::anyhow!("{error:?}"))?;

            let mut plain_header = [0u8; GEOMETRY_HEADER_SIZE];
            plain_header[0..4].copy_from_slice(&context.stream_id.to_le_bytes());
            plain_header[4..12].copy_from_slice(&frame_index.to_le_bytes());
            plain_header[12..16].copy_from_slice(&seq_id.to_le_bytes());
            plain_header[16..20].copy_from_slice(&total_size.to_le_bytes());
            plain_header[20..22].copy_from_slice(&(pkt_size as u16).to_le_bytes());
            plain_header[22] = kind.as_header_flag();

            let mask = generate_header_mask(&context.header_key, &packet_data);
            for index in 0..GEOMETRY_HEADER_SIZE {
                plain_header[index] ^= mask[index];
            }

            let mut wire_packet = Vec::with_capacity(DATA_PREFIX_SIZE + packet_data.len() + 64);
            wire_packet.push(TYPE_DATA);
            wire_packet.extend_from_slice(&context.session_id.to_le_bytes());
            wire_packet.extend_from_slice(&plain_header);
            wire_packet.extend_from_slice(&packet_data);

            let target_len = target_packet_len(self.transport.padding, wire_packet.len());
            if wire_packet.len() < target_len {
                wire_packet.resize(target_len, 0u8);
            }

            self.socket.send(&wire_packet).await?;
            self.pacer
                .pace(wire_packet.len(), keyframe, *jitter_us)
                .await;
        }

        Ok(())
    }

    async fn drain_control(
        &self,
        session_id: u64,
        stream_id: u32,
        frame_index: u64,
        redundancy: &mut f32,
        jitter_us: &mut u32,
    ) -> Result<()> {
        let mut control_buf = [0u8; 512];
        loop {
            match self.socket.try_recv(&mut control_buf) {
                Ok(amt) if amt >= 1 => match control_buf[0] {
                    TYPE_FEC_FEEDBACK => {
                        if let Ok(feedback) =
                            bincode::deserialize::<FecFeedbackPacket>(&control_buf[1..amt])
                            && feedback.session_id == session_id
                            && feedback.stream_id == stream_id
                            && feedback.frame_index <= frame_index
                        {
                            *redundancy =
                                adjust_redundancy(*redundancy, &feedback, self.transport.fec);
                        }
                    }
                    TYPE_TELEMETRY => {
                        if let Ok(telemetry) =
                            bincode::deserialize::<TelemetryPacket>(&control_buf[1..amt])
                            && telemetry.session_id == session_id
                            && telemetry.stream_id == stream_id
                            && telemetry.frame_index <= frame_index
                        {
                            *redundancy = adjust_redundancy_with_telemetry(
                                *redundancy,
                                &telemetry,
                                self.transport.fec,
                            );
                            *jitter_us = telemetry.jitter_us;
                        }
                    }
                    TYPE_ACK => {}
                    _ => {}
                },
                Ok(_) => break,
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

struct DecoderState {
    frame_index: u64,
    decoder: WirehairDecoder,
    ideal_packets: u32,
    used_packets: u32,
}

#[derive(Default)]
struct StreamState {
    next_frame_index: u64,
    decoder_state: Option<DecoderState>,
    bytes_received: u64,
    frames_received: u64,
    last_arrival: Option<Instant>,
    last_timestamp_us: Option<u64>,
    jitter_us: u32,
}

struct SessionState {
    source_ip: IpAddr,
    keys: SessionKeys,
    pipeline: SankakuPipeline,
    streams: HashMap<u32, StreamState>,
}

#[derive(Default)]
struct ReceiverRuntime {
    sessions: HashMap<u64, SessionState>,
}

pub struct SankakuReceiver {
    socket: UdpSocket,
    psk: [u8; 32],
    ticket_key: [u8; 32],
    transport: TransportConfig,
    handshake_engine: Arc<dyn HandshakeEngine>,
}

impl SankakuReceiver {
    pub async fn new(bind_addr: &str) -> Result<Self> {
        let psk = load_psk_from_env()?;
        let ticket_key = load_ticket_key_from_env_or_psk(psk)?;
        Self::new_with_psk_and_ticket_key(bind_addr, psk, ticket_key).await
    }

    pub async fn new_with_psk(bind_addr: &str, psk: [u8; 32]) -> Result<Self> {
        Self::new_with_psk_and_ticket_key(bind_addr, psk, psk).await
    }

    pub async fn new_with_psk_and_ticket_key(
        bind_addr: &str,
        psk: [u8; 32],
        ticket_key: [u8; 32],
    ) -> Result<Self> {
        Self::new_with_psk_ticket_key_config_and_engine(
            bind_addr,
            psk,
            ticket_key,
            TransportConfig::default(),
            Arc::new(DefaultHandshakeEngine),
        )
        .await
    }

    pub async fn new_with_psk_ticket_key_and_config(
        bind_addr: &str,
        psk: [u8; 32],
        ticket_key: [u8; 32],
        config: TransportConfig,
    ) -> Result<Self> {
        Self::new_with_psk_ticket_key_config_and_engine(
            bind_addr,
            psk,
            ticket_key,
            config,
            Arc::new(DefaultHandshakeEngine),
        )
        .await
    }

    pub async fn new_with_psk_ticket_key_config_and_engine(
        bind_addr: &str,
        psk: [u8; 32],
        ticket_key: [u8; 32],
        config: TransportConfig,
        handshake_engine: Arc<dyn HandshakeEngine>,
    ) -> Result<Self> {
        crate::init();
        let socket = UdpSocket::bind(bind_addr).await?;
        Ok(Self {
            socket,
            psk,
            ticket_key,
            transport: config,
            handshake_engine,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    pub fn spawn_frame_channel(self) -> mpsc::Receiver<InboundVideoFrame> {
        let (tx, rx) = mpsc::channel(2048);
        thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async move {
                let _ = self.run_frame_loop(tx).await;
            });
        });
        rx
    }

    pub async fn run_frame_loop(self, frame_tx: mpsc::Sender<InboundVideoFrame>) -> Result<()> {
        let mut runtime = ReceiverRuntime::default();
        let mut buf = vec![0u8; MAX_WIRE_PACKET_SIZE];

        loop {
            let (amt, src) = self.socket.recv_from(&mut buf).await?;
            if amt == 0 {
                continue;
            }
            let packet = &buf[..amt];
            match packet[0] {
                TYPE_HANDSHAKE => {
                    self.handle_handshake_packet(&mut runtime, packet, src)
                        .await?;
                }
                TYPE_RESUME => {
                    self.handle_resume_packet(&mut runtime, packet, src).await?;
                }
                TYPE_PING => {
                    self.handle_ping_packet(&mut runtime, packet, src).await?;
                }
                TYPE_STREAM_FIN => {
                    self.handle_stream_fin_packet(&mut runtime, packet, src)
                        .await?;
                }
                TYPE_DATA => {
                    self.handle_data_packet(&mut runtime, packet, src, &frame_tx)
                        .await?;
                }
                _ => {}
            }
        }
    }

    async fn handle_handshake_packet(
        &self,
        runtime: &mut ReceiverRuntime,
        packet: &[u8],
        src: SocketAddr,
    ) -> Result<()> {
        let Ok(client_hello) = bincode::deserialize::<HandshakePacket>(&packet[1..]) else {
            return Ok(());
        };
        if !self
            .handshake_engine
            .verify_client_hello(&client_hello, &self.psk)
        {
            return Ok(());
        }

        let server_keys = KeyExchange::new();
        let server_public = *server_keys.public.as_bytes();
        let session_ticket = self
            .handshake_engine
            .issue_session_ticket(&self.ticket_key, SESSION_TICKET_LIFETIME_SECS)
            .ok();
        let reply = self.handshake_engine.build_server_hello(
            client_hello.session_id,
            server_public,
            client_hello.public_key,
            &self.psk,
            session_ticket,
        );

        let mut response = vec![TYPE_HANDSHAKE];
        response.extend(bincode::serialize(&reply)?);
        self.socket.send_to(&response, src).await?;

        let shared_secret = server_keys.derive_shared_secret(client_hello.public_key);
        let context = HandshakeContext {
            protocol_version: PROTOCOL_VERSION,
            capabilities: client_hello.capabilities,
            session_id: client_hello.session_id,
            client_public: client_hello.public_key,
            server_public,
        };
        let session_keys = self.handshake_engine.derive_session_keys(
            shared_secret,
            &self.psk,
            HandshakeRole::Server,
            &context,
        )?;
        runtime.sessions.insert(
            client_hello.session_id,
            SessionState {
                source_ip: src.ip(),
                keys: session_keys,
                pipeline: SankakuPipeline::new_with_config(
                    &session_keys.payload_rx,
                    self.transport.pipeline,
                ),
                streams: HashMap::new(),
            },
        );
        Ok(())
    }

    async fn handle_resume_packet(
        &self,
        runtime: &mut ReceiverRuntime,
        packet: &[u8],
        src: SocketAddr,
    ) -> Result<()> {
        let Ok(resume) = bincode::deserialize::<ResumePacket>(&packet[1..]) else {
            return Ok(());
        };
        if resume.protocol_version != PROTOCOL_VERSION {
            return Ok(());
        }

        let now_secs = unix_now_secs();
        let Some(validated_ticket) = self.handshake_engine.validate_ticket_identity(
            &self.ticket_key,
            &resume.ticket_identity,
            now_secs,
        ) else {
            return Ok(());
        };

        if validated_ticket.expires_at != resume.expires_at
            || !self.handshake_engine.verify_resume_packet(
                &resume,
                &validated_ticket.resumption_secret,
                now_secs,
            )
        {
            return Ok(());
        }

        self.accept_resumed_session(
            runtime,
            resume.session_id,
            resume.client_nonce,
            src,
            validated_ticket,
        )
        .await
    }

    async fn accept_resumed_session(
        &self,
        runtime: &mut ReceiverRuntime,
        session_id: u64,
        client_nonce: [u8; 24],
        src: SocketAddr,
        validated_ticket: ValidatedTicket,
    ) -> Result<()> {
        let session_keys = self.handshake_engine.derive_resumption_session_keys(
            validated_ticket.resumption_secret,
            HandshakeRole::Server,
            session_id,
            client_nonce,
        )?;

        runtime.sessions.insert(
            session_id,
            SessionState {
                source_ip: src.ip(),
                keys: session_keys,
                pipeline: SankakuPipeline::new_with_config(
                    &session_keys.payload_rx,
                    self.transport.pipeline,
                ),
                streams: HashMap::new(),
            },
        );
        Ok(())
    }

    async fn handle_ping_packet(
        &self,
        runtime: &mut ReceiverRuntime,
        packet: &[u8],
        src: SocketAddr,
    ) -> Result<()> {
        let Some(session_id) = packet.get(1..9).and_then(parse_u64_le) else {
            return Ok(());
        };
        let Some(session) = runtime.sessions.get(&session_id) else {
            return Ok(());
        };
        if session.source_ip != src.ip() {
            return Ok(());
        }

        let mut pong = vec![TYPE_PONG];
        pong.extend_from_slice(&session_id.to_le_bytes());
        self.socket.send_to(&pong, src).await?;
        Ok(())
    }

    async fn handle_stream_fin_packet(
        &self,
        runtime: &mut ReceiverRuntime,
        packet: &[u8],
        src: SocketAddr,
    ) -> Result<()> {
        let Ok(fin) = bincode::deserialize::<StreamFinPacket>(&packet[1..]) else {
            return Ok(());
        };
        let Some(session) = runtime.sessions.get_mut(&fin.session_id) else {
            return Ok(());
        };
        if session.source_ip != src.ip() {
            return Ok(());
        }

        session.streams.remove(&fin.stream_id);

        let mut ack = vec![TYPE_ACK];
        ack.extend_from_slice(&fin.session_id.to_le_bytes());
        ack.extend_from_slice(&fin.stream_id.to_le_bytes());
        self.socket.send_to(&ack, src).await?;
        Ok(())
    }

    async fn handle_data_packet(
        &self,
        runtime: &mut ReceiverRuntime,
        packet: &[u8],
        src: SocketAddr,
        frame_tx: &mpsc::Sender<InboundVideoFrame>,
    ) -> Result<()> {
        if packet.len() < DATA_PREFIX_SIZE {
            return Ok(());
        }

        let Some(session_id) = packet.get(1..9).and_then(parse_u64_le) else {
            return Ok(());
        };
        let Some(session) = runtime.sessions.get_mut(&session_id) else {
            return Ok(());
        };
        if session.source_ip != src.ip() {
            return Ok(());
        }

        let Some(masked_header) = packet.get(9..DATA_PREFIX_SIZE) else {
            return Ok(());
        };
        let Some(payload_with_padding) = packet.get(DATA_PREFIX_SIZE..) else {
            return Ok(());
        };
        if payload_with_padding.is_empty() {
            return Ok(());
        }

        let mask = generate_header_mask(&session.keys.header_rx, payload_with_padding);
        let mut plain_header = [0u8; GEOMETRY_HEADER_SIZE];
        for index in 0..GEOMETRY_HEADER_SIZE {
            plain_header[index] = masked_header[index] ^ mask[index];
        }

        let stream_id = parse_header_u32(&plain_header, 0);
        let frame_index = parse_header_u64(&plain_header, 4);
        let seq_id = parse_header_u32(&plain_header, 12);
        let total_size = parse_header_u32(&plain_header, 16);
        let Some(pkt_size) = parse_u16_le(&plain_header[20..22]) else {
            return Ok(());
        };
        let kind_flag = plain_header[22];

        if total_size == 0 || total_size > MAX_PROTECTED_BLOCK_SIZE {
            return Ok(());
        }
        if pkt_size == 0 || usize::from(pkt_size) > TARGET_PACKET_SIZE {
            return Ok(());
        }
        if VideoPayloadKind::from_header_flag(kind_flag).is_none() {
            return Ok(());
        }

        let payload_len = usize::from(pkt_size).min(payload_with_padding.len());
        if payload_len == 0 {
            return Ok(());
        }
        let payload = &payload_with_padding[..payload_len];

        let stream = session
            .streams
            .entry(stream_id)
            .or_insert_with(StreamState::default);

        if frame_index != stream.next_frame_index {
            return Ok(());
        }

        if stream
            .decoder_state
            .as_ref()
            .is_some_and(|state| state.frame_index != frame_index)
        {
            stream.decoder_state = None;
        }

        if stream.decoder_state.is_none() {
            let decoder = WirehairDecoder::new(total_size as u64, u32::from(pkt_size))?;
            stream.decoder_state = Some(DecoderState {
                frame_index,
                decoder,
                ideal_packets: total_size.div_ceil(u32::from(pkt_size)),
                used_packets: 0,
            });
        }

        let mut recovered: Option<Vec<u8>> = None;
        let mut ideal_packets = 0u32;
        let mut used_packets = 0u32;
        if let Some(decoder_state) = stream.decoder_state.as_mut() {
            match decoder_state.decoder.decode(seq_id, payload) {
                Ok(true) => {
                    recovered = Some(decoder_state.decoder.recover()?);
                    decoder_state.used_packets = seq_id.saturating_add(1);
                    ideal_packets = decoder_state.ideal_packets;
                    used_packets = decoder_state.used_packets;
                }
                Ok(false) => return Ok(()),
                Err(_) => {
                    stream.decoder_state = None;
                    return Ok(());
                }
            }
        }
        stream.decoder_state = None;

        let Some(protected) = recovered else {
            return Ok(());
        };
        let (restored_kind, raw) =
            session
                .pipeline
                .restore_frame(&protected, stream_id, frame_index)?;
        if restored_kind.as_header_flag() != kind_flag {
            return Ok(());
        }

        let envelope: FrameEnvelope =
            bincode::deserialize(&raw).context("Failed to decode frame envelope")?;

        let now = Instant::now();
        if let (Some(last_arrival), Some(last_timestamp)) =
            (stream.last_arrival, stream.last_timestamp_us)
        {
            let arrival_delta = now.duration_since(last_arrival).as_micros() as i128;
            let sender_delta = envelope.timestamp_us.saturating_sub(last_timestamp) as i128;
            let sample = (arrival_delta - sender_delta).unsigned_abs() as u64;
            stream.jitter_us = ((stream.jitter_us as u64 * 7 + sample) / 8) as u32;
        }
        stream.last_arrival = Some(now);
        stream.last_timestamp_us = Some(envelope.timestamp_us);

        stream.bytes_received = stream
            .bytes_received
            .saturating_add(envelope.payload.len() as u64);
        stream.frames_received = stream.frames_received.saturating_add(1);
        stream.next_frame_index = stream.next_frame_index.saturating_add(1);

        let inbound = InboundVideoFrame {
            session_id,
            stream_id,
            frame_index,
            timestamp_us: envelope.timestamp_us,
            keyframe: envelope.keyframe,
            kind: restored_kind,
            payload: envelope.payload,
        };
        if frame_tx.send(inbound).await.is_err() {
            return Ok(());
        }

        let feedback = FecFeedbackPacket {
            session_id,
            stream_id,
            frame_index,
            ideal_packets,
            used_packets,
        };
        let mut feedback_wire = vec![TYPE_FEC_FEEDBACK];
        feedback_wire.extend(bincode::serialize(&feedback)?);
        self.socket.send_to(&feedback_wire, src).await?;

        let packet_loss_ppm = if ideal_packets == 0 || used_packets <= ideal_packets {
            0
        } else {
            let excess = used_packets.saturating_sub(ideal_packets) as u64;
            ((excess.saturating_mul(1_000_000)) / ideal_packets as u64).min(u32::MAX as u64) as u32
        };
        let telemetry = TelemetryPacket {
            session_id,
            stream_id,
            frame_index,
            packet_loss_ppm,
            jitter_us: stream.jitter_us,
        };
        let mut telemetry_wire = vec![TYPE_TELEMETRY];
        telemetry_wire.extend(bincode::serialize(&telemetry)?);
        self.socket.send_to(&telemetry_wire, src).await?;

        Ok(())
    }
}

/// Public high-level API for frontend clients.
///
/// `SankakuStream` accepts a remote target and provides async send/receive
/// methods over in-memory `VideoFrame` channels.
pub struct SankakuStream {
    sender: SankakuSender,
    stream_id: u32,
    inbound: mpsc::Receiver<InboundVideoFrame>,
}

impl SankakuStream {
    pub async fn connect(
        target: &str,
        bind_addr: &str,
        psk: [u8; 32],
        ticket_key: [u8; 32],
    ) -> Result<Self> {
        let mut sender = SankakuSender::new_with_psk(target, psk).await?;
        let receiver =
            SankakuReceiver::new_with_psk_and_ticket_key(bind_addr, psk, ticket_key).await?;
        let inbound = receiver.spawn_frame_channel();
        let stream_id = sender.open_stream()?;
        Ok(Self {
            sender,
            stream_id,
            inbound,
        })
    }

    pub async fn connect_with_env(target: &str, bind_addr: &str) -> Result<Self> {
        let psk = load_psk_from_env()?;
        let ticket_key = load_ticket_key_from_env_or_psk(psk)?;
        Self::connect(target, bind_addr, psk, ticket_key).await
    }

    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    pub fn import_resumption_ticket(&mut self, blob: &[u8]) -> Result<()> {
        self.sender.import_resumption_ticket(blob)
    }

    pub fn export_resumption_ticket(&self) -> Result<Option<Vec<u8>>> {
        self.sender.export_resumption_ticket()
    }

    pub fn session_id(&self) -> Option<u64> {
        self.sender.session_id()
    }

    pub fn bootstrap_mode(&self) -> SessionBootstrapMode {
        self.sender.bootstrap_mode()
    }

    pub fn update_compression_graph(&mut self, serialized_graph: &[u8]) -> Result<()> {
        self.sender.update_compression_graph(serialized_graph)
    }

    pub async fn send(&mut self, frame: VideoFrame) -> Result<u64> {
        self.sender.send_frame(self.stream_id, frame).await
    }

    pub async fn recv(&mut self) -> Option<InboundVideoFrame> {
        self.inbound.recv().await
    }
}

pub type KyuSender = SankakuSender;
pub type KyuReceiver = SankakuReceiver;
pub type MediaFrame = VideoFrame;
pub type InboundFrame = InboundVideoFrame;
