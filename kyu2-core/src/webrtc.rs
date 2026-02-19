use anyhow::{Context, Result, bail};
use bytes::Bytes;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::{MIME_TYPE_H264, MIME_TYPE_OPUS, MediaEngine};
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::media::Sample;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::track::track_local::TrackLocal;
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;

/// Default STUN server used when no explicit ICE servers are configured.
pub const DEFAULT_STUN_SERVER: &str = "stun:stun.l.google.com:19302";

/// Per-server ICE configuration for STUN/TURN negotiation.
#[derive(Debug, Clone)]
pub struct IceServerConfig {
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub credential: Option<String>,
}

impl IceServerConfig {
    /// Builds a STUN-only server entry from a single URL.
    pub fn stun(url: impl Into<String>) -> Self {
        Self {
            urls: vec![url.into()],
            username: None,
            credential: None,
        }
    }

    /// Builds a TURN server entry with long-term credentials.
    pub fn turn(
        url: impl Into<String>,
        username: impl Into<String>,
        credential: impl Into<String>,
    ) -> Self {
        Self {
            urls: vec![url.into()],
            username: Some(username.into()),
            credential: Some(credential.into()),
        }
    }

    fn into_webrtc(self) -> RTCIceServer {
        RTCIceServer {
            urls: self.urls,
            username: self.username.unwrap_or_default(),
            credential: self.credential.unwrap_or_default(),
            ..Default::default()
        }
    }
}

/// End-to-end WebRTC transport configuration.
#[derive(Debug, Clone)]
pub struct WebRtcConfig {
    pub ice_servers: Vec<IceServerConfig>,
}

impl Default for WebRtcConfig {
    fn default() -> Self {
        Self {
            ice_servers: vec![IceServerConfig::stun(DEFAULT_STUN_SERVER)],
        }
    }
}

/// Inbound data-channel payload delivered by `install_data_channel_ingress`.
#[derive(Debug, Clone)]
pub struct InboundDataChannelMessage {
    pub label: String,
    pub is_string: bool,
    pub payload: Vec<u8>,
}

/// Inbound RTP payload delivered by `install_inbound_rtp_bridge`.
#[derive(Debug, Clone)]
pub struct InboundRtpFrame {
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub marker: bool,
    pub ssrc: u32,
    pub payload: Vec<u8>,
}

/// WebRTC peer wrapper providing ICE/STUN/TURN + DTLS/SRTP connectivity.
pub struct WebRtcPeer {
    peer: Arc<RTCPeerConnection>,
    connection_state_rx: watch::Receiver<RTCPeerConnectionState>,
}

impl WebRtcPeer {
    /// Creates a peer with default media codecs and interceptor stack.
    pub async fn new(config: WebRtcConfig) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .context("failed to register WebRTC default codecs")?;

        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut media_engine)
            .context("failed to register WebRTC default interceptors")?;

        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build();

        let peer_connection = api
            .new_peer_connection(RTCConfiguration {
                ice_servers: config
                    .ice_servers
                    .into_iter()
                    .map(IceServerConfig::into_webrtc)
                    .collect(),
                ..Default::default()
            })
            .await
            .context("failed to create WebRTC peer connection")?;

        let peer = Arc::new(peer_connection);
        let (state_tx, state_rx) = watch::channel(RTCPeerConnectionState::New);
        peer.on_peer_connection_state_change(Box::new(move |state: RTCPeerConnectionState| {
            let state_tx = state_tx.clone();
            Box::pin(async move {
                let _ = state_tx.send(state);
            })
        }));

        Ok(Self {
            peer,
            connection_state_rx: state_rx,
        })
    }

    /// Returns the underlying WebRTC peer connection.
    pub fn peer_connection(&self) -> Arc<RTCPeerConnection> {
        Arc::clone(&self.peer)
    }

    /// Creates a negotiated data channel used for binary frame/file transport.
    pub async fn create_data_channel(&self, label: &str) -> Result<Arc<RTCDataChannel>> {
        self.peer
            .create_data_channel(label, None)
            .await
            .with_context(|| format!("failed to create data channel `{label}`"))
    }

    /// Creates and serializes a full SDP offer (with ICE candidates gathered).
    pub async fn create_offer_sdp(&self) -> Result<String> {
        let offer = self
            .peer
            .create_offer(None)
            .await
            .context("failed to create SDP offer")?;

        let mut gather_complete = self.peer.gathering_complete_promise().await;
        self.peer
            .set_local_description(offer)
            .await
            .context("failed to set local offer")?;
        let _ = gather_complete.recv().await;

        let local = self
            .peer
            .local_description()
            .await
            .context("missing local SDP offer")?;
        serde_json::to_string(&local).context("failed to serialize SDP offer")
    }

    /// Accepts a remote SDP offer and returns a serialized full SDP answer.
    pub async fn accept_offer_create_answer_sdp(&self, offer_sdp_json: &str) -> Result<String> {
        let offer: RTCSessionDescription =
            serde_json::from_str(offer_sdp_json).context("failed to parse remote SDP offer")?;
        self.peer
            .set_remote_description(offer)
            .await
            .context("failed to set remote SDP offer")?;

        let answer = self
            .peer
            .create_answer(None)
            .await
            .context("failed to create SDP answer")?;

        let mut gather_complete = self.peer.gathering_complete_promise().await;
        self.peer
            .set_local_description(answer)
            .await
            .context("failed to set local SDP answer")?;
        let _ = gather_complete.recv().await;

        let local = self
            .peer
            .local_description()
            .await
            .context("missing local SDP answer")?;
        serde_json::to_string(&local).context("failed to serialize SDP answer")
    }

    /// Applies a remote SDP answer (or offer in out-of-band negotiation flows).
    pub async fn set_remote_description_sdp(&self, remote_sdp_json: &str) -> Result<()> {
        let remote: RTCSessionDescription = serde_json::from_str(remote_sdp_json)
            .context("failed to parse remote SDP description")?;
        self.peer
            .set_remote_description(remote)
            .await
            .context("failed to apply remote SDP description")
    }

    /// Emits local trickle ICE candidates as serialized JSON payloads.
    pub fn install_local_candidate_bridge(&self, capacity: usize) -> mpsc::Receiver<String> {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        self.peer.on_ice_candidate(Box::new(move |candidate| {
            let tx = tx.clone();
            Box::pin(async move {
                let Some(candidate) = candidate else {
                    return;
                };

                let Ok(candidate_init) = candidate.to_json().await else {
                    return;
                };
                let Ok(raw) = serde_json::to_string(&candidate_init) else {
                    return;
                };
                let _ = tx.send(raw).await;
            })
        }));
        rx
    }

    /// Applies one remote trickle ICE candidate encoded as JSON.
    pub async fn add_remote_candidate_json(&self, candidate_json: &str) -> Result<()> {
        let candidate: RTCIceCandidateInit =
            serde_json::from_str(candidate_json).context("failed to parse ICE candidate JSON")?;
        self.peer
            .add_ice_candidate(candidate)
            .await
            .context("failed to add remote ICE candidate")
    }

    /// Waits until ICE + DTLS complete and the peer is connected.
    pub async fn wait_connected(&self, timeout: Duration) -> Result<()> {
        let mut state_rx = self.connection_state_rx.clone();
        let wait = async move {
            loop {
                let state = state_rx.borrow().clone();
                match state {
                    RTCPeerConnectionState::Connected => return Ok(()),
                    RTCPeerConnectionState::Failed => {
                        bail!("WebRTC peer connection failed during ICE/DTLS negotiation")
                    }
                    RTCPeerConnectionState::Closed => {
                        bail!("WebRTC peer connection closed before becoming connected")
                    }
                    _ => {
                        state_rx
                            .changed()
                            .await
                            .context("peer connection state watcher closed unexpectedly")?;
                    }
                }
            }
        };

        tokio::time::timeout(timeout, wait)
            .await
            .context("timed out waiting for WebRTC ICE/DTLS connectivity")?
    }

    /// Blocks until a data channel transitions to Open.
    pub async fn wait_data_channel_open(
        channel: &Arc<RTCDataChannel>,
        timeout: Duration,
    ) -> Result<()> {
        let (ready_tx, ready_rx) = oneshot::channel::<()>();
        let ready_tx = Arc::new(Mutex::new(Some(ready_tx)));

        channel.on_open(Box::new(move || {
            let ready_tx = Arc::clone(&ready_tx);
            Box::pin(async move {
                if let Some(ready_tx) = ready_tx.lock().await.take() {
                    let _ = ready_tx.send(());
                }
            })
        }));

        tokio::time::timeout(timeout, ready_rx)
            .await
            .context("timed out waiting for data channel open")?
            .context("data channel open signal dropped unexpectedly")
    }

    /// Sends one binary message over a data channel.
    pub async fn send_data_channel_binary(
        channel: &Arc<RTCDataChannel>,
        payload: &[u8],
    ) -> Result<usize> {
        let data = Bytes::copy_from_slice(payload);
        channel
            .send(&data)
            .await
            .context("failed to send data channel payload")
    }

    /// Routes inbound data-channel messages into a bounded async receiver.
    pub fn install_data_channel_ingress(
        &self,
        label_filter: Option<String>,
        capacity: usize,
    ) -> mpsc::Receiver<InboundDataChannelMessage> {
        let (tx, rx) = mpsc::channel(capacity.max(1));

        self.peer.on_data_channel(Box::new(move |channel| {
            let tx = tx.clone();
            let label_filter = label_filter.clone();
            Box::pin(async move {
                let channel_label = channel.label().to_string();
                if let Some(expected_label) = label_filter.as_ref() {
                    if expected_label != &channel_label {
                        return;
                    }
                }

                channel.on_message(Box::new(move |message: DataChannelMessage| {
                    let tx = tx.clone();
                    let label = channel_label.clone();
                    Box::pin(async move {
                        let packet = InboundDataChannelMessage {
                            label,
                            is_string: message.is_string,
                            payload: message.data.to_vec(),
                        };
                        let _ = tx.send(packet).await;
                    })
                }));
            })
        }));

        rx
    }

    /// Adds an Opus sender track. When negotiated, media flows over SRTP.
    pub async fn add_opus_track(
        &self,
        track_id: &str,
        stream_id: &str,
    ) -> Result<Arc<TrackLocalStaticSample>> {
        let track = Arc::new(TrackLocalStaticSample::new(
            webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability {
                mime_type: MIME_TYPE_OPUS.to_owned(),
                clock_rate: 48_000,
                channels: 2,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            track_id.to_owned(),
            stream_id.to_owned(),
        ));

        let sender = self
            .peer
            .add_track(Arc::clone(&track) as Arc<dyn TrackLocal + Send + Sync>)
            .await
            .context("failed to add Opus sender track")?;
        Self::spawn_rtcp_drainer(sender);
        Ok(track)
    }

    /// Adds an H264 sender track. When negotiated, media flows over SRTP.
    pub async fn add_h264_track(
        &self,
        track_id: &str,
        stream_id: &str,
    ) -> Result<Arc<TrackLocalStaticSample>> {
        let track = Arc::new(TrackLocalStaticSample::new(
            webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability {
                mime_type: MIME_TYPE_H264.to_owned(),
                clock_rate: 90_000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            track_id.to_owned(),
            stream_id.to_owned(),
        ));

        let sender = self
            .peer
            .add_track(Arc::clone(&track) as Arc<dyn TrackLocal + Send + Sync>)
            .await
            .context("failed to add H264 sender track")?;
        Self::spawn_rtcp_drainer(sender);
        Ok(track)
    }

    /// Writes one encoded media sample onto an SRTP-protected sender track.
    pub async fn write_media_sample(
        track: &Arc<TrackLocalStaticSample>,
        payload: &[u8],
        duration: Duration,
    ) -> Result<()> {
        track
            .write_sample(&Sample {
                data: Bytes::copy_from_slice(payload),
                timestamp: SystemTime::now(),
                duration,
                packet_timestamp: 0,
                prev_dropped_packets: 0,
                prev_padding_packets: 0,
            })
            .await
            .context("failed to write SRTP media sample")
    }

    /// Routes inbound SRTP RTP packets into a bounded async receiver.
    pub fn install_inbound_rtp_bridge(&self, capacity: usize) -> mpsc::Receiver<InboundRtpFrame> {
        let (tx, rx) = mpsc::channel(capacity.max(1));

        self.peer
            .on_track(Box::new(move |track, _receiver, _transceiver| {
                let tx = tx.clone();
                Box::pin(async move {
                    while let Ok((packet, _)) = track.read_rtp().await {
                        let frame = InboundRtpFrame {
                            payload_type: packet.header.payload_type,
                            sequence_number: packet.header.sequence_number,
                            timestamp: packet.header.timestamp,
                            marker: packet.header.marker,
                            ssrc: packet.header.ssrc,
                            payload: packet.payload.to_vec(),
                        };
                        if tx.send(frame).await.is_err() {
                            break;
                        }
                    }
                })
            }));

        rx
    }

    /// Gracefully closes the peer connection and all transports.
    pub async fn close(&self) -> Result<()> {
        self.peer
            .close()
            .await
            .context("failed to close peer connection")
    }

    fn spawn_rtcp_drainer(sender: Arc<webrtc::rtp_transceiver::rtp_sender::RTCRtpSender>) {
        tokio::spawn(async move {
            let mut rtcp_buf = vec![0u8; 1500];
            while sender.read(&mut rtcp_buf).await.is_ok() {}
        });
    }
}
