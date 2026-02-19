use sankaku_core::{
    InboundVideoFrame, SankakuReceiver, SankakuSender, VideoFrame, VideoPayloadKind, init,
};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout};

async fn recv_matching_stream(
    inbound: &mut mpsc::Receiver<InboundVideoFrame>,
    stream_id: u32,
    expected: usize,
    timeout_budget: Duration,
) -> Vec<InboundVideoFrame> {
    let mut frames = Vec::with_capacity(expected);
    let deadline = Instant::now() + timeout_budget;
    while frames.len() < expected {
        let now = Instant::now();
        assert!(now < deadline, "timed out waiting for expected frames");
        let remaining = deadline - now;
        let frame = timeout(remaining, inbound.recv())
            .await
            .expect("frame receive should not time out")
            .expect("inbound frame channel should remain open");
        if frame.stream_id == stream_id {
            frames.push(frame);
        }
    }
    frames
}

fn skip_if_network_denied<T>(result: anyhow::Result<T>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            let message = error.to_string();
            if message.contains("Operation not permitted") || message.contains("Permission denied")
            {
                None
            } else {
                panic!("unexpected network error: {message}");
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_regenerates_frames_in_memory() {
    init();

    let psk = [0x66; 32];

    let Some(destination) =
        skip_if_network_denied(SankakuReceiver::new_with_psk("127.0.0.1:0", psk).await)
    else {
        return;
    };
    let destination_addr = destination
        .local_addr()
        .expect("destination addr should resolve");
    let mut destination_inbound = destination.spawn_frame_channel();

    let Some(relay) =
        skip_if_network_denied(SankakuReceiver::new_with_psk("127.0.0.1:0", psk).await)
    else {
        return;
    };
    let relay_addr = relay.local_addr().expect("relay addr should resolve");
    let mut relay_inbound = relay.spawn_frame_channel();

    let Some(mut source_sender) =
        skip_if_network_denied(SankakuSender::new_with_psk(&relay_addr.to_string(), psk).await)
    else {
        return;
    };
    let source_stream = source_sender
        .open_stream()
        .expect("source stream should allocate");

    let Some(mut relay_sender) = skip_if_network_denied(
        SankakuSender::new_with_psk(&destination_addr.to_string(), psk).await,
    ) else {
        return;
    };
    let relay_stream = relay_sender
        .open_stream()
        .expect("relay stream should allocate");

    let frames = vec![
        VideoFrame {
            timestamp_us: 100,
            keyframe: true,
            kind: VideoPayloadKind::NalUnit,
            payload: b"relay-frame-0".to_vec(),
        },
        VideoFrame {
            timestamp_us: 200,
            keyframe: false,
            kind: VideoPayloadKind::SaoParameters,
            payload: b"relay-frame-1".to_vec(),
        },
        VideoFrame {
            timestamp_us: 300,
            keyframe: false,
            kind: VideoPayloadKind::NalUnit,
            payload: b"relay-frame-2".to_vec(),
        },
    ];

    for frame in frames.iter().cloned() {
        source_sender
            .send_frame(source_stream, frame)
            .await
            .expect("source frame should send to relay");

        let relay_received = timeout(Duration::from_secs(3), relay_inbound.recv())
            .await
            .expect("relay should receive a frame in time")
            .expect("relay inbound channel should stay open");
        assert_eq!(relay_received.stream_id, source_stream);

        relay_sender
            .send_frame(
                relay_stream,
                VideoFrame {
                    timestamp_us: relay_received.timestamp_us,
                    keyframe: relay_received.keyframe,
                    kind: relay_received.kind,
                    payload: relay_received.payload,
                },
            )
            .await
            .expect("relay should forward regenerated frame");
    }

    let total_bytes: u64 = frames.iter().map(|frame| frame.payload.len() as u64).sum();
    source_sender
        .send_stream_fin(source_stream, total_bytes, frames.len() as u64)
        .await
        .expect("source fin should send");
    relay_sender
        .send_stream_fin(relay_stream, total_bytes, frames.len() as u64)
        .await
        .expect("relay fin should send");

    let destination_frames = recv_matching_stream(
        &mut destination_inbound,
        relay_stream,
        frames.len(),
        Duration::from_secs(6),
    )
    .await;

    assert_ne!(
        source_stream, relay_stream,
        "relay should emit a regenerated downstream stream id"
    );
    for (sent, received) in frames.iter().zip(destination_frames.iter()) {
        assert_eq!(received.payload, sent.payload);
        assert_eq!(received.kind, sent.kind);
        assert_eq!(received.timestamp_us, sent.timestamp_us);
        assert_eq!(received.keyframe, sent.keyframe);
    }
}
