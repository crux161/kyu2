use sankaku_core::{
    InboundVideoFrame, SankakuReceiver, SankakuSender, SankakuStream, SessionBootstrapMode,
    VideoFrame, VideoPayloadKind, init,
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
async fn sankaku_stream_round_trip_with_0rtt_resume_ticket() {
    init();

    let psk = [0x31; 32];
    let ticket_key = [0x77; 32];

    let Some(receiver) = skip_if_network_denied(
        SankakuReceiver::new_with_psk_and_ticket_key("127.0.0.1:0", psk, ticket_key).await,
    ) else {
        return;
    };
    let receiver_addr = receiver.local_addr().expect("receiver addr should resolve");
    let mut inbound = receiver.spawn_frame_channel();

    // Warm up once to mint a ticket.
    let Some(mut warm_sender) =
        skip_if_network_denied(SankakuSender::new_with_psk(&receiver_addr.to_string(), psk).await)
    else {
        return;
    };
    let warm_stream = warm_sender
        .open_stream()
        .expect("stream id should allocate");
    warm_sender
        .send_frame(warm_stream, VideoFrame::nal(vec![0xAB], 1, true))
        .await
        .expect("warm frame should send");
    warm_sender
        .send_stream_fin(warm_stream, 1, 1)
        .await
        .expect("warm fin should send");
    let ticket_blob = warm_sender
        .export_resumption_ticket()
        .expect("ticket export should succeed")
        .expect("receiver should issue a resumption ticket");
    let _ = timeout(Duration::from_secs(3), inbound.recv())
        .await
        .expect("warm-up frame should arrive");

    // Use SankakuStream with imported ticket and assert 0-RTT path.
    let Some(mut stream) = skip_if_network_denied(
        SankakuStream::connect(&receiver_addr.to_string(), "127.0.0.1:0", psk, ticket_key).await,
    ) else {
        return;
    };
    stream
        .import_resumption_ticket(&ticket_blob)
        .expect("ticket import should succeed");
    let stream_id = stream.stream_id();

    let expected = vec![
        VideoFrame {
            timestamp_us: 10_000,
            keyframe: true,
            kind: VideoPayloadKind::NalUnit,
            payload: b"frame-0-nal".to_vec(),
        },
        VideoFrame {
            timestamp_us: 20_000,
            keyframe: false,
            kind: VideoPayloadKind::SaoParameters,
            payload: b"frame-1-sao".to_vec(),
        },
        VideoFrame {
            timestamp_us: 30_000,
            keyframe: false,
            kind: VideoPayloadKind::NalUnit,
            payload: b"frame-2-nal".to_vec(),
        },
    ];

    for frame in expected.clone() {
        stream
            .send(frame)
            .await
            .expect("stream frame send should succeed");
    }

    assert_eq!(stream.bootstrap_mode(), SessionBootstrapMode::ZeroRttResume);
    assert!(
        stream.session_id().is_some(),
        "resumed stream should have an active session id"
    );

    let received = recv_matching_stream(
        &mut inbound,
        stream_id,
        expected.len(),
        Duration::from_secs(6),
    )
    .await;
    assert_eq!(received.len(), expected.len());
    for (index, (rx, tx)) in received.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            rx.frame_index, index as u64,
            "frame index should map directly to block_id"
        );
        assert_eq!(rx.timestamp_us, tx.timestamp_us);
        assert_eq!(rx.keyframe, tx.keyframe);
        assert_eq!(rx.kind, tx.kind);
        assert_eq!(rx.payload, tx.payload);
    }
}
