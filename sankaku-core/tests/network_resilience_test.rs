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
async fn dynamic_fec_scales_with_mock_packet_drop_feedback() {
    init();

    let psk = [0x52; 32];
    let Some(receiver) =
        skip_if_network_denied(SankakuReceiver::new_with_psk("127.0.0.1:0", psk).await)
    else {
        return;
    };
    let receiver_addr = receiver.local_addr().expect("receiver addr should resolve");
    let mut inbound = receiver.spawn_frame_channel();

    let Some(mut sender) =
        skip_if_network_denied(SankakuSender::new_with_psk(&receiver_addr.to_string(), psk).await)
    else {
        return;
    };
    let stream_id = sender.open_stream().expect("stream id should allocate");

    let initial_redundancy = sender
        .stream_redundancy(stream_id)
        .expect("stream redundancy should exist");

    let mut sent = Vec::new();
    for index in 0..6u64 {
        // Introduce mock packet-loss/jitter bursts before each send.
        sender.apply_network_telemetry(stream_id, 260_000, 25_000);

        let frame = VideoFrame {
            timestamp_us: 1_000 * (index + 1),
            keyframe: index % 2 == 0,
            kind: VideoPayloadKind::NalUnit,
            payload: format!("loss-burst-frame-{index}").into_bytes(),
        };
        sent.push(frame.clone());
        sender
            .send_frame(stream_id, frame)
            .await
            .expect("frame should send");
    }

    let elevated_redundancy = sender
        .stream_redundancy(stream_id)
        .expect("stream redundancy should exist after mock drops");
    assert!(
        elevated_redundancy > initial_redundancy,
        "expected redundancy to scale up under simulated drop telemetry ({initial_redundancy} -> {elevated_redundancy})"
    );

    // Apply low-loss feedback and ensure controller can scale back down.
    for _ in 0..6 {
        sender.apply_network_telemetry(stream_id, 0, 500);
        sender
            .send_frame(
                stream_id,
                VideoFrame {
                    timestamp_us: 100_000,
                    keyframe: false,
                    kind: VideoPayloadKind::NalUnit,
                    payload: b"stabilizer".to_vec(),
                },
            )
            .await
            .expect("stabilizer frame should send");
    }

    let recovered_redundancy = sender
        .stream_redundancy(stream_id)
        .expect("stream redundancy should exist after recovery");
    assert!(
        recovered_redundancy <= elevated_redundancy,
        "redundancy should not stay pinned after healthy telemetry ({elevated_redundancy} -> {recovered_redundancy})"
    );

    let received =
        recv_matching_stream(&mut inbound, stream_id, sent.len(), Duration::from_secs(6)).await;
    for (tx, rx) in sent.iter().zip(received.iter()) {
        assert_eq!(rx.kind, tx.kind);
        assert_eq!(rx.payload, tx.payload);
        assert_eq!(rx.timestamp_us, tx.timestamp_us);
    }
}
