use sankaku_core::{
    InboundVideoFrame, SankakuReceiver, SankakuStream, VideoFrame, VideoPayloadKind, init,
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
async fn compression_graph_hot_swap_keeps_active_session() {
    init();

    let psk = [0x44; 32];
    let ticket_key = [0x24; 32];

    let Some(receiver) = skip_if_network_denied(
        SankakuReceiver::new_with_psk_and_ticket_key("127.0.0.1:0", psk, ticket_key).await,
    ) else {
        return;
    };
    let receiver_addr = receiver.local_addr().expect("receiver addr should resolve");
    let mut inbound = receiver.spawn_frame_channel();

    let Some(mut stream) = skip_if_network_denied(
        SankakuStream::connect(&receiver_addr.to_string(), "127.0.0.1:0", psk, ticket_key).await,
    ) else {
        return;
    };
    let stream_id = stream.stream_id();

    stream
        .update_compression_graph(b"graph-v1")
        .expect("first graph install should succeed");
    let first_frame = VideoFrame {
        timestamp_us: 1_000,
        keyframe: false,
        kind: VideoPayloadKind::SaoParameters,
        payload: b"sao-first".to_vec(),
    };
    stream
        .send(first_frame.clone())
        .await
        .expect("first frame should send");
    let session_id_before = stream
        .session_id()
        .expect("session id should exist after first frame");

    stream
        .update_compression_graph(b"graph-v2")
        .expect("hot-swap graph install should succeed");
    let second_frame = VideoFrame {
        timestamp_us: 2_000,
        keyframe: false,
        kind: VideoPayloadKind::SaoParameters,
        payload: b"sao-second".to_vec(),
    };
    stream
        .send(second_frame.clone())
        .await
        .expect("second frame should send");
    let session_id_after = stream
        .session_id()
        .expect("session id should remain available");

    assert_eq!(
        session_id_before, session_id_after,
        "compression graph swap must not reset transport security/session state"
    );

    let received = recv_matching_stream(&mut inbound, stream_id, 2, Duration::from_secs(6)).await;
    assert_eq!(received[0].payload, first_frame.payload);
    assert_eq!(received[0].kind, first_frame.kind);
    assert_eq!(received[1].payload, second_frame.payload);
    assert_eq!(received[1].kind, second_frame.kind);
}
