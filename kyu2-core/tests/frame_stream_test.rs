use kyu2_core::{
    FrameSink, FrameSource, FrameStreamConfig, InboundFrame, KyuReceiver, KyuSender, MediaFrame,
    StreamSemantics, init,
};
use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

fn wait_until<F>(timeout: Duration, mut condition: F) -> bool
where
    F: FnMut() -> bool,
{
    let started = Instant::now();
    while started.elapsed() < timeout {
        if condition() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

fn skip_if_network_denied<T>(result: io::Result<T>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error)
            if error.kind() == io::ErrorKind::PermissionDenied
                || error.to_string().contains("Operation not permitted") =>
        {
            None
        }
        Err(error) => panic!("unexpected io error: {error}"),
    }
}

struct VecFrameSource {
    frames: VecDeque<MediaFrame>,
}

impl FrameSource for VecFrameSource {
    fn next_frame(&mut self) -> anyhow::Result<Option<MediaFrame>> {
        Ok(self.frames.pop_front())
    }
}

#[derive(Default)]
struct SinkState {
    frames: Vec<Vec<u8>>,
    finished: bool,
}

struct CollectSink {
    state: Arc<Mutex<SinkState>>,
}

impl FrameSink for CollectSink {
    fn on_frame(&mut self, frame: InboundFrame) -> anyhow::Result<()> {
        let mut state = self
            .state
            .lock()
            .expect("sink mutex should not be poisoned");
        state.frames.push(frame.payload);
        Ok(())
    }

    fn on_stream_end(
        &mut self,
        _session_id: u64,
        _stream_id: u32,
        _trace_id: u64,
        _final_bytes: u64,
        _final_frames: u64,
    ) {
        let mut state = self
            .state
            .lock()
            .expect("sink mutex should not be poisoned");
        state.finished = true;
    }
}

#[test]
fn frame_mode_send_and_receive_round_trip() {
    init();

    let psk = [0x44; 32];
    let Some(receiver) = skip_if_network_denied(
        KyuReceiver::new_with_psk("127.0.0.1:0", std::path::Path::new("."), psk)
            .map_err(|error| io::Error::other(error.to_string())),
    ) else {
        return;
    };
    let receiver_addr = receiver
        .local_addr()
        .expect("receiver local addr should resolve");

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);
    let sink_state = Arc::new(Mutex::new(SinkState::default()));
    let sink_state_clone = Arc::clone(&sink_state);
    let receiver_handle = thread::spawn(move || {
        let mut sink = CollectSink {
            state: sink_state_clone,
        };
        let _ = receiver.run_loop_frames_until(
            &mut sink,
            |_, _| {},
            || stop_clone.load(Ordering::Relaxed),
        );
    });

    let Some(mut sender) = skip_if_network_denied(
        KyuSender::new_with_psk(&receiver_addr.to_string(), psk)
            .map_err(|error| io::Error::other(error.to_string())),
    ) else {
        stop.store(true, Ordering::Relaxed);
        let _ = receiver_handle.join();
        return;
    };

    let frames = VecDeque::from(vec![
        MediaFrame {
            payload: b"frame-a".to_vec(),
            timestamp_us: 10,
            keyframe: true,
        },
        MediaFrame {
            payload: b"frame-b".to_vec(),
            timestamp_us: 20,
            keyframe: false,
        },
        MediaFrame {
            payload: b"frame-c".to_vec(),
            timestamp_us: 30,
            keyframe: false,
        },
    ]);
    let mut source = VecFrameSource { frames };
    sender
        .send_stream_from_source(
            &mut source,
            FrameStreamConfig {
                stream_name: "media.opus".to_string(),
                semantics: StreamSemantics::MediaFrames,
                declared_size: None,
                initial_redundancy: 1.3,
                max_bytes_per_sec: 10_000_000,
            },
            |_| {},
        )
        .expect("frame send should complete");

    let completed = wait_until(Duration::from_secs(5), || {
        sink_state
            .lock()
            .expect("sink mutex should not be poisoned")
            .finished
    });
    stop.store(true, Ordering::Relaxed);
    receiver_handle.join().expect("receiver thread should join");

    assert!(completed, "frame sink did not observe stream completion");
    let state = sink_state
        .lock()
        .expect("sink mutex should not be poisoned");
    assert_eq!(state.frames.len(), 3);
    assert_eq!(state.frames[0], b"frame-a");
    assert_eq!(state.frames[1], b"frame-b");
    assert_eq!(state.frames[2], b"frame-c");
}
