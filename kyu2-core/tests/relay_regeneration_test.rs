use kyu2_core::{KyuEvent, KyuReceiver, KyuSender, init};
use rand::RngExt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "kyu2-{label}-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    fs::create_dir_all(&dir).expect("temp dir should be created");
    dir
}

fn write_random_file(path: &Path, size: usize) {
    let mut data = vec![0u8; size];
    rand::rng().fill(data.as_mut_slice());
    fs::write(path, &data).expect("input should be written");
}

fn wait_until<F>(timeout: Duration, mut condition: F) -> bool
where
    F: FnMut() -> bool,
{
    let started = Instant::now();
    while started.elapsed() < timeout {
        if condition() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

fn skip_if_network_denied<T, E: std::fmt::Display>(result: Result<T, E>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            let text = error.to_string();
            if text.contains("Operation not permitted") || text.contains("Permission denied") {
                None
            } else {
                panic!("unexpected network error: {text}");
            }
        }
    }
}

#[test]
fn relay_recovers_and_regenerates_end_to_end() {
    init();

    let psk = [0x66; 32];
    let input_dir = temp_dir("relay-source");
    let relay_spool_dir = temp_dir("relay-spool");
    let destination_out_dir = temp_dir("relay-dest");

    let input_file = input_dir.join("relay_e2e.bin");
    write_random_file(&input_file, 160 * 1024);

    let Some(destination_receiver) = skip_if_network_denied(KyuReceiver::new_with_psk(
        "127.0.0.1:0",
        &destination_out_dir,
        psk,
    )) else {
        return;
    };
    let destination_addr = destination_receiver
        .local_addr()
        .expect("destination addr should resolve");

    let stop_destination = Arc::new(AtomicBool::new(false));
    let destination_completed = Arc::new(AtomicBool::new(false));
    let destination_trace_id = Arc::new(Mutex::new(None::<u64>));

    let destination_stop_clone = Arc::clone(&stop_destination);
    let destination_done_clone = Arc::clone(&destination_completed);
    let destination_trace_clone = Arc::clone(&destination_trace_id);
    let destination_handle = thread::spawn(move || {
        let _ = destination_receiver.run_loop_until(
            |_, event| {
                if let KyuEvent::TransferComplete { trace_id, .. } = event {
                    *destination_trace_clone
                        .lock()
                        .expect("destination trace lock should work") = Some(trace_id);
                    destination_done_clone.store(true, Ordering::Relaxed);
                }
            },
            || destination_stop_clone.load(Ordering::Relaxed),
        );
    });

    let Some(relay_receiver) = skip_if_network_denied(KyuReceiver::new_with_psk(
        "127.0.0.1:0",
        &relay_spool_dir,
        psk,
    )) else {
        stop_destination.store(true, Ordering::Relaxed);
        let _ = destination_handle.join();
        return;
    };
    let relay_addr = relay_receiver
        .local_addr()
        .expect("relay addr should resolve");

    let Some(forward_sender) =
        skip_if_network_denied(KyuSender::new_with_psk(&destination_addr.to_string(), psk))
    else {
        stop_destination.store(true, Ordering::Relaxed);
        let _ = destination_handle.join();
        return;
    };

    let relay_inbound_trace_id = Arc::new(Mutex::new(None::<u64>));
    let relay_forward_trace_id = Arc::new(Mutex::new(None::<u64>));
    let stop_relay = Arc::new(AtomicBool::new(false));

    let relay_inbound_trace_clone = Arc::clone(&relay_inbound_trace_id);
    let relay_forward_trace_clone = Arc::clone(&relay_forward_trace_id);
    let relay_stop_clone = Arc::clone(&stop_relay);
    let relay_handle = thread::spawn(move || {
        let sender_cell = std::cell::RefCell::new(forward_sender);
        let _ = relay_receiver.run_loop_until(
            |_, event| {
                if let KyuEvent::TransferComplete { trace_id, path, .. } = event {
                    *relay_inbound_trace_clone
                        .lock()
                        .expect("relay inbound trace lock should work") = Some(trace_id);

                    let _ = sender_cell.borrow_mut().send_file(
                        &path,
                        1.5,
                        12_000_000,
                        |forward_event| {
                            if let KyuEvent::TransferComplete { trace_id, .. } = forward_event {
                                *relay_forward_trace_clone
                                    .lock()
                                    .expect("relay forward trace lock should work") =
                                    Some(trace_id);
                            }
                        },
                    );
                }
            },
            || relay_stop_clone.load(Ordering::Relaxed),
        );
    });

    let source_trace_id = Arc::new(Mutex::new(None::<u64>));
    let Some(mut source_sender) =
        skip_if_network_denied(KyuSender::new_with_psk(&relay_addr.to_string(), psk))
    else {
        stop_relay.store(true, Ordering::Relaxed);
        stop_destination.store(true, Ordering::Relaxed);
        let _ = relay_handle.join();
        let _ = destination_handle.join();
        return;
    };

    let source_trace_clone = Arc::clone(&source_trace_id);
    source_sender
        .send_file(&input_file, 1.8, 12_000_000, |event| {
            if let KyuEvent::TransferComplete { trace_id, .. } = event {
                *source_trace_clone
                    .lock()
                    .expect("source trace lock should work") = Some(trace_id);
            }
        })
        .expect("source send should complete");

    let destination_path = destination_out_dir.join("relay_e2e.bin");
    let completed = wait_until(Duration::from_secs(20), || {
        destination_completed.load(Ordering::Relaxed) && destination_path.exists()
    });

    stop_relay.store(true, Ordering::Relaxed);
    stop_destination.store(true, Ordering::Relaxed);
    relay_handle.join().expect("relay thread should join");
    destination_handle
        .join()
        .expect("destination thread should join");

    assert!(
        completed,
        "relay end-to-end transfer did not complete in time"
    );

    let original = fs::read(&input_file).expect("source file should be readable");
    let recovered = fs::read(&destination_path).expect("destination file should be readable");
    assert_eq!(recovered, original, "relay destination output mismatch");

    let source_trace = *source_trace_id
        .lock()
        .expect("source trace lock should work");
    let relay_inbound_trace = *relay_inbound_trace_id
        .lock()
        .expect("relay inbound trace lock should work");
    let relay_forward_trace = *relay_forward_trace_id
        .lock()
        .expect("relay forward trace lock should work");
    let destination_trace = *destination_trace_id
        .lock()
        .expect("destination trace lock should work");

    assert!(source_trace.is_some(), "source trace should be set");
    assert!(
        relay_inbound_trace.is_some(),
        "relay inbound trace should be set"
    );
    assert!(
        relay_forward_trace.is_some(),
        "relay forward trace should be set"
    );
    assert!(
        destination_trace.is_some(),
        "destination trace should be set"
    );

    assert_eq!(
        source_trace, relay_inbound_trace,
        "relay should observe source transfer trace"
    );
    assert_eq!(
        relay_forward_trace, destination_trace,
        "destination should observe forwarded transfer trace"
    );
    assert_ne!(
        source_trace, relay_forward_trace,
        "relay regeneration should emit a fresh downstream trace"
    );
}
