use kyu2_core::{KyuEvent, KyuReceiver, KyuSender, init};
use rand::RngExt;
use std::fs;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
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

fn write_random_file(path: &Path, size: usize) -> io::Result<()> {
    let mut data = vec![0u8; size];
    rand::rng().fill(data.as_mut_slice());
    fs::write(path, &data)
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

/// Spawns a best-effort adversarial relay that injects deterministic loss/duplication/corruption.
fn spawn_adversarial_relay(
    destination: SocketAddr,
    stop: Arc<AtomicBool>,
) -> io::Result<(SocketAddr, thread::JoinHandle<()>)> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(25)))?;

    let relay_addr = socket.local_addr()?;
    let handle = thread::spawn(move || {
        let mut sender_addr: Option<SocketAddr> = None;
        let mut packet_index = 0u64;
        let mut buf = [0u8; 2048];

        while !stop.load(Ordering::Relaxed) {
            match socket.recv_from(&mut buf) {
                Ok((amt, src)) => {
                    if src == destination {
                        if let Some(sender) = sender_addr {
                            let _ = socket.send_to(&buf[..amt], sender);
                        }
                        continue;
                    }

                    sender_addr = Some(src);
                    packet_index += 1;
                    let mut packet = buf[..amt].to_vec();

                    if packet.first().copied() == Some(b'D') {
                        if packet_index.is_multiple_of(11) && packet.len() > 40 {
                            packet[35] ^= 0x5A;
                        }
                        if packet_index.is_multiple_of(5) {
                            continue;
                        }
                        if packet_index.is_multiple_of(7) {
                            let _ = socket.send_to(&packet, destination);
                        }
                    }

                    let _ = socket.send_to(&packet, destination);
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
        }
    });

    Ok((relay_addr, handle))
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

#[test]
fn transfer_survives_loss_duplication_and_corruption() {
    init();

    let psk = [0x55; 32];
    let in_dir = temp_dir("resilience-in");
    let out_dir = temp_dir("resilience-out");
    let input_file = in_dir.join("resilience_input.bin");
    write_random_file(&input_file, 192 * 1024).expect("input should be written");

    let Some(receiver) = skip_if_network_denied(
        KyuReceiver::new_with_psk("127.0.0.1:0", &out_dir, psk)
            .map_err(|error| io::Error::other(error.to_string())),
    ) else {
        return;
    };
    let receiver_addr = receiver
        .local_addr()
        .expect("receiver local addr should resolve");

    let stop_receiver = Arc::new(AtomicBool::new(false));
    let receiver_stop_clone = Arc::clone(&stop_receiver);
    let receiver_handle = thread::spawn(move || {
        let _ = receiver.run_loop_until(|_, _| {}, || receiver_stop_clone.load(Ordering::Relaxed));
    });

    let stop_relay = Arc::new(AtomicBool::new(false));
    let Some((relay_addr, relay_handle)) = skip_if_network_denied(spawn_adversarial_relay(
        receiver_addr,
        Arc::clone(&stop_relay),
    )) else {
        stop_receiver.store(true, Ordering::Relaxed);
        let _ = receiver_handle.join();
        return;
    };

    let Some(mut sender) = skip_if_network_denied(
        KyuSender::new_with_psk(&relay_addr.to_string(), psk)
            .map_err(|error| io::Error::other(error.to_string())),
    ) else {
        stop_relay.store(true, Ordering::Relaxed);
        stop_receiver.store(true, Ordering::Relaxed);
        let _ = relay_handle.join();
        let _ = receiver_handle.join();
        return;
    };
    sender
        .send_file(&input_file, 4.0, 20_000_000, |_| {})
        .expect("send should complete over adversarial relay");

    let expected_out = out_dir.join("resilience_input.bin");
    let expected_size = input_file
        .metadata()
        .expect("input metadata should be readable")
        .len();
    let completed = wait_until(Duration::from_secs(20), || {
        expected_out
            .metadata()
            .map(|metadata| metadata.len() == expected_size)
            .unwrap_or(false)
    });

    stop_relay.store(true, Ordering::Relaxed);
    stop_receiver.store(true, Ordering::Relaxed);
    relay_handle.join().expect("relay thread should join");
    receiver_handle.join().expect("receiver thread should join");

    assert!(completed, "receiver did not finish transfer before timeout");

    let original = fs::read(&input_file).expect("input should be readable");
    let recovered = fs::read(&expected_out).expect("output should be readable");
    assert_eq!(
        recovered, original,
        "output mismatch after adversarial transit"
    );
}

#[test]
fn multiplexed_streams_and_session_churn_complete() {
    init();

    let psk = [0x77; 32];
    let in_dir = temp_dir("multiplex-in");
    let out_dir = temp_dir("multiplex-out");

    let Some(receiver) = skip_if_network_denied(
        KyuReceiver::new_with_psk("127.0.0.1:0", &out_dir, psk)
            .map_err(|error| io::Error::other(error.to_string())),
    ) else {
        return;
    };
    let receiver_addr = receiver
        .local_addr()
        .expect("receiver local addr should resolve");

    let stop_receiver = Arc::new(AtomicBool::new(false));
    let receiver_stop_clone = Arc::clone(&stop_receiver);
    let receiver_handle = thread::spawn(move || {
        let _ = receiver.run_loop_until(|_, _| {}, || receiver_stop_clone.load(Ordering::Relaxed));
    });

    let mut multiplex_paths = Vec::new();
    for index in 0..12 {
        let path = in_dir.join(format!("mux-{index:02}.bin"));
        let size = 8 * 1024 + index * 1024;
        write_random_file(&path, size).expect("multiplex input file should be created");
        multiplex_paths.push(path);
    }

    let Some(mut multiplex_sender) = skip_if_network_denied(
        KyuSender::new_with_psk(&receiver_addr.to_string(), psk)
            .map_err(|error| io::Error::other(error.to_string())),
    ) else {
        stop_receiver.store(true, Ordering::Relaxed);
        let _ = receiver_handle.join();
        return;
    };
    multiplex_sender
        .send_files(&multiplex_paths, 1.5, 15_000_000, |_| {})
        .expect("multiplexed send should complete");

    for index in 0..6 {
        let path = in_dir.join(format!("session-{index:02}.bin"));
        let size = 6 * 1024 + index * 512;
        write_random_file(&path, size).expect("session churn input file should be created");

        let Some(mut sender) = skip_if_network_denied(
            KyuSender::new_with_psk(&receiver_addr.to_string(), psk)
                .map_err(|error| io::Error::other(error.to_string())),
        ) else {
            stop_receiver.store(true, Ordering::Relaxed);
            let _ = receiver_handle.join();
            return;
        };
        sender
            .send_file(&path, 1.3, 10_000_000, |event| {
                if let KyuEvent::Fault { .. } = event {
                    panic!("unexpected fault during session churn send");
                }
            })
            .expect("session churn send should complete");
        multiplex_paths.push(path);
    }

    let all_done = wait_until(Duration::from_secs(20), || {
        multiplex_paths.iter().all(|input| {
            let Some(name) = input.file_name() else {
                return false;
            };

            let expected_size = match input.metadata() {
                Ok(metadata) => metadata.len(),
                Err(_) => return false,
            };

            out_dir
                .join(name)
                .metadata()
                .map(|metadata| metadata.len() == expected_size)
                .unwrap_or(false)
        })
    });

    stop_receiver.store(true, Ordering::Relaxed);
    receiver_handle.join().expect("receiver thread should join");

    assert!(all_done, "not all multiplex/session files completed");

    for input in &multiplex_paths {
        let name = input.file_name().expect("input filename should exist");
        let output = out_dir.join(name);

        let original = fs::read(input).expect("input should be readable");
        let recovered = fs::read(output).expect("output should be readable");
        assert_eq!(recovered, original, "output mismatch for {:?}", input);
    }
}
