use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sankaku_core::{parse_psk_hex, SankakuReceiver, SankakuSender, VideoFrame, VideoPayloadKind};
use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "sankaku-cli", about = "Sankaku realtime frame transport CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Send {
        #[arg(long, default_value = "127.0.0.1:8080")]
        dest: String,
        #[arg(long)]
        psk: Option<String>,
        #[arg(long)]
        ticket_in: Option<String>,
        #[arg(long)]
        ticket_out: Option<String>,
        #[arg(long, default_value_t = 120)]
        frames: u32,
        #[arg(long, default_value_t = 30)]
        fps: u32,
        #[arg(long, default_value_t = 1200)]
        payload_bytes: usize,
        #[arg(long, default_value_t = false)]
        keyframe_every_30: bool,
        #[arg(long, default_value_t = false)]
        sao: bool,
    },
    Recv {
        #[arg(long, default_value = "0.0.0.0:8080")]
        bind: String,
        #[arg(long)]
        psk: Option<String>,
        #[arg(long)]
        ticket_key: Option<String>,
        #[arg(long, default_value_t = 0)]
        max_frames: u64,
    },
}

fn resolve_psk(explicit: Option<String>) -> Result<[u8; 32]> {
    if let Some(value) = explicit {
        return parse_psk_hex(&value);
    }
    if let Ok(value) = std::env::var("SANKAKU_PSK") {
        return parse_psk_hex(&value);
    }
    if let Ok(value) = std::env::var("KYU2_PSK") {
        return parse_psk_hex(&value);
    }
    anyhow::bail!("Missing PSK: pass --psk or set SANKAKU_PSK");
}

fn resolve_ticket_key(explicit: Option<String>, psk: [u8; 32]) -> Result<[u8; 32]> {
    if let Some(value) = explicit {
        return parse_psk_hex(&value);
    }
    if let Ok(value) = std::env::var("SANKAKU_TICKET_KEY") {
        return parse_psk_hex(&value);
    }
    if let Ok(value) = std::env::var("KYU2_TICKET_KEY") {
        return parse_psk_hex(&value);
    }
    Ok(psk)
}

fn unix_us_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Send {
            dest,
            psk,
            ticket_in,
            ticket_out,
            frames,
            fps,
            payload_bytes,
            keyframe_every_30,
            sao,
        } => {
            let psk = resolve_psk(psk)?;
            let mut sender = SankakuSender::new_with_psk(&dest, psk).await?;
            if let Some(path) = ticket_in {
                let blob =
                    fs::read(&path).with_context(|| format!("Failed to read ticket {path}"))?;
                sender.import_resumption_ticket(&blob)?;
            }

            let stream_id = sender.open_stream()?;
            let interval_ms = (1000u64 / fps.max(1) as u64).max(1);
            let payload_seed = if sao { 0x5Au8 } else { 0x3Cu8 };

            let mut total_bytes = 0u64;
            for index in 0..frames {
                let mut payload = vec![payload_seed; payload_bytes.max(1)];
                if !payload.is_empty() {
                    payload[0] = (index & 0xFF) as u8;
                }

                let keyframe = keyframe_every_30 && index % 30 == 0;
                let frame = VideoFrame {
                    timestamp_us: unix_us_now(),
                    keyframe,
                    kind: if sao {
                        VideoPayloadKind::SaoParameters
                    } else {
                        VideoPayloadKind::NalUnit
                    },
                    payload,
                };
                let frame_index = sender.send_frame(stream_id, frame).await?;
                println!("sent stream={stream_id:x} frame={frame_index}");
                total_bytes = total_bytes.saturating_add(payload_bytes as u64);
                tokio::time::sleep(Duration::from_millis(interval_ms)).await;
            }

            sender
                .send_stream_fin(stream_id, total_bytes, frames as u64)
                .await?;

            if let Some(path) = ticket_out {
                if let Some(blob) = sender.export_resumption_ticket()? {
                    fs::write(&path, blob)
                        .with_context(|| format!("Failed to write ticket {path}"))?;
                }
            }
        }
        Commands::Recv {
            bind,
            psk,
            ticket_key,
            max_frames,
        } => {
            let psk = resolve_psk(psk)?;
            let ticket_key = resolve_ticket_key(ticket_key, psk)?;
            let receiver = SankakuReceiver::new_with_psk_and_ticket_key(&bind, psk, ticket_key)
                .await
                .with_context(|| format!("Failed to bind receiver on {bind}"))?;
            println!("listening on {}", receiver.local_addr()?);

            let mut frames_seen = 0u64;
            let mut inbound = receiver.spawn_frame_channel();
            while let Some(frame) = inbound.recv().await {
                frames_seen = frames_seen.saturating_add(1);
                println!(
                    "recv session={} stream={:x} frame={} kind={:?} bytes={} keyframe={}",
                    frame.session_id,
                    frame.stream_id,
                    frame.frame_index,
                    frame.kind,
                    frame.payload.len(),
                    frame.keyframe
                );
                if max_frames > 0 && frames_seen >= max_frames {
                    break;
                }
            }
        }
    }
    Ok(())
}
