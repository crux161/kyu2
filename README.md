# Sankaku

Sankaku is a frame-native UDP transport focused on realtime video payload delivery.
It preserves authenticated X25519/ChaCha20-Poly1305 session setup and Wirehair FEC, and replaces file-centric flow with async in-memory frame I/O.

## Workspace Crates

- `sankaku-core`: async transport library (`SankakuSender`, `SankakuReceiver`, `SankakuStream`)
- `sankaku-cli`: minimal CLI for sending/receiving generated frame traffic
- `sankaku-wirehair-sys`: Wirehair FEC bindings
- `sankaku-openzl-sys`: OpenZL FFI bindings (wired for SAO payload path)

## Build

```bash
cargo check --workspace
```

## Quick Start

Set a shared key:

```bash
export SANKAKU_PSK=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

Receiver:

```bash
cargo run -p sankaku-cli -- recv --bind 0.0.0.0:8080
```

Sender:

```bash
cargo run -p sankaku-cli -- send --dest 127.0.0.1:8080 --frames 120 --fps 30 --payload-bytes 1200
```

Send SAO-class payloads through the OpenZL path:

```bash
cargo run -p sankaku-cli -- send --dest 127.0.0.1:8080 --sao --frames 120 --fps 30
```

## Protocol

See `SPEC.md` for the v3 format:

- variable-size UDP payloads (no fixed 1200-byte enforcement)
- 23-byte masked geometry header with data-kind multiplex flag
- OpenZL stage for SAO payloads before ChaCha20-Poly1305
- RTCP-style telemetry (`loss`, `jitter`) + adaptive FEC tuning
- monotonic frame-index mapping (`block_id == frame_index`)

## License

MIT (`LICENSE`)
