# Sankaku Wire Format (v3)

Sankaku is a frame-native, UDP/FEC transport for realtime video payloads.

## 1. Session Handshake

Sankaku keeps the authenticated X25519 + ChaCha20-Poly1305 key schedule and 0-RTT ticket model.

- `H` (`0x48`): full 1-RTT handshake packet (`HandshakePacket` bincode blob)
- `R` (`0x52`): 0-RTT resume packet (`ResumePacket` bincode blob)
- `P` / `O`: ping/pong liveness

## 2. Data Packet (`D`)

Unlike the previous fixed 1200-byte format, Sankaku packets are variable-sized.
Optional padding still exists, but no fixed-size enforcement is required.

| Offset | Size | Field | Notes |
| :--- | :--- | :--- | :--- |
| 0 | 1 | Type | `0x44` (`D`) |
| 1 | 8 | Session ID | Plaintext lookup key |
| 9 | 23 | Masked Geometry Header | XOR-masked with header key stream |
| 32 | `PktSize` | Wirehair droplet bytes | Actual encoded droplet |
| var | optional | Padding | Optional policy-driven padding |

## 3. Masked Geometry Header (23 bytes)

`block_id` is now the monotonic frame index.

| Offset | Type | Field |
| :--- | :--- | :--- |
| 0 | `u32` | Stream ID |
| 4 | `u64` | Frame Index (`block_id`) |
| 12 | `u32` | FEC Sequence ID |
| 16 | `u32` | Protected Size |
| 20 | `u16` | Packet Size |
| 22 | `u8` | Data Kind Flag (`0` = NAL, `1` = SAO) |

Header masking uses ChaCha20-derived keystream from the first payload bytes and the negotiated header key.

## 4. Frame Payload Pipeline

Per frame:

1. Serialize frame envelope (`timestamp_us`, `keyframe`, raw payload bytes).
2. If kind is SAO and compression enabled, apply OpenZL.
3. Wrap with pipeline envelope mode byte:
   - raw NAL
   - raw SAO
   - OpenZL-compressed SAO
4. Encrypt with ChaCha20-Poly1305 using `(stream_id, frame_index)` bound nonce/AAD.
5. Apply Wirehair FEC and emit droplets.

Receiver reverses this path and emits fully recovered frames in-memory.

## 5. Control / Adaptation

- `F` (`0x46`): FEC feedback (`ideal_packets`, `used_packets`)
- `T` (`0x54`): telemetry (`packet_loss_ppm`, `jitter_us`)
- `E` (`0x45`): stream-finish marker (final bytes/frames)
- `A` (`0x41`): stream ACK

Sender uses `F` and `T` to tune redundancy dynamically (`~1.1x` up to bounded max) and to adjust pacing for jitter-heavy paths.

## 6. Async API Surface

`SankakuStream` exposes async send/receive of `VideoFrame`:

- outbound: `send(VideoFrame)` (frame index mapped monotonically on wire)
- inbound: `recv() -> InboundVideoFrame` via in-memory channel
- ticket continuity: import/export session ticket blobs to preserve 0-RTT resumes

No filesystem-based payload path is required for transport operation.
