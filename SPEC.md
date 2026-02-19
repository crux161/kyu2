# Kyu2 Wire Format (v2.0)

The protocol is designed to be **stateless**, **multiplexed**, and **adversarially resistant**.

## 1. Handshake Phase (Type `H`)
Initiates the X25519 Diffie-Hellman key exchange.

| Offset | Size | Field | Description |
| :--- | :--- | :--- | :--- |
| **0** | `1` | **Type** | `0x48` (b'H') |
| **1** | `VLP` | **Bincode Blob** | Contains `ProtocolVersion` (u16), `Capabilities` (u16), `SessionID` (u64), `PublicKey` (32 bytes), and `AuthTag` (16 bytes). |

---

## 2. Data Stream Phase (Type `D`)

Every data packet is padded to exactly **1200 bytes** to prevent traffic analysis. The payload size is hidden within the encrypted header.



### Packet Layout
| Offset | Size | Field | Description |
| :--- | :--- | :--- | :--- |
| **0** | `1` | **Type** | `0x44` (b'D') |
| **1** | `8` | **Session ID** | Plaintext. Used by receiver to look up the X25519 Shared Secret. |
| **9** | `22` | **Masked Header** | The XOR-obfuscated geometry. |
| **31** | `VLP`| **Payload** | The raw Wirehair droplet data (up to `Pkt Size`). |
| **Varies**| `VLP`| **Padding** | Zeros appended to reach exactly 1200 bytes. |

---

### 3. The Masked Header (22 Bytes)
To prevent stream tracking and replay analysis, the 22-byte geometry header is XOR-masked before transmission.

**Plaintext Geometry:**
| Offset | Type | Field | Description |
| :--- | :--- | :--- | :--- |
| **0** | `u32` | **Stream ID** | Multiplexing ID for the specific file. |
| **4** | `u64` | **Block ID** | Chunk index. Block 0 is the `SessionManifest`. |
| **12** | `u32` | **Seq ID** | FEC droplet index. |
| **16** | `u32` | **Total Size** | Total bytes of the encrypted blob for this Block. |
| **20** | `u16` | **Pkt Size** | Size of the valid Payload in this UDP packet. |

**Masking Algorithm:**
1. Extract the first 12 bytes of the Payload. This is the **Dynamic Nonce**.
2. Initialize ChaCha20 with the `SharedSecret` and the `Dynamic Nonce`.
3. Encrypt a 22-byte array of zeros `[0u8; 22]` to generate the **Keystream Mask**.
4. Apply a bitwise XOR between the Plaintext Geometry and the Keystream Mask.

Because the payload is previously encrypted via ChaCha20-Poly1305 (using `BlockID` as AAD), the first 12 bytes are statistically random and guaranteed to change for every FEC droplet, ensuring the Keystream Mask is highly dynamic.

---

## 4. Stream Manifest (`BlockID = 0`)

Each stream starts with a serialized `SessionManifest` block. Current fields:

- `filename: String`
- `file_size: u64`
- `trace_id: u64`
- `timestamp: u64`

`trace_id` is propagated through sender/receiver events to support observability and relay tracing.
