## 🧬 Kyu2 Wire Format (v1.1)

The protocol is designed to be **stateless** and **atomic**. Every UDP packet contains enough geometry to initialize a decoder without a back-and-forth handshake.

### **1. The UDP Packet Layout**

Every packet sent over the wire follows this 18-byte header structure, followed by the Variable Length Payload (VLP).

| Offset | Type | Field | Description |
| --- | --- | --- | --- |
| **0** | `u64` | **Block ID** | The chunk index. **Block 0** is reserved for the `SessionManifest`. |
| **8** | `u32` | **Seq ID** | The FEC droplet index.  are systematic;  are repair. |
| **12** | `u32` | **Total Size** | Total bytes of the *encrypted blob* for this specific Block ID. |
| **16** | `u16` | **Pkt Size** | The size of each FEC droplet (Geometry). |
| **18** | `[u8]` | **Payload** | The raw Wirehair-encoded data. |

---

### **2. Logical Mapping**

The protocol operates in two distinct phases based on the **Block ID**.

#### **Phase A: The Manifest (Block 0)**

The payload of Block 0, once recovered and decrypted, is a **Bincode-serialized** `SessionManifest`.

* **Filename:** UTF-8 String.
* **File Size:** `u64` (Total bytes of the actual file).
* **Timestamp:** `u64` (Unix epoch).

#### **Phase B: The Data Stream (Blocks 1..N)**

All subsequent Block IDs contain the raw bytes of the file, processed through the **Kyu Pipeline**.

---

### **3. The Security Layer (Kyu Pipeline)**

Before data enters the Wirehair encoder, it is transformed by the pipeline. The receiver must reverse this after FEC recovery.

1. **Compression:** `Zstd (tANS)` - Reduces entropy and size.
2. **Encryption:** `ChaCha20-Poly1305` - Authenticated encryption.
* **Key:** 32-byte shared secret.
* **Nonce:** 12 bytes. Composed of `[0u8; 4]` + `BlockID` (8 bytes).
* **AAD:** The `BlockID` is passed as Additional Authenticated Data to prevent "Block Swapping" attacks.



---

### **4. FEC Geometry Constraints**

To ensure the **Wirehair** engine functions correctly:

* **N ≥ 2:** If the encrypted blob size is less than or equal to the `TARGET_PACKET_SIZE` (1400 bytes), the `Pkt Size` is automatically halved to force at least two packets.
* **Alignment:** The `Total Size` in the header is the size of the *protected blob*, not the original raw data. The receiver uses this exact value to initialize `WirehairDecoder`.

