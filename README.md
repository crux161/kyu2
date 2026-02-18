# Kyu2: Zen-Mode UDP Transport Protocol

**Kyu2** is a next-generation, high-performance reliable UDP transport protocol designed for the **Nomikai** project. It combines modern cryptography, fountain codes, and compression into a single "Zero-State" pipeline.

> *"The Master does nothing, yet he leaves nothing undone"*

![Happy Lunar New Year!](images/2026LNY.png)


## 🌊 Architecture

Kyu2 uses a unique "Squeeze, Seal, & Spray" pipeline to ensure data integrity and confidentiality over unreliable networks.

```
graph LR
    A[Raw Data] -->|Zstd (tANS)| B(Compressed Block)
    B -->|ChaCha20-Poly1305| C(Encrypted Blob)
    C -->|Wirehair FEC| D{Droplets}
    D -->|UDP Blast| E[Network]
```

1.  **Compression (Squeeze):** Data is compressed using Zstandard (tANS) to maximize throughput.
2.  **Encryption (Seal):** Data is authenticated and encrypted using ChaCha20-Poly1305. The Block ID serves as the Nonce, eliminating IV overhead.
3.  **Forward Error Correction (Spray):** The blob is encoded using **Wirehair** (O(N) Fountain Code). This allows the receiver to recover the file from *any* subset of packets, regardless of loss.

---

## 🚀 Features

* **Self-Healing Mesh:** Includes a `Relay` mode. Intermediate nodes recover the file and mathematically regenerate *fresh* packets to forward to the destination.
* **Dynamic Geometry:** Automatically adjusts packet sizes (43 bytes to 1400 bytes) based on payload size to satisfy FEC requirements.
* **Stateless Header:** Every packet contains the geometry needed to decode it. No handshakes required.
* **Zero-Copy Design:** Built on `kyu2-core`, designed for integration into GUI applications.

---

## 🛠️ Installation

Ensure you have Rust and Cargo installed.

```bash
# Build the CLI tool
cargo build --release -p kyu2-cli

# The binary will be at:
./target/release/kyu2-cli
```

---

## 📖 Usage

### 1. Simple File Transfer

**Receiver (Window 1):**
```bash
# Listen on port 8080 and save to output.txt
./kyu2-cli recv --bind 0.0.0.0:8080 -o output.txt
```

**Sender (Window 2):**
```bash
# Send a file to localhost:8080
./kyu2-cli send my_file.txt --dest 127.0.0.1:8080
```

### 2. The "Nano-P2P" Relay (Mesh Mode)

Kyu2 supports chaining nodes. If the link between A and C is weak, you can place B in the middle. B will recover the file and generate *new* repair packets for C.

**Node C (Destination):**
```bash
./kyu2-cli recv --bind 0.0.0.0:9090 -o final.txt
```

**Node B (The Relay):**
```bash
# Receives on 8080, saves a local copy, and relays to 9090
./kyu2-cli recv --bind 0.0.0.0:8080 -o relay_copy.txt --relay 127.0.0.1:9090
```

**Node A (Source):**
```bash
# Sends to the Relay (B)
./kyu2-cli send my_file.txt --dest 127.0.0.1:8080
```

---

## 🧬 Protocol Specification

Kyu2 uses a custom 18-byte header for every UDP packet to ensure stateless decoding.

| Offset | Type | Field | Description |
| :--- | :--- | :--- | :--- |
| 0 | `u64` | **Block ID** | Monotonically increasing ID for the file chunk. |
| 8 | `u32` | **Seq ID** | The "Droplet" ID. 0..N are systematic, N+ are repair. |
| 12 | `u32` | **Total Size** | The total size of the encrypted blob for this block. |
| 16 | `u16` | **Pkt Size** | The size of each individual droplet (payload). |
| 18 | `[u8]` | **Payload** | The Wirehair encoded data. |

---

## 📦 Project Structure

* `kyu2-core`: The safe Rust API. Handles the Pipeline and FEC logic.
* `kyu2-cli`: The command-line interface application.
* `kyu2-wirehair-sys`: Low-level C++ bindings to the Wirehair library (O(N) Fountain Code).

## 📜 License

MIT License. See `LICENSE` for details.
