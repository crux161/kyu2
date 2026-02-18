# Kyu2: Zen-Mode UDP Transport Protocol

**Kyu2** is a next-generation, high-performance reliable UDP transport protocol designed for the **Nomikai** project. It combines modern cryptography, fountain codes, and compression into a single "Zero-State" pipeline.

> *"The Master does nothing, yet he leaves nothing undone"*

![Happy Lunar New Year!](images/2026LNY.png)


## 🌊 Architecture

Kyu2 uses a unique "Squeeze, Seal, & Spray" pipeline to ensure data integrity and confidentiality over unreliable networks.

```mermaid
graph LR
    A[Raw Data] -->|Zstd| B(Compressed)
    B -->|ChaCha20-Poly1305| C(Encrypted Blob)
    C -->|Wirehair FEC| D{Droplets}
    D -->|QUIC-Style XOR Mask| E(Obfuscated Header)
    E -->|1400B Padding| F[UDP Blast]
```

1.  **Compression (Squeeze):** Data is compressed using Zstandard (tANS).
2.  **Encryption (Seal):** Authenticated encryption via ChaCha20-Poly1305 using an X25519 ephemeral shared secret.
3.  **Forward Error Correction (Spray):** Data is encoded using **Wirehair** (O(N) Fountain Code), allowing recovery from any subset of packets.
4.  **Header Protection (Mask):** The packet geometry is XOR-masked using a dynamic nonce derived from the encrypted payload, preventing stream tracking.
5.  **Traffic Obfuscation:** Every network packet is padded to exactly 1400 bytes. An observer cannot distinguish between file transfers, handshakes, or silence.

---

## 🚀 Features

* **Multiplexing:** Send hundreds of files simultaneously over a single UDP port. Head-of-Line (HoL) blocking is mathematically eliminated.
* **1-RTT Handshake:** Ephemeral X25519 key exchange establishes forward secrecy before any data flows.
* **Self-Healing Mesh:** Intermediate relay nodes can recover and mathematically regenerate fresh packets for destination nodes.
* **Adversarial Resistance:** Packet sizes are static (1400B), and sequence numbers are encrypted.
* **Stateless Decoding:** Every packet contains enough masked geometry to initialize a decoder.

---

## 🛠️ Installation & Usage

Ensure you have Rust and Cargo installed.

```bash
cargo build --release -p kyu2-cli
```

**Receiver (Listen on Port 8080):**
```bash
./target/release/kyu2-cli recv --bind 0.0.0.0:8080 --out-dir ./downloads
```

**Sender (Send a file):**
```bash
./target/release/kyu2-cli send my_video.mp4 --dest 127.0.0.1:8080
```

---

## 📦 Project Structure

* `kyu2-core`: The safe Rust library exposing a clean, event-driven API (`KyuSender` / `KyuReceiver`). Ready for GUI integration.
* `kyu2-cli`: The command-line interface driver.
* `kyu2-wirehair-sys`: Low-level C++ bindings to the Wirehair FEC engine.

## 📜 License

MIT License. See `LICENSE` for details.
