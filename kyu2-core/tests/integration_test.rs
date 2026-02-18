use kyu2_core::{init, KyuPipeline, WirehairEncoder, WirehairDecoder};

#[test]
fn test_full_pipeline_round_trip() {
    // 0. Init
    init();

    // Data Setup
    let original_message = b"This is a test of the Kyu2 Emergency Broadcast System. This is only a test. Repeat: This is a test.";
    let block_id = 42;
    let secret_key = [0x77; 32]; // "Secure" key ;)
    let packet_size = 16; // Tiny packets to force FEC to work hard

    // --- SENDER SIDE ---

    // 1. Pipeline: Compress & Encrypt
    let mut sender_pipeline = KyuPipeline::new(&secret_key);
    let protected_blob = sender_pipeline.protect_block(original_message, block_id).expect("Pipeline failed");

    println!("Original Size: {}", original_message.len());
    println!("Protected Size: {}", protected_blob.len());

    // 2. FEC: Encode
    // We treat the 'protected_blob' as the message we want to send over Wirehair
    let encoder = WirehairEncoder::new(&protected_blob, packet_size).expect("Encoder init failed");
    
    // Generate packets. We need N packets + maybe 1 or 2 repair packets.
    // Let's drop packet #2 and #4 to simulate network loss.
    let mut sent_packets = Vec::new();
    let num_packets_needed = (protected_blob.len() as u32 + packet_size - 1) / packet_size;
    
    for i in 0..(num_packets_needed + 5) {
        if i == 2 || i == 4 { continue; } // SIMULATE PACKET LOSS
        let pkt = encoder.encode(i).expect("Encoding failed");
        sent_packets.push((i, pkt));
    }

    // --- RECEIVER SIDE ---

    // 3. FEC: Decode
    let mut decoder = WirehairDecoder::new(protected_blob.len() as u64, packet_size).expect("Decoder init failed");
    let mut recovered_blob = Vec::new();

    for (seq_id, data) in sent_packets {
        let is_complete = decoder.decode(seq_id, &data).expect("Decode error");
        if is_complete {
            recovered_blob = decoder.recover().expect("Recover error");
            break;
        }
    }

    assert!(!recovered_blob.is_empty(), "Failed to recover blob via FEC");
    assert_eq!(recovered_blob, protected_blob, "FEC recovery mismatch!");

    // 4. Pipeline: Decrypt & Decompress
    let receiver_pipeline = KyuPipeline::new(&secret_key);
    let final_message = receiver_pipeline.restore_block(&recovered_blob, block_id).expect("Restore failed");

    // 5. Verify
    assert_eq!(final_message, original_message);
    println!("Success! Recovered: {:?}", String::from_utf8_lossy(&final_message));
}
