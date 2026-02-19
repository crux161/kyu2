#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        unsafe {
            // 1. FIX: Call the actual function 'wirehair_init_' (note the underscore)
            // We pass '2' manually because WIREHAIR_VERSION is a #define macro we can't see easily yet.
            let init_result = wirehair_init_(2);

            // 2. FIX: Check against the generated Enum constant
            // bindgen usually prefixes enum variants with the Enum Name
            assert_eq!(
                init_result, WirehairResult_t_Wirehair_Success,
                "Wirehair init failed"
            );

            // Basic check: Create an encoder
            let message = "Hello Wirehair";
            let packet_size = 4;
            let encoder = wirehair_encoder_create(
                std::ptr::null_mut(), // reuseOpt
                message.as_ptr() as *const _,
                message.len() as u64,
                packet_size as u32,
            );

            assert!(!encoder.is_null(), "Encoder creation failed");

            wirehair_free(encoder);
        }
    }
}
