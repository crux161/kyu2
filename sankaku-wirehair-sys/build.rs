use std::env;
use std::path::PathBuf;

fn main() {
    // 1. Define the C++ source files
    let cpp_sources = [
        "wirehair/wirehair.cpp",
        "wirehair/WirehairCodec.cpp",
        "wirehair/WirehairTools.cpp",
        "wirehair/gf256.cpp",
    ];

    // 2. Track changes so Cargo rebuilds if C++ code changes
    for src in &cpp_sources {
        println!("cargo:rerun-if-changed={}", src);
    }
    // Track the header in its NEW location
    println!("cargo:rerun-if-changed=wirehair/wirehair.h");

    // 3. Compile the C++ library
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .std("c++11")
        .flag("-O3")
        .flag_if_supported("-mavx2")
        .flag_if_supported("-mssse3")
        .include(".")
        .files(cpp_sources)
        .compile("wirehair");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "macos" || target_os == "ios" {
        println!("cargo:rustc-link-lib=c++");
    } else if target_os != "windows" {
        println!("cargo:rustc-link-lib=stdc++");
    }

    // 4. Generate Rust bindings
    // Get the absolute path to the header file
    let root_dir = env::var("CARGO_MANIFEST_DIR").expect("Could not get manifest dir");
    // CRITICAL FIX: Point to the new location (wirehair/wirehair.h)
    let header_path = PathBuf::from(&root_dir).join("wirehair").join("wirehair.h");

    if !header_path.exists() {
        panic!("Header file not found at: {:?}", header_path);
    }

    let bindings = bindgen::Builder::default()
        .header(header_path.to_str().expect("Path is not valid UTF-8"))
        // Tell clang to look in the root dir too, just in case the header has imports
        .clang_arg(format!("-I{}", root_dir))
        .allowlist_function("wirehair_.*")
        .allowlist_type("Wirehair.*")
        .allowlist_var("Wirehair.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    // 5. Write bindings to the $OUT_DIR
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
