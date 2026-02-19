use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn collect_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let Some(name) = path.file_name().and_then(|part| part.to_str()) else {
                continue;
            };
            if matches!(
                name,
                "test" | "tests" | "example" | "examples" | "bench" | "benches" | "target"
            ) {
                continue;
            }
            collect_sources(&path, out);
            continue;
        }

        let Some(ext) = path.extension().and_then(|part| part.to_str()) else {
            continue;
        };
        if matches!(ext, "c" | "cc" | "cpp" | "cxx") {
            out.push(path);
        }
    }
}

fn library_name_from_file(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    if let Some(stripped) = name
        .strip_prefix("lib")
        .and_then(|value| value.strip_suffix(".a"))
    {
        return Some(stripped.to_string());
    }
    if let Some(stripped) = name.strip_suffix(".lib") {
        return Some(stripped.to_string());
    }
    None
}

fn emit_cmake_linking(openzl_dir: &Path) -> bool {
    if !openzl_dir.join("CMakeLists.txt").exists() {
        return false;
    }

    let out_dir = PathBuf::from(
        env::var("OUT_DIR").expect("OUT_DIR should always be set by Cargo build scripts"),
    );
    let build_dir = out_dir.join("openzl-cmake-build");
    let install_dir = out_dir.join("openzl-cmake-install");
    if fs::create_dir_all(&build_dir).is_err() || fs::create_dir_all(&install_dir).is_err() {
        println!("cargo:warning=OpenZL: failed to create CMake build/install directories");
        return false;
    }

    let configure_ok = Command::new("cmake")
        .arg("-S")
        .arg(openzl_dir)
        .arg("-B")
        .arg(&build_dir)
        .arg("-DBUILD_SHARED_LIBS=OFF")
        .arg("-DBUILD_TESTING=OFF")
        .arg("-DCMAKE_BUILD_TYPE=Release")
        .arg(format!(
            "-DCMAKE_INSTALL_PREFIX={}",
            install_dir.to_string_lossy()
        ))
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !configure_ok {
        println!("cargo:warning=OpenZL: CMake configure failed, falling back to cc");
        return false;
    }

    let build_ok = Command::new("cmake")
        .arg("--build")
        .arg(&build_dir)
        .arg("--config")
        .arg("Release")
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !build_ok {
        println!("cargo:warning=OpenZL: CMake build failed, falling back to cc");
        return false;
    }

    let _ = Command::new("cmake")
        .arg("--install")
        .arg(&build_dir)
        .arg("--config")
        .arg("Release")
        .status();

    let mut candidates = Vec::new();
    for dir in [
        install_dir.join("lib"),
        install_dir.join("lib64"),
        build_dir.join("lib"),
        build_dir.join("lib64"),
        build_dir.join("src"),
        build_dir.join("build"),
        build_dir.join("build/lib"),
        build_dir.join("build/lib64"),
        build_dir.join("build/src"),
    ] {
        if dir.exists() {
            println!("cargo:rustc-link-search=native={}", dir.display());
            candidates.push(dir);
        }
    }

    for dir in candidates {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(stem) = library_name_from_file(&path) else {
                continue;
            };
            if stem.starts_with("openzl") {
                println!("cargo:rustc-link-lib=static={stem}");
                return true;
            }
        }
    }

    // Conservative fallback when CMake output name is not discoverable.
    println!("cargo:rustc-link-lib=static=openzl");
    true
}

fn emit_cc_linking(openzl_dir: &Path) {
    let mut sources = Vec::new();
    collect_sources(openzl_dir, &mut sources);
    sources.sort();
    if sources.is_empty() {
        panic!(
            "No OpenZL C/C++ sources found under {}",
            openzl_dir.display()
        );
    }

    let has_cpp = sources.iter().any(|path| {
        matches!(
            path.extension().and_then(|part| part.to_str()),
            Some("cc" | "cpp" | "cxx")
        )
    });

    let mut build = cc::Build::new();
    build.include(openzl_dir);
    let include_dir = openzl_dir.join("include");
    if include_dir.exists() {
        build.include(include_dir);
    }
    if has_cpp {
        build.cpp(true);
        build.flag_if_supported("-std=c++17");
    }

    for source in sources {
        println!("cargo:rerun-if-changed={}", source.display());
        build.file(source);
    }
    build.compile("openzl");
}

fn main() {
    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR should always be set by Cargo build scripts"),
    );
    let openzl_dir = manifest_dir.join("openzl");
    if !openzl_dir.exists() {
        panic!(
            "Missing OpenZL source tree at {} (expected vendor/submodule checkout)",
            openzl_dir.display()
        );
    }

    println!("cargo:rerun-if-changed={}", openzl_dir.display());
    if !emit_cmake_linking(&openzl_dir) {
        emit_cc_linking(&openzl_dir);
    }
}
