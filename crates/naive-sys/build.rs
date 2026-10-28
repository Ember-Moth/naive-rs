use sha2::{Digest, Sha256};
use std::{env, fs, io, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=NAIVE_NATIVE_DIR");
    let target = env::var("TARGET").unwrap();
    if target.ends_with("windows-msvc") {
        let features = env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
        assert!(
            features.split(',').any(|feature| feature == "crt-static"),
            "native Windows library uses /MT; enable -C target-feature=+crt-static in the consuming Cargo workspace"
        );
    }
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("../..");
    let dir = env::var_os("NAIVE_NATIVE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target/native/lib").join(&target));
    let manifest_path = dir.join("manifest.json");
    println!("cargo:rerun-if-changed={}", manifest_path.display());
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap_or_else(|_| {
        panic!("native artifact missing for {target}. Run `cargo xtask toolchain --target {target}` then `cargo xtask build --target {target}`, or set NAIVE_NATIVE_DIR")
    })).expect("invalid native manifest");
    assert_eq!(
        manifest["target"].as_str(),
        Some(target.as_str()),
        "native target mismatch"
    );
    assert_eq!(manifest["abi"].as_u64(), Some(6), "native ABI mismatch");
    assert_eq!(
        manifest["wrapper_version"].as_str(),
        Some(env!("CARGO_PKG_VERSION")),
        "native wrapper version mismatch"
    );
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("native-version.json")).unwrap();
    assert_eq!(
        manifest["upstream"]["commit"], expected["upstream_commit"],
        "native upstream version mismatch"
    );
    let archive_name = if target.contains("windows-msvc") {
        "naive_native.lib"
    } else {
        "libnaive_native.a"
    };
    let archive = dir.join(archive_name);
    println!("cargo:rerun-if-changed={}", archive.display());
    let mut hash = Sha256::new();
    io::copy(
        &mut fs::File::open(&archive).expect("native archive missing"),
        &mut hash,
    )
    .unwrap();
    assert_eq!(
        manifest["archive_sha256"].as_str(),
        Some(format!("{:x}", hash.finalize()).as_str()),
        "native archive checksum mismatch"
    );
    // In a source checkout, reject stale patched/native sources. Installed binary
    // distributions still validate ABI, target and archive digest above.
    if root.join("upstream.lock.json").exists() {
        let mut inputs = vec![root.join("upstream.lock.json"), root.join("patches/series")];
        let series = fs::read_to_string(root.join("patches/series")).unwrap();
        inputs.extend(
            series
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty() && !s.starts_with('#'))
                .map(|s| root.join("patches").join(s)),
        );
        let mut build_sources = Vec::new();
        collect(&root.join("xtask/src"), &mut build_sources);
        build_sources.sort();
        inputs.extend(build_sources);
        let mut native = Vec::new();
        collect(&root.join("native"), &mut native);
        native.sort();
        inputs.extend(native);
        let mut hash = Sha256::new();
        for path in inputs {
            println!("cargo:rerun-if-changed={}", path.display());
            hash.update(
                path.strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
                    .as_bytes(),
            );
            let bytes = fs::read(path).unwrap();
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        }
        assert_eq!(
            manifest["fingerprint"].as_str(),
            Some(format!("{:x}", hash.finalize()).as_str()),
            "native sources or patches changed; rebuild with cargo xtask build"
        );
    }
    // This is metadata for embedding applications: rustc-link-arg does not
    // propagate from an rlib dependency to the final application linker.
    if target.contains("apple") {
        println!("cargo:required_link_args=-Wl,-ObjC");
    }
    println!("cargo:rustc-link-search=native={}", dir.display());
    println!("cargo:rustc-link-lib=static=naive_native");
    for library in manifest["libs"].as_array().expect("missing system libs") {
        let library = library.as_str().unwrap();
        assert!(valid_link_name(library), "invalid native library name");
        let library = if target.contains("windows-msvc") {
            library.trim_end_matches(".lib")
        } else {
            library
        };
        println!("cargo:rustc-link-lib={library}");
    }
    for framework in manifest["frameworks"]
        .as_array()
        .expect("missing frameworks")
    {
        let framework = framework.as_str().unwrap();
        assert!(valid_link_name(framework), "invalid native framework name");
        println!(
            "cargo:rustc-link-lib=framework={}",
            framework.trim_end_matches(".framework")
        );
    }
}

fn collect(dir: &std::path::Path, paths: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.file_name().unwrap() == ".DS_Store" {
            continue;
        }
        if path.is_dir() {
            collect(&path, paths);
        } else {
            paths.push(path);
        }
    }
}

fn valid_link_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_+.-".contains(&c))
}
