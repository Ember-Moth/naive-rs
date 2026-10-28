mod artifact;
mod platform;
use sha2::{Digest, Sha256};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
struct BuildLock(PathBuf);
impl Drop for BuildLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("xtask: {error}");
        std::process::exit(1);
    }
}

fn command(cwd: &Path, program: &str, args: &[&str]) -> Command {
    let mut command = Command::new(program);
    command.current_dir(cwd).args(args);
    command
}

fn checked(mut command: Command) -> Result<()> {
    if !command.status()?.success() {
        return Err(format!("command failed: {command:?}").into());
    }
    Ok(())
}

fn output(mut command: Command) -> Result<String> {
    let result = command.output()?;
    if !result.status.success() {
        return Err(format!("{command:?}: {}", String::from_utf8_lossy(&result.stderr)).into());
    }
    Ok(String::from_utf8(result.stdout)?.trim().to_owned())
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_owned()
}

fn patch_names(root: &Path) -> Result<Vec<String>> {
    let series = fs::read_to_string(root.join("patches/series"))?;
    let names: Vec<_> = series
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .map(str::to_owned)
        .collect();
    for name in &names {
        if name.contains('/') || name.contains('\\') || !name.ends_with(".patch") {
            return Err(format!("invalid patch name: {name}").into());
        }
    }
    Ok(names)
}

fn files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.file_name().unwrap() == ".DS_Store" {
            continue;
        }
        if path.is_dir() {
            result.extend(files(&path)?);
        } else {
            result.push(path);
        }
    }
    result.sort();
    Ok(result)
}

fn hash_inputs(root: &Path, native: bool) -> Result<String> {
    let mut hash = Sha256::new();
    let mut inputs = vec![root.join("upstream.lock.json"), root.join("patches/series")];
    inputs.extend(
        patch_names(root)?
            .iter()
            .map(|name| root.join("patches").join(name)),
    );
    if native {
        inputs.extend(files(&root.join("xtask/src"))?);
        inputs.extend(files(&root.join("native"))?);
    }
    for path in inputs {
        hash.update(
            path.strip_prefix(root)?
                .to_string_lossy()
                .replace('\\', "/")
                .as_bytes(),
        );
        let bytes = fs::read(path)?;
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn prepare(root: &Path, force_check: bool) -> Result<PathBuf> {
    let lock: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("upstream.lock.json"))?)?;
    let commit = lock["commit"].as_str().ok_or("missing upstream commit")?;
    let sub = root.join("vendor/naiveproxy");
    if !sub.join("src/BUILD.gn").exists() {
        return Err("initialize sources with: git submodule update --init --recursive".into());
    }
    if output(command(&sub, "git", &["rev-parse", "HEAD"]))? != commit {
        return Err("submodule HEAD differs from upstream.lock.json".into());
    }
    checked(command(&sub, "git", &["diff", "--exit-code", "--quiet"]))?;
    checked(command(
        &sub,
        "git",
        &["diff", "--cached", "--exit-code", "--quiet"],
    ))?;
    let host_key = format!("{}-{}", env::consts::OS, env::consts::ARCH);
    let parent = root.join("target/native/source").join(&host_key);
    fs::create_dir_all(&parent)?;
    let dest = parent.join(hash_inputs(root, false)?);
    if !dest.join(".prepared").exists() || force_check {
        let staging = parent.join(format!("preparing-{}", std::process::id()));
        if staging.exists() {
            return Err(format!("stale preparation directory: {}", staging.display()).into());
        }
        fs::create_dir(&staging)?;
        let result = (|| -> Result<()> {
            let mut archive = command(&sub, "git", &["archive", commit])
                .stdout(Stdio::piped())
                .spawn()?;
            let mut tar = command(&staging, "tar", &["xf", "-"]);
            tar.stdin(archive.stdout.take().unwrap());
            let extract_result = checked(tar);
            let archive_status = archive.wait()?;
            extract_result?;
            if !archive_status.success() {
                return Err("git archive failed".into());
            }
            checked(command(&staging, "git", &["init", "-q"]))?;
            for name in patch_names(root)? {
                let patch = root.join("patches").join(&name);
                eprintln!("Applying {name}");
                checked(command(
                    &staging,
                    "git",
                    &["apply", "--check", patch.to_str().unwrap()],
                ))?;
                checked(command(
                    &staging,
                    "git",
                    &["apply", patch.to_str().unwrap()],
                ))?;
            }
            fs::write(staging.join(".prepared"), commit)?;
            Ok(())
        })();
        if result.is_err() || force_check {
            fs::remove_dir_all(&staging)?;
            result?;
            if force_check {
                return Ok(dest);
            }
        } else {
            fs::rename(staging, &dest)?;
        }
    }
    let overlay = dest.join("src/naive_rs");
    fs::create_dir_all(&overlay)?;
    for path in files(&root.join("native"))? {
        let to = overlay.join(path.strip_prefix(root.join("native"))?);
        fs::create_dir_all(to.parent().unwrap())?;
        let bytes = fs::read(&path)?;
        if fs::read(&to).ok().as_deref() != Some(bytes.as_slice()) {
            fs::write(to, bytes)?;
        }
    }
    // Toolchains are shared across patch revisions of the same upstream commit.
    // The source checkout and all downloads still stay under target/.
    let cache = root
        .join("target/native/toolchains")
        .join(&host_key)
        .join(commit);
    for relative in [
        "third_party/llvm-build/Release+Asserts",
        "gn",
        "chrome/build/pgo_profiles",
        "out/sysroot-build",
    ] {
        let link = dest.join("src").join(relative);
        let cached = cache.join(relative);
        #[cfg(windows)]
        if junction::exists(&link)? {
            continue;
        }
        if link
            .symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            continue;
        }
        fs::create_dir_all(cached.parent().unwrap())?;
        if link.exists() {
            if cached.exists() {
                return Err(
                    format!("both source and cached toolchain exist: {}", link.display()).into(),
                );
            }
            fs::rename(&link, &cached)?;
        } else {
            fs::create_dir_all(&cached)?;
        }
        fs::create_dir_all(link.parent().unwrap())?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(&cached, &link)?;
        #[cfg(windows)]
        junction::create(&cached, &link)?;
    }
    Ok(dest)
}

fn description(src: &Path, out: &str, what: &str) -> Result<Vec<String>> {
    let text = output(command(
        src,
        "./gn/out/gn",
        &["desc", out, "//naive_rs:link_probe", what, "--format=json"],
    ))?;
    let value: serde_json::Value = serde_json::from_str(&text)?;
    Ok(serde_json::from_value(
        value["//naive_rs:link_probe"][what].clone(),
    )?)
}

fn run() -> Result<()> {
    let root = root();
    let args: Vec<String> = env::args().skip(1).collect();
    let action = args.first().map(String::as_str).unwrap_or("help");
    if action == "targets" {
        for platform in platform::PLATFORMS {
            println!("{} ({}/{})", platform.target, platform.os, platform.cpu);
        }
        return Ok(());
    }
    let version: serde_json::Value = serde_json::from_slice(&fs::read(
        root.join("crates/naive-sys/native-version.json"),
    )?)?;
    let pinned: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("upstream.lock.json"))?)?;
    if version["abi"] != pinned["abi"] || version["upstream_commit"] != pinned["commit"] {
        return Err("naive-sys/native-version.json differs from upstream.lock.json".into());
    }
    if matches!(action, "package" | "fetch") {
        return artifact::run(&args);
    }
    let mut target = output(command(&root, "rustc", &["-vV"]))?
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .unwrap()
        .to_owned();
    let mut jobs = "8".to_owned();
    let mut native_profile = "portable".to_owned();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--target" | "--jobs" | "--native-profile" if i + 1 < args.len() => {
                if args[i] == "--target" {
                    target = args[i + 1].clone();
                } else if args[i] == "--jobs" {
                    jobs = args[i + 1].clone();
                } else {
                    native_profile = args[i + 1].clone();
                }
                i += 2;
            }
            arg => return Err(format!("unknown/incomplete argument: {arg}").into()),
        }
    }
    if action == "help" {
        println!(
            "cargo xtask <prepare|check-patches|toolchain|build|fingerprint|targets> [--target TRIPLE] [--jobs N] [--native-profile portable|pgo]\n\
             cargo xtask package --target TRIPLE [--native-dir DIR] [--output ARCHIVE]\n\
             cargo xtask fetch --target TRIPLE --url HTTPS_URL --sha256 DIGEST [--destination DIR] [--replace]"
        );
        return Ok(());
    }
    if action == "fingerprint" {
        println!("{}", hash_inputs(&root, true)?);
        return Ok(());
    }
    if !["prepare", "check-patches", "toolchain", "build"].contains(&action) {
        return Err("unknown action".into());
    }
    if !["portable", "pgo"].contains(&native_profile.as_str()) {
        return Err("native profile must be portable or pgo".into());
    }
    fs::create_dir_all(root.join("target/native"))?;
    let lock_path = root.join("target/native/.lock");
    let mut lock_file = fs::OpenOptions::new().write(true).create_new(true).open(&lock_path)
        .map_err(|error| format!("cannot acquire {}: {error}; another xtask may be running (inspect the recorded PID before removing a stale lock)", lock_path.display()))?;
    std::io::Write::write_all(&mut lock_file, std::process::id().to_string().as_bytes())?;
    let _build_lock = BuildLock(lock_path);
    let build_fingerprint = hash_inputs(&root, true)?;
    let platform = platform::Platform::parse(&target)?;
    platform.host_check()?;
    let os = platform.os;
    let source = prepare(&root, action == "check-patches")?;
    if action == "check-patches" {
        eprintln!("Patch queue applies cleanly to the pinned commit");
        return Ok(());
    }
    if action == "prepare" {
        println!("{}", source.display());
        return Ok(());
    }
    let src = source.join("src");
    if action == "toolchain" {
        platform::toolchain(&src, platform, &native_profile)?;
        return Ok(());
    }
    if os == "android" {
        platform::prepare_android(&src)?;
    }
    let exe = if cfg!(windows) { ".exe" } else { "" };
    let gn = format!("./gn/out/gn{exe}");
    if !src.join(format!("gn/out/gn{exe}")).exists()
        || !src
            .join(format!(
                "third_party/llvm-build/Release+Asserts/bin/clang{exe}"
            ))
            .exists()
    {
        return Err("native toolchain missing; run cargo xtask toolchain first".into());
    }
    let suffix = if native_profile == "portable" {
        String::new()
    } else {
        format!("-{native_profile}")
    };
    let out = format!("out/naive-rs-{target}{suffix}");
    let mut gn_args = fs::read_to_string(root.join("native/args.gn"))?;
    gn_args.push_str(&platform.args());
    if native_profile == "pgo" {
        gn_args.push_str("chrome_pgo_phase = 2\n");
    }
    fs::create_dir_all(src.join(&out))?;
    fs::write(src.join(&out).join("args.gn"), &gn_args)?;
    let mut generate = command(&src, &gn, &["gen", &out, "--fail-on-unused-args"]);
    generate.env("DEPOT_TOOLS_WIN_TOOLCHAIN", "0");
    checked(generate)?;
    checked(command(
        &src,
        "ninja",
        &["-C", &out, "-j", &jobs, "naive_native", "link_probe"],
    ))?;
    if hash_inputs(&root, true)? != build_fingerprint {
        return Err("native inputs changed during compilation; rerun cargo xtask build".into());
    }
    let mut dest = root.join("target/native/lib").join(&target);
    if native_profile != "portable" {
        dest = dest.join(&native_profile);
    }
    fs::create_dir_all(&dest)?;
    let archive = src.join(&out).join("obj/naive_rs").join(platform.archive());
    fs::copy(&archive, dest.join(platform.archive()))?;
    let mut hasher = Sha256::new();
    let mut file = fs::File::open(&archive)?;
    io::copy(&mut file, &mut hasher)?;
    let libs = description(&src, &out, "libs")?;
    let frameworks = if os == "mac" || os == "ios" {
        description(&src, &out, "frameworks")?
    } else {
        Vec::new()
    };
    let manifest = serde_json::json!({
        "abi": 3, "target": target, "fingerprint": build_fingerprint,
        "native_profile": native_profile, "gn_args": gn_args,
        "archive": platform.archive(), "platform": platform::details(&src, platform)?,
        "wrapper_version": env!("CARGO_PKG_VERSION"),
        "build_host": format!("{}-{}", env::consts::OS, env::consts::ARCH),
        "consumer_link_args": if matches!(os,"mac"|"ios") { vec!["-Wl,-ObjC"] } else { vec![] },
        "clang_revision": fs::read_to_string(src.join("third_party/llvm-build/Release+Asserts/cr_build_revision"))?.trim(),
        "archive_sha256": format!("{:x}", hasher.finalize()),
        "libs": libs, "frameworks": frameworks,
        "upstream": serde_json::from_slice::<serde_json::Value>(&fs::read(root.join("upstream.lock.json"))?)?,
    });
    fs::write(
        dest.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    println!("Native library ready: {}", dest.display());
    Ok(())
}
