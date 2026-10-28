use crate::{Result, checked, command, files, hash_inputs, platform::Platform, root};
use flate2::{Compression, GzBuilder, read::GzDecoder};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Write},
    path::{Component, Path, PathBuf},
};

const MAX_ARCHIVE: u64 = 512 * 1024 * 1024;
const MAX_UNPACKED: u64 = 1024 * 1024 * 1024;

fn digest(path: &Path) -> Result<String> {
    let mut hash = Sha256::new();
    io::copy(&mut fs::File::open(path)?, &mut hash)?;
    Ok(format!("{:x}", hash.finalize()))
}
fn safe_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
        && path
            .to_str()
            .is_some_and(|s| !s.contains('\\') && s.len() < 4096)
}
fn verify_manifest(
    root: &Path,
    manifest: &serde_json::Value,
    target: Platform,
    profile: &str,
) -> Result<()> {
    let expected: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("upstream.lock.json"))?)?;
    if manifest["abi"] != expected["abi"] || manifest["upstream"]["commit"] != expected["commit"] {
        return Err("artifact ABI or upstream revision differs from this checkout".into());
    }
    if manifest["target"] != target.target
        || manifest["native_profile"] != profile
        || manifest["wrapper_version"] != env!("CARGO_PKG_VERSION")
    {
        return Err("artifact target, profile or wrapper version mismatch".into());
    }
    if manifest["fingerprint"] != hash_inputs(root, true)? {
        return Err(
            "artifact source fingerprint mismatch; rebuild or use the matching source release"
                .into(),
        );
    }
    for field in ["libs", "frameworks"] {
        let names = manifest[field]
            .as_array()
            .ok_or("missing linker metadata")?;
        for name in names {
            let name = name.as_str().ok_or("non-string linker metadata")?;
            if name.is_empty()
                || name.len() > 128
                || name.starts_with('-')
                || !name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_+.-".contains(&c))
            {
                return Err("invalid linker metadata name".into());
            }
        }
    }
    if manifest["archive"] != target.archive() {
        return Err("unexpected native archive name".into());
    }
    Ok(())
}
fn append(builder: &mut tar::Builder<impl Write>, name: &str, path: &Path) -> Result<()> {
    let mut header = tar::Header::new_ustar();
    header.set_size(fs::metadata(path)?.len());
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    builder.append_data(&mut header, name, fs::File::open(path)?)?;
    Ok(())
}
fn licenses(root: &Path) -> Result<BTreeMap<String, PathBuf>> {
    let upstream = root.join("vendor/naiveproxy");
    let listed = crate::output(command(&upstream, "git", &["ls-files"]))?;
    let mut result = BTreeMap::new();
    for name in listed.lines() {
        let path = Path::new(name);
        let basename = path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_ascii_uppercase();
        if ["LICENSE", "COPYING", "NOTICE", "PATENTS", "AUTHORS"]
            .iter()
            .any(|prefix| basename.starts_with(prefix))
            || basename == "README.CHROMIUM"
        {
            let source = upstream.join(path);
            if !safe_path(path) || !source.symlink_metadata()?.is_file() {
                continue;
            }
            result.insert(format!("licenses/upstream/{name}"), source);
        }
    }
    if result.is_empty() {
        return Err("upstream license inventory is empty".into());
    }
    Ok(result)
}
fn package(
    root: &Path,
    target: Platform,
    profile: &str,
    native_dir: &Path,
    output: &Path,
) -> Result<()> {
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(native_dir.join("manifest.json"))?)?;
    verify_manifest(root, &manifest, target, profile)?;
    let library = native_dir.join(target.archive());
    if manifest["archive_sha256"] != digest(&library)? {
        return Err("native archive checksum mismatch".into());
    }
    let mut members = licenses(root)?;
    members.insert(target.archive().into(), library);
    members.insert("LICENSE".into(), root.join("LICENSE"));
    for file in files(&root.join("native/include"))? {
        members.insert(
            format!(
                "include/{}",
                file.strip_prefix(root.join("native/include"))?
                    .to_string_lossy()
                    .replace('\\', "/")
            ),
            file,
        );
    }
    let mut checksums = BTreeMap::new();
    for (name, path) in &members {
        checksums.insert(name.clone(), digest(path)?);
    }
    manifest["package_schema"] = 1.into();
    manifest["files"] = serde_json::to_value(checksums)?;
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    fs::create_dir_all(output.parent().ok_or("output has no parent")?)?;
    let temp = output.with_extension(format!("partial-{}", std::process::id()));
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    let result = (|| -> Result<()> {
        let encoder = GzBuilder::new()
            .mtime(0)
            .write(file, Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for (name, path) in &members {
            append(&mut builder, name, path)?;
        }
        let mut header = tar::Header::new_ustar();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        builder.append_data(&mut header, "manifest.json", bytes.as_slice())?;
        builder.into_inner()?.finish()?.sync_all()?;
        fs::rename(&temp, output)?;
        fs::write(
            output.with_extension("gz.sha256"),
            format!(
                "{}  {}\n",
                digest(output)?,
                output.file_name().unwrap().to_string_lossy()
            ),
        )?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result?;
    println!("Packaged {}", output.display());
    Ok(())
}

fn unpack(
    root: &Path,
    archive: &Path,
    target: Platform,
    profile: &str,
    destination: &Path,
    replace: bool,
) -> Result<()> {
    let parent = destination.parent().ok_or("destination has no parent")?;
    fs::create_dir_all(parent)?;
    let staging = parent.join(format!(".naive-install-{}", std::process::id()));
    fs::create_dir(&staging)?;
    let result = (|| -> Result<()> {
        let decoder = GzDecoder::new(fs::File::open(archive)?);
        let mut input = tar::Archive::new(decoder);
        let mut seen = BTreeSet::new();
        let mut total = 0u64;
        for entry in input.entries()?.raw(true) {
            let mut entry = entry?;
            let name = entry.path()?.into_owned();
            if !entry.header().entry_type().is_file()
                || !safe_path(&name)
                || !seen.insert(name.clone())
                || seen.len() > 10_000
            {
                return Err(
                    "artifact contains an unsafe, duplicate or excessive archive member".into(),
                );
            }
            total = total
                .checked_add(entry.size())
                .ok_or("archive size overflow")?;
            if total > MAX_UNPACKED {
                return Err("artifact unpacked size exceeds limit".into());
            }
            let output = staging.join(&name);
            fs::create_dir_all(output.parent().unwrap())?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)?;
            io::copy(&mut entry, &mut file)?;
        }
        let manifest_path = staging.join("manifest.json");
        if fs::metadata(&manifest_path)?.len() > 1024 * 1024 {
            return Err("artifact manifest exceeds limit".into());
        }
        let manifest: serde_json::Value = serde_json::from_slice(&fs::read(manifest_path)?)?;
        verify_manifest(root, &manifest, target, profile)?;
        if manifest["package_schema"] != 1 {
            return Err("unsupported artifact package schema".into());
        }
        let hashes = manifest["files"]
            .as_object()
            .ok_or("missing artifact file inventory")?;
        if hashes.len() + 1 != seen.len() {
            return Err("artifact file inventory does not match archive".into());
        }
        for required in [
            target.archive(),
            "LICENSE",
            "include/naive.h",
            "include/naive_network.h",
        ] {
            if !hashes.contains_key(required) {
                return Err(format!("artifact missing {required}").into());
            }
        }
        for (name, hash) in hashes {
            if !safe_path(Path::new(name))
                || !seen.contains(Path::new(name))
                || hash.as_str() != Some(&digest(&staging.join(name))?)
            {
                return Err(format!("artifact member checksum mismatch: {name}").into());
            }
        }
        if manifest["archive_sha256"] != digest(&staging.join(target.archive()))? {
            return Err("native library digest mismatch".into());
        }
        if destination.symlink_metadata().is_ok() {
            if !destination.symlink_metadata()?.is_dir() {
                return Err(
                    "artifact destination must be a directory, not a file or symlink".into(),
                );
            }
            if !replace {
                return Err(
                    "destination exists; use --replace for an explicit atomic replacement".into(),
                );
            }
            let installed: serde_json::Value = serde_json::from_slice(
                &fs::read(destination.join("manifest.json"))
                    .map_err(|_| "refusing to replace a directory without a native manifest")?,
            )?;
            if installed["target"] != target.target || installed["native_profile"] != profile {
                return Err("refusing to replace a different target/profile installation".into());
            }
            let backup = parent.join(format!(".naive-backup-{}", std::process::id()));
            if backup.exists() {
                return Err("stale install backup exists".into());
            }
            fs::rename(destination, &backup)?;
            if let Err(error) = fs::rename(&staging, destination) {
                fs::rename(&backup, destination)?;
                return Err(error.into());
            }
            fs::remove_dir_all(backup)?;
        } else {
            fs::rename(&staging, destination)?;
        }
        Ok(())
    })();
    if staging.exists() {
        fs::remove_dir_all(staging)?;
    }
    result
}

pub fn run(args: &[String]) -> Result<()> {
    let root = root();
    let action = args[0].as_str();
    let mut target = None;
    let mut native_dir = None;
    let mut output = None;
    let mut destination = None;
    let mut url = None;
    let mut expected = None;
    let mut profile = "portable".to_owned();
    let mut replace = false;
    let mut allow_http = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--replace" => {
                replace = true;
                i += 1;
            }
            "--allow-http" => {
                allow_http = true;
                i += 1;
            }
            name if i + 1 < args.len() => {
                let value = args[i + 1].clone();
                match name {
                    "--target" => target = Some(value),
                    "--native-dir" => native_dir = Some(std::path::absolute(value)?),
                    "--output" => output = Some(std::path::absolute(value)?),
                    "--destination" => destination = Some(std::path::absolute(value)?),
                    "--url" => url = Some(value),
                    "--sha256" => expected = Some(value),
                    "--native-profile" => profile = value,
                    _ => return Err(format!("unknown artifact option: {name}").into()),
                }
                i += 2;
            }
            arg => return Err(format!("incomplete artifact option: {arg}").into()),
        }
    }
    let target = Platform::parse(&target.ok_or("--target is required")?)?;
    if !["portable", "pgo"].contains(&profile.as_str()) {
        return Err("unsupported native profile".into());
    }
    let mut default_dir = root.join("target/native/lib").join(target.target);
    let suffix = if profile == "portable" {
        String::new()
    } else {
        default_dir.push(&profile);
        format!("-{profile}")
    };
    if action == "package" {
        let output = output.unwrap_or_else(|| {
            root.join(format!(
                "target/dist/naive-rs-native-{}-{}{suffix}.tar.gz",
                env!("CARGO_PKG_VERSION"),
                target.target
            ))
        });
        return package(
            &root,
            target,
            &profile,
            &native_dir.unwrap_or(default_dir),
            &output,
        );
    }
    let url = url.ok_or("--url is required")?;
    let expected = expected
        .ok_or("--sha256 is required (pin the release archive digest)")?
        .to_ascii_lowercase();
    if expected.len() != 64 || !expected.bytes().all(|x| x.is_ascii_hexdigit()) {
        return Err("invalid SHA-256 digest".into());
    }
    if !url.starts_with("https://") && !(allow_http && loopback_http(&url)) {
        return Err("HTTPS required; --allow-http permits only explicit loopback test URLs".into());
    }
    let download = root.join("target/native/downloads");
    fs::create_dir_all(&download)?;
    let temp = download.join(format!("{expected}.partial-{}", std::process::id()));
    if temp.exists() {
        return Err("stale artifact download exists".into());
    }
    let result = (|| -> Result<()> {
        let proto = if allow_http { "=http,https" } else { "=https" };
        checked(command(
            &root,
            "curl",
            &[
                "--fail",
                "--location",
                "--retry",
                "3",
                "--max-time",
                "180",
                "--max-filesize",
                &MAX_ARCHIVE.to_string(),
                "--max-redirs",
                if allow_http { "0" } else { "5" },
                "--proto",
                proto,
                "--proto-redir",
                proto,
                "--output",
                temp.to_str().unwrap(),
                &url,
            ],
        ))?;
        if fs::metadata(&temp)?.len() > MAX_ARCHIVE || digest(&temp)? != expected {
            return Err("downloaded artifact SHA-256 mismatch".into());
        }
        unpack(
            &root,
            &temp,
            target,
            &profile,
            &destination.unwrap_or(default_dir),
            replace,
        )?;
        println!("Installed verified native artifact for {}", target.target);
        Ok(())
    })();
    if temp.exists() {
        fs::remove_file(temp)?;
    }
    result
}

fn loopback_http(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    matches!(host, "127.0.0.1" | "localhost" | "[::1]")
        && port.parse::<u16>().is_ok_and(|port| port != 0)
}
