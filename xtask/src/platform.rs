use crate::{Result, command, output};
use sha2::{Digest, Sha256};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug)]
pub struct Platform {
    pub target: &'static str,
    pub os: &'static str,
    pub cpu: &'static str,
    pub environment: Option<&'static str>,
}
pub const PLATFORMS: &[Platform] = &[
    Platform {
        target: "aarch64-apple-darwin",
        os: "mac",
        cpu: "arm64",
        environment: None,
    },
    Platform {
        target: "x86_64-apple-darwin",
        os: "mac",
        cpu: "x64",
        environment: None,
    },
    Platform {
        target: "x86_64-unknown-linux-gnu",
        os: "linux",
        cpu: "x64",
        environment: None,
    },
    Platform {
        target: "aarch64-unknown-linux-gnu",
        os: "linux",
        cpu: "arm64",
        environment: None,
    },
    Platform {
        target: "aarch64-linux-android",
        os: "android",
        cpu: "arm64",
        environment: None,
    },
    Platform {
        target: "x86_64-linux-android",
        os: "android",
        cpu: "x64",
        environment: None,
    },
    Platform {
        target: "armv7-linux-androideabi",
        os: "android",
        cpu: "arm",
        environment: None,
    },
    Platform {
        target: "aarch64-apple-ios",
        os: "ios",
        cpu: "arm64",
        environment: Some("device"),
    },
    Platform {
        target: "aarch64-apple-ios-sim",
        os: "ios",
        cpu: "arm64",
        environment: Some("simulator"),
    },
    Platform {
        target: "x86_64-apple-ios",
        os: "ios",
        cpu: "x64",
        environment: Some("simulator"),
    },
    Platform {
        target: "x86_64-pc-windows-msvc",
        os: "win",
        cpu: "x64",
        environment: None,
    },
    Platform {
        target: "aarch64-pc-windows-msvc",
        os: "win",
        cpu: "arm64",
        environment: None,
    },
];
impl Platform {
    pub fn parse(target: &str) -> Result<Self> {
        PLATFORMS
            .iter()
            .find(|p| p.target == target)
            .copied()
            .ok_or_else(|| format!("unsupported native target: {target}").into())
    }
    pub fn archive(self) -> &'static str {
        if self.os == "win" {
            "naive_native.lib"
        } else {
            "libnaive_native.a"
        }
    }
    pub fn host_check(self) -> Result<()> {
        let host = env::consts::OS;
        let allowed = match self.os {
            "mac" | "ios" => host == "macos",
            "linux" => matches!(host, "linux" | "macos"),
            "win" => host == "windows",
            "android" => matches!(host, "macos" | "linux"),
            _ => false,
        };
        if !allowed {
            return Err(format!(
                "{} native build requires a compatible host; this host is {host}",
                self.target
            )
            .into());
        }
        Ok(())
    }
    pub fn args(self) -> String {
        let mut args = format!(
            "\ntarget_os = \"{}\"\ntarget_cpu = \"{}\"\n",
            self.os, self.cpu
        );
        if self.os == "linux" {
            let arch = if self.cpu == "x64" { "amd64" } else { "arm64" };
            args.push_str(&format!(
                "target_sysroot = \"//out/sysroot-build/bullseye/bullseye_{arch}_staging\"\n"
            ));
            if self.cpu == "x64" {
                args.push_str("use_cfi_icall = false\n");
            }
        }
        if matches!(self.os, "mac" | "ios") {
            args.push_str("enable_dsyms = false\nmac_allow_system_xcode_for_official_builds_for_testing = true\n");
        }
        if let Some(environment) = self.environment {
            args.push_str(&format!("target_environment = \"{environment}\"\nios_enable_code_signing = false\nios_is_app_extension = true\nuse_blink = false\nchrome_root_store_optional = true\n"));
        }
        if self.os == "android" {
            args.push_str("is_desktop_android = true\ndefault_min_sdk_version = 24\nis_high_end_android = true\nenable_android_secondary_abi = false\n");
        }
        args
    }
}

pub fn android_ndk() -> Result<PathBuf> {
    let path = ["NAIVE_ANDROID_NDK", "ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"]
        .into_iter()
        .find_map(|name| env::var_os(name).filter(|value| !value.is_empty()))
        .map(PathBuf::from)
        .ok_or("set NAIVE_ANDROID_NDK to an installed Android NDK 29.0.14206865")?;
    if !path.join("source.properties").is_file() {
        return Err(format!("invalid Android NDK: {}", path.display()).into());
    }
    let properties = fs::read_to_string(path.join("source.properties"))?;
    let revision = properties.lines().find_map(|line| {
        line.strip_prefix("Pkg.Revision")
            .and_then(|s| s.split_once('=').map(|(_, v)| v.trim()))
    });
    if revision != Some("29.0.14206865") {
        return Err("use the pinned Android NDK 29.0.14206865".into());
    }
    Ok(fs::canonicalize(path)?)
}
pub fn prepare_android(src: &Path) -> Result<()> {
    let ndk = android_ndk()?;
    let link = src.join("third_party/android_toolchain/ndk");
    fs::create_dir_all(link.parent().unwrap())?;
    if link.symlink_metadata().is_ok() {
        if fs::canonicalize(&link)? != ndk {
            return Err(format!("{} already points to another NDK; remove this generated link before switching NDKs",link.display()).into());
        }
    } else {
        #[cfg(unix)]
        std::os::unix::fs::symlink(&ndk, &link)?;
    }
    let host = if cfg!(target_os = "macos") {
        "darwin-x86_64"
    } else {
        "linux-x86_64"
    };
    if !ndk
        .join(format!("toolchains/llvm/prebuilt/{host}/sysroot"))
        .is_dir()
    {
        return Err(format!("NDK does not contain the {host} host toolchain").into());
    }
    Ok(())
}
fn download(src: &Path, url: &str, archive: &Path) -> Result<()> {
    crate::checked(command(
        src,
        "curl",
        &[
            "--fail",
            "--location",
            "--retry",
            "3",
            url,
            "--output",
            archive.to_str().unwrap(),
        ],
    ))
}
// The pinned upstream sysroots contain target headers and libraries only.
// Using the same verified bundles on both hosts avoids running Linux package
// managers or creating a VM just to perform a cross link.
fn linux_sysroot(src: &Path, platform: Platform) -> Result<()> {
    let arch = if platform.cpu == "x64" {
        "amd64"
    } else {
        "arm64"
    };
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(
        src.join("build/linux/sysroot_scripts/sysroots.json"),
    )?)?;
    let entry = &manifest[format!("bullseye_{arch}")];
    let digest = entry["Sha256Sum"]
        .as_str()
        .ok_or("missing pinned sysroot digest")?;
    let origin = entry["URL"].as_str().ok_or("missing pinned sysroot URL")?;
    if digest.len() != 64
        || !digest.bytes().all(|c| c.is_ascii_hexdigit())
        || !origin.starts_with("https://")
    {
        return Err("invalid pinned sysroot metadata".into());
    }
    let base = src.join("out/sysroot-build/bullseye");
    let dest = base.join(format!("bullseye_{arch}_staging"));
    let stamp = dest.join(".naive-prebuilt-sha256");
    if fs::read_to_string(&stamp).ok().as_deref() == Some(digest) {
        return Ok(());
    }
    if dest.exists() {
        return Err(format!("{} is not the pinned prebuilt sysroot; move the old generated sysroot aside before retrying", dest.display()).into());
    }
    fs::create_dir_all(&base)?;
    let archive = base.join(format!("{digest}.tar.xz"));
    if !archive.exists() {
        download(src, &format!("{origin}/{digest}"), &archive)?;
    }
    let mut hash = Sha256::new();
    io::copy(&mut fs::File::open(&archive)?, &mut hash)?;
    if format!("{:x}", hash.finalize()) != digest {
        return Err("downloaded sysroot SHA-256 mismatch".into());
    }
    let staging = base.join(format!("{arch}.staging-{}", std::process::id()));
    fs::create_dir(&staging)?;
    let result = (|| -> Result<()> {
        crate::checked(command(
            src,
            "tar",
            &[
                "xJf",
                archive.to_str().unwrap(),
                "-C",
                staging.to_str().unwrap(),
            ],
        ))?;
        fs::write(staging.join(".naive-prebuilt-sha256"), digest)?;
        fs::rename(&staging, &dest)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(staging);
    }
    result
}

fn host_tools(src: &Path) -> Result<String> {
    let revision = output(command(
        &src.join("tools/clang/scripts"),
        "python3",
        &["-c", "import update; print(update.PACKAGE_VERSION)"],
    ))?;
    let clang = src.join("third_party/llvm-build/Release+Asserts");
    let host = match (env::consts::OS, env::consts::ARCH) {
        ("macos", "aarch64") => "Mac_arm64",
        ("macos", _) => "Mac",
        ("linux", _) => "Linux_x64",
        _ => unreachable!(),
    };
    if !clang.join("bin/clang").is_file() {
        let archive = src.join("clang-host.tar.xz");
        let url = format!(
            "https://commondatastorage.googleapis.com/chromium-browser-clang/{host}/clang-{revision}.tar.xz"
        );
        download(src, &url, &archive)?;
        fs::create_dir_all(&clang)?;
        crate::checked(command(
            src,
            "tar",
            &[
                "xJf",
                archive.to_str().unwrap(),
                "-C",
                clang.to_str().unwrap(),
            ],
        ))?;
        fs::remove_file(archive)?;
        fs::write(clang.join("cr_build_revision"), &revision)?;
    }
    if fs::read_to_string(clang.join("cr_build_revision"))?.trim() != revision {
        return Err("cached compiler revision differs from pinned sources".into());
    }
    let gn = src.join("gn/out");
    if !gn.join("gn").is_file() {
        let deps = fs::read_to_string(src.join("DEPS"))?;
        let line = deps
            .lines()
            .find(|line| line.contains("'gn_version':"))
            .ok_or("missing GN revision")?;
        let version = line.split('\'').nth(3).ok_or("invalid GN revision")?;
        let host = if cfg!(target_os = "macos") {
            if cfg!(target_arch = "aarch64") {
                "mac-arm64"
            } else {
                "mac-amd64"
            }
        } else {
            "linux-amd64"
        };
        let url = format!("https://chrome-infra-packages.appspot.com/dl/gn/gn/{host}/+/{version}");
        let archive = src.join("gn-host.zip");
        download(src, &url, &archive)?;
        fs::create_dir_all(&gn)?;
        crate::checked(command(
            src,
            "unzip",
            &["-q", archive.to_str().unwrap(), "-d", gn.to_str().unwrap()],
        ))?;
        fs::remove_file(archive)?;
    }
    Ok(revision)
}

pub fn toolchain(src: &Path, platform: Platform, profile: &str) -> Result<()> {
    if platform.os == "linux" {
        linux_sysroot(src, platform)?;
        host_tools(src)?;
        if profile == "portable" {
            return Ok(());
        }
    }
    if platform.os != "android" {
        let mut c = command(src, "sh", &["./get-clang.sh"]);
        c.env(
            "EXTRA_FLAGS",
            format!(
                "target_os=\"{}\" target_cpu=\"{}\"",
                platform.os, platform.cpu
            ),
        );
        return crate::checked(c);
    }
    prepare_android(src)?;
    let revision = host_tools(src)?;
    let clang = src.join("third_party/llvm-build/Release+Asserts");
    // Android runtime archives are host-independent target libraries.
    let stamp = clang.join(".naive-android-runtime");
    if fs::read_to_string(&stamp).ok().as_deref() != Some(revision.as_str()) {
        let url = format!(
            "https://commondatastorage.googleapis.com/chromium-browser-clang/Linux_x64/clang-android-runtime-library-{revision}.tar.xz"
        );
        let archive = src.join("clang-android-runtime.tar.xz");
        download(src, &url, &archive)?;
        crate::checked(command(
            src,
            "tar",
            &[
                "xJf",
                archive.to_str().unwrap(),
                "-C",
                clang.to_str().unwrap(),
            ],
        ))?;
        fs::remove_file(archive)?;
        fs::write(stamp, &revision)?;
    }
    if profile == "pgo" {
        // The host compiler is now present, so upstream skips its Linux-only
        // first-install runtime path and only downloads the requested profile.
        let mut c = command(src, "sh", &["./get-clang.sh"]);
        c.env(
            "EXTRA_FLAGS",
            format!("target_os=\"android\" target_cpu=\"{}\"", platform.cpu),
        );
        crate::checked(c)?;
    }
    Ok(())
}

pub fn details(src: &Path, platform: Platform) -> Result<serde_json::Value> {
    Ok(if platform.os == "android" {
        serde_json::json!({"android_api":24,"ndk":fs::read_to_string(android_ndk()?.join("source.properties"))?})
    } else if platform.os == "linux" {
        let arch = if platform.cpu == "x64" {
            "amd64"
        } else {
            "arm64"
        };
        let digest = fs::read_to_string(src.join(format!(
            "out/sysroot-build/bullseye/bullseye_{arch}_staging/.naive-prebuilt-sha256"
        )))?;
        serde_json::json!({"sysroot":"debian-bullseye","sysroot_sha256":digest})
    } else if platform.os == "ios" {
        let sdk = if platform.environment == Some("device") {
            "iphoneos"
        } else {
            "iphonesimulator"
        };
        serde_json::json!({"ios_minimum":"18.0","environment":platform.environment,"sdk":output(command(src,"xcrun",&["--sdk",sdk,"--show-sdk-version"]))?,"app_extension_safe":true})
    } else {
        serde_json::json!({})
    })
}
