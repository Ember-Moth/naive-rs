# Native platforms and validation

The build tool separates the target ABI from the host toolchain. Run
`cargo xtask targets` to list accepted Rust triples. A configured recipe is not
evidence that a binary has run on that platform; current results are recorded
in `platform-build-results.json` and the functional-gap checklist.

| Target family | Build host | Current recipe boundary |
|---|---|---|
| macOS arm64 / x86_64 | macOS with Xcode | Native static library, macOS 13+ |
| Linux GNU arm64 / x86_64 | macOS or Linux | Pinned host Clang and SHA-256-verified Bullseye headers/libraries; glibc, not musl |
| Android arm64 / x86_64 / armv7 | macOS or Linux | NDK 29.0.14206865, API 24+, native static library |
| iOS arm64 device | macOS with Xcode | iOS 18+, built with app-extension restrictions |
| iOS arm64 / x86_64 simulator | macOS with Xcode | iOS 18+ simulator ABI, separate from the device archive |
| Windows MSVC arm64 / x86_64 | Windows with Git Bash, MSVC C++ workload and Windows SDK | Build configuration supplied; native Windows build/runtime not yet verified |

Windows is intentionally documented as unverified until a Windows runner is
available. The Rust build-tool code has been cross-checked for MSVC, which does
not substitute for compiling and linking the native library.

## Build

Use the same target throughout preparation, native compilation and Cargo:

```sh
cargo xtask toolchain --target aarch64-apple-ios-sim
cargo xtask build --target aarch64-apple-ios-sim --jobs 4
IPHONEOS_DEPLOYMENT_TARGET=18.0 cargo build --target aarch64-apple-ios-sim
```

Apple final links must retain Objective-C categories with `-ObjC`. The
repository Cargo configuration sets `-C link-arg=-Wl,-ObjC` for its binaries.
Consumers outside this checkout must set the equivalent Cargo rustflag, or add
`-ObjC` to the final Xcode application's Other Linker Flags when embedding a
Rust static library. These are final-application settings; an rlib dependency
cannot propagate arbitrary linker arguments.

Native artifacts remain under `target/native/lib/<target>/`. Compiler caches
and prepared sources are separated by host OS/architecture below
`target/native/toolchains/` and `target/native/source/`. This prevents different build hosts sharing a checkout from loading each
other's compiler binaries.
The build lock still serializes native preparation and compilation within a
checkout. The pinned Linux host tools are x86_64 binaries; an ARM64 Linux host
needs a working x86_64 user-mode execution environment. CI uses an x86_64 host for Linux cross-compilation.

For Linux targets, `xtask toolchain` downloads the pinned upstream Bullseye
headers/libraries and verifies their SHA-256 before installation. It uses the
host-native Clang and GN, including on Apple Silicon. No Linux system image or
virtual machine is needed. On a Linux host, the normal native/cross GCC linker
can be used. For a final Rust link from macOS, use the supplied Clang wrapper:

```sh
cargo xtask toolchain --target x86_64-unknown-linux-gnu
native_source="$(cargo xtask prepare --target x86_64-unknown-linux-gnu)"
export NAIVE_CLANG="$native_source/src/third_party/llvm-build/Release+Asserts/bin/clang"
export NAIVE_LINUX_TARGET=x86_64-unknown-linux-gnu
export NAIVE_LINUX_SYSROOT="$native_source/src/out/sysroot-build/bullseye/bullseye_amd64_staging"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$PWD/tools/linux-clang-linker.sh"
cargo xtask build --target x86_64-unknown-linux-gnu --jobs 4
cargo test -p naive-rs --target x86_64-unknown-linux-gnu --all-features --no-run --locked
```

For arm64, use `aarch64-unknown-linux-gnu`, `bullseye_arm64_staging` and
`CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER` consistently. The wrapper passes
all Cargo linker arguments through and never executes the output. A preexisting
sysroot without the matching provenance stamp is rejected rather than silently
replaced; move that generated cache aside before reinstalling.

For Android, point at the exact installed NDK:

```sh
export NAIVE_ANDROID_NDK="$ANDROID_HOME/ndk/29.0.14206865"
# On Linux use linux-x86_64 in place of darwin-x86_64.
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NAIVE_ANDROID_NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang"
cargo xtask toolchain --target aarch64-linux-android
cargo xtask build --target aarch64-linux-android --jobs 4
cargo build --target aarch64-linux-android
```

The wrapper uses the upstream native-only Android build; it does not initialize
Java classes, create a VPN service or monitor Android network changes. The host
app supplies its INTERNET permission, lifecycle, DNS/routing policy and socket
protection through `Config::network`, and calls `close_all_connections()` on a
network transition. The static library does not contain app signing material.

On iOS the default certificate verifier continues to use SecTrust. Supplying
`extra_root_certificates` selects the builtin verifier with compiled Chrome roots
and those explicit anchors, without changing the keychain. That explicit-root
path does not import user keychain trust settings. Device and simulator archives
must not be interchanged, even when both use arm64.

## Validation scope

Platform acceptance requires native compilation and final Rust linking. Use
`cargo test -p naive-rs --target <triple> --all-features --no-run --locked` to
compile and link the library's existing test binaries without executing them.

No simulator, emulator, VM image, complete app, device installation or runtime
launch is required by this workflow. Existing library-level regression tests
remain available separately. Build evidence must not be described as app,
device, VPN-routing or signed-release runtime validation.
