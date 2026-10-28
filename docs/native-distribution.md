# Native archive distribution

The intended release repository is `Ember-Moth/naive-rs`. No release is implied
by the presence of these scripts: a published tag and its uploaded archives are
the external evidence of a release.

A versioned native bundle contains:

- The target-specific static library and `manifest.json`.
- Public C headers, including the host networking interface.
- The wrapper license and an inventory of upstream license/notice files.
- SHA-256 digests for every payload file, in addition to the archive checksum.

The manifest binds the archive to the wrapper version, upstream commit, native
ABI, target triple, native profile and source/build-script fingerprint. Native
build manifests also record platform SDK information and final-consumer linker
requirements. Apple applications must retain Objective-C categories with `-ObjC`;
see [platform integration](platforms.md). The package is generated
deterministically from those inputs; this is not a claim that native compiler
outputs from different SDK installations are byte-identical.

## Consumers

A wrapper checkout without initialized submodules can install a matching binary:

```sh
# Set URL to the archive for the desired published version and target.
# Obtain SHA256 from a trusted release checksum.
cargo xtask fetch --target aarch64-apple-darwin \
  --url "$URL" --sha256 "$SHA256"
cargo build --locked
```

`fetch` requires HTTPS, validates the outer digest before extraction, rejects
links, traversal paths and duplicate members, then checks the manifest and every
payload digest. It stages the result before installing it. An existing
installation is preserved unless `--replace` is explicitly supplied; failed
validation does not replace it. `--allow-http` exists only for explicitly named
loopback test servers.

`--destination DIR` selects a different installation. Set `NAIVE_NATIVE_DIR=DIR`
when building the Rust crate against it. Ordinary `cargo build` does not download
Chromium or prebuilt archives and does not modify the submodule. It verifies the
artifact's version, ABI, target, upstream revision and library checksum; in a
source checkout it also verifies the source fingerprint.

Portable and experimental PGO bundles are distinct. A PGO artifact must be
explicitly selected with `--native-profile pgo`; portable remains the default.

## Maintainers

```sh
git submodule update --init --recursive
cargo xtask toolchain --target aarch64-apple-darwin
cargo xtask build --target aarch64-apple-darwin
cargo xtask package --target aarch64-apple-darwin
python3 tests/artifact_distribution.py
```

`package` writes a versioned `.tar.gz` and `.sha256` file under `target/dist/`.
The distribution test installs a real archive through a local HTTP server,
checks rejected digests/versions/targets/members and atomic replacement, and
compiles and links a separate Rust consumer using the installed library.
Use `--target <triple>` to verify a cross-compiled package. The consumer is linked
for that target and is never executed; Intel macOS packages can be checked on an
Apple Silicon runner with the current SDK.

`.github/workflows/native-artifacts.yml` builds the target matrix. Manual runs
produce reviewable workflow artifacts. Supplying `release_version` publishes that
version only after every build job succeeds, creating its tag at the tested
workflow commit. An existing tag is never replaced by this manual path.
A `v<crate-version>` tag also triggers publication after the matrix succeeds.
Version-specific release notes live in `docs/releases/`. Existing releases are not
overwritten by the workflow. All platform jobs compile and link without launching test binaries or full
apps. Package validation checks installation, rejection cases and consumer
linking; it does not start a simulator or VM.
