#!/usr/bin/env bash
# Rebuild the JNI library from the pinned Rust/NDK inputs and verify every ELF.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="${FOXCORE_JNI_OUTPUT:-"$ROOT/target/android-jni"}"
# Pinned to the toolchain installed on the release workstation. Overrides are
# still checked below, so a build can never silently claim reproducibility while
# using another NDK.
NDK_VERSION="29.0.14206865"
CARGO_NDK_VERSION="4.1.2"
# The protocol set this build contains, stated rather than inherited.
#
# `shipped` is the release set — the fifteen protocol features listed in
# crates/foxcore-android/Cargo.toml, Tor client and onion-service publication
# among them, because the public ARM artifact promises both a working Tor lane
# and Tor-only file sharing.
#
# This variable used to *add* to the crate's defaults, which meant it could only
# ever make the artifact bigger: there was no way to build a core without a
# protocol from the release path, and every parser shipped to every phone
# regardless of the profile on it. It now names the whole set, so a build can
# subtract:
#
#   FOXCORE_ANDROID_FEATURES=vless,tor scripts/android-build.sh
#   FOXCORE_ANDROID_FEATURES= scripts/android-build.sh      # no protocol at all
#
# A reduced build is a real artifact, not a curiosity: the capabilities document
# reports `compiled: false` for what is absent, and the app feature-detects on
# exactly that field. It is still not a *release* — abi-gate.sh refuses a
# capabilities document that drops a protocol the frozen v1 fixture promises.
FEATURES="${FOXCORE_ANDROID_FEATURES-shipped}"

export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"

find_ndk() {
    if [ -n "${ANDROID_NDK_HOME:-}" ] && [ -d "$ANDROID_NDK_HOME" ]; then
        printf '%s\n' "$ANDROID_NDK_HOME"
        return
    fi
    for sdk in "${ANDROID_SDK_ROOT:-}" "${ANDROID_HOME:-}" "$HOME/Library/Android/sdk"; do
        if [ -n "$sdk" ] && [ -d "$sdk/ndk/$NDK_VERSION" ]; then
            printf '%s\n' "$sdk/ndk/$NDK_VERSION"
            return
        fi
    done
    return 1
}

ANDROID_NDK_HOME="$(find_ndk)" || {
    echo "Android NDK $NDK_VERSION was not found; set ANDROID_NDK_HOME." >&2
    exit 1
}
export ANDROID_NDK_HOME

# ANDROID_NDK_HOME used to be taken on trust, which meant the pin held only for
# whoever let the script search for itself. Everyone else silently built against
# whatever was in the environment, and "reproduced from pinned inputs" stopped
# being true without anything failing. The revision is read from the toolchain
# itself; an override has to name the version it is accepting, so an unpinned
# build is a deliberate sentence in someone's shell history rather than a
# default.
actual_ndk="$(sed -n 's/^Pkg.Revision *= *//p' "$ANDROID_NDK_HOME/source.properties" 2>/dev/null || true)"
if [ "$actual_ndk" != "$NDK_VERSION" ]; then
    if [ "${FOXCORE_ANDROID_NDK_ALLOW:-}" = "$actual_ndk" ]; then
        echo "WARNING: building with unpinned NDK ${actual_ndk:-unknown} (pin is $NDK_VERSION)" >&2
    else
        echo "NDK at ANDROID_NDK_HOME is ${actual_ndk:-unreadable}; the pin is $NDK_VERSION." >&2
        echo "To build anyway: FOXCORE_ANDROID_NDK_ALLOW=${actual_ndk:-<revision>}" >&2
        exit 1
    fi
fi

actual_cargo_ndk="$(cargo ndk --version 2>/dev/null || true)"
if [ "$actual_cargo_ndk" != "cargo-ndk $CARGO_NDK_VERSION" ]; then
    echo "cargo-ndk $CARGO_NDK_VERSION is required; found: ${actual_cargo_ndk:-nothing}" >&2
    echo "Install it with: cargo install cargo-ndk --version $CARGO_NDK_VERSION --locked" >&2
    exit 1
fi

# What ships: two ARM ABIs and nothing else. The product targets phones, and a
# fourth architecture in the APK is weight on every device that will never run
# it.
#
# x86_64 used to be in this default, which made the default invocation a
# statement nobody had checked: every reproducibility run had to pass
# FOXCORE_ANDROID_ABIS=arm64-v8a by hand because the x86_64
# target was missing on the build machine. It is installed here now, but that is
# not a reason to ship it.
#
# For an emulator it can still be asked for by name — it is not removed, only
# taken out of the default:
#
#   FOXCORE_ANDROID_ABIS=x86_64 scripts/android-build.sh
#
# scripts/android-elf-gate.sh checks such a build exactly as it checks the
# shipped ones, but refuses a non-ARM library that nobody asked for, so an
# emulator artifact cannot drift into a release tree unnoticed.
abis=(${FOXCORE_ANDROID_ABIS:-arm64-v8a armeabi-v7a})
ndk_args=()
for abi in "${abis[@]}"; do
    ndk_args+=("-t" "$abi")
done

# `--no-default-features` unconditionally, so the list above is the whole answer
# to "what is in this .so" and the crate's own default cannot quietly add to it.
feature_args=(--no-default-features)
if [ -n "$FEATURES" ]; then
    feature_args+=(--features "$FEATURES")
fi
echo "protocol features: ${FEATURES:-<none>}"

mkdir -p "$OUTPUT"
cd "$ROOT"
# `${arr[@]+...}` rather than `${arr[@]}`: bash 3.2 (what macOS ships) treats an
# empty array as unset under `set -u`, so the plain form aborts the build the
# moment no extra features are asked for — that is, on the default path.
cargo ndk "${ndk_args[@]}" -o "$OUTPUT" \
    build --release --locked --offline -p foxcore-android \
    ${feature_args[@]+"${feature_args[@]}"}
"$ROOT/scripts/android-elf-gate.sh" "$OUTPUT"
