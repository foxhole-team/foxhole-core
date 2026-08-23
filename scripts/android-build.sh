#!/usr/bin/env bash
# Rebuild the JNI library from the pinned Rust/NDK inputs and verify every ELF.
set -euo pipefail

ROOT_LOGICAL="$(cd "$(dirname "$0")/.." && pwd -L)"
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
OUTPUT="${FOXCORE_JNI_OUTPUT:-"$ROOT/target/android-jni"}"
# Release toolchain pins; overrides must be explicit below.
NDK_VERSION="29.0.14206865"
CARGO_NDK_VERSION="4.1.2"
# This replaces, rather than extends, the crate's default feature set:
#
#   FOXCORE_ANDROID_FEATURES=vless,tor scripts/android-build.sh
#   FOXCORE_ANDROID_FEATURES= scripts/android-build.sh
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

# Panic locations survive stripping; remap every spelling Cargo may embed.
raw_absolute_build_root() {
    local path="$1"
    case "$path" in
        /*) ;;
        *) path="$ROOT_LOGICAL/$path" ;;
    esac
    printf '%s\n' "$path"
}

logical_build_root() {
    local path="$1"
    if [ -d "$path" ]; then
        (cd "$path" && pwd -L)
    else
        printf '%s\n' "$path"
    fi
}

physical_build_root() {
    local path="$1"
    if [ -d "$path" ]; then
        (cd "$path" && pwd -P)
    else
        printf '%s\n' "$path"
    fi
}

cargo_home_raw="$(raw_absolute_build_root "${CARGO_HOME:-$HOME/.cargo}")"
cargo_home_logical="$(logical_build_root "$cargo_home_raw")"
cargo_home_physical="$(physical_build_root "$cargo_home_raw")"
rustup_home_raw="$(raw_absolute_build_root "${RUSTUP_HOME:-$HOME/.rustup}")"
rustup_home_logical="$(logical_build_root "$rustup_home_raw")"
rustup_home_physical="$(physical_build_root "$rustup_home_raw")"
release_rustflags=(
    # Keep linker flags synchronized with .cargo/config.toml and build.rs.
    "-C"
    "link-arg=-Wl,--no-as-needed"
    "-C"
    "link-arg=-landroid"
    "-C"
    "link-arg=-Wl,-z,max-page-size=16384"
    "-C"
    "link-arg=-Wl,-z,common-page-size=16384"
    # rustc remaps exact prefixes; cover raw, logical, and physical spellings.
    "--remap-path-prefix=$ROOT_LOGICAL=."
    "--remap-path-prefix=$ROOT=."
    "--remap-path-prefix=$cargo_home_raw=.cargo"
    "--remap-path-prefix=$cargo_home_logical=.cargo"
    "--remap-path-prefix=$cargo_home_physical=.cargo"
    "--remap-path-prefix=$rustup_home_raw=.rustup"
    "--remap-path-prefix=$rustup_home_logical=.rustup"
    "--remap-path-prefix=$rustup_home_physical=.rustup"
)
encoded_release_rustflags="$(IFS=$'\x1f'; printf '%s' "${release_rustflags[*]}")"
if [ -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]; then
    export CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS}"$'\x1f'"$encoded_release_rustflags"
else
    export CARGO_ENCODED_RUSTFLAGS="$encoded_release_rustflags"
fi

# Verify environment overrides against the release NDK pin.
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

# Releases ship ARM only; emulator ABIs require FOXCORE_ANDROID_ABIS explicitly.
abis=(${FOXCORE_ANDROID_ABIS:-arm64-v8a armeabi-v7a})
ndk_args=()
for abi in "${abis[@]}"; do
    ndk_args+=("-t" "$abi")
done

# Make FEATURES the complete compiled protocol set.
feature_args=(--no-default-features)
if [ -n "$FEATURES" ]; then
    feature_args+=(--features "$FEATURES")
fi
echo "protocol features: ${FEATURES:-<none>}"

mkdir -p "$OUTPUT"
cd "$ROOT"
# Bash 3.2 treats an empty array as unset under `set -u`.
cargo ndk "${ndk_args[@]}" -o "$OUTPUT" \
    build --release --locked --offline -p foxcore-android \
    ${feature_args[@]+"${feature_args[@]}"}
"$ROOT/scripts/android-elf-gate.sh" "$OUTPUT"
