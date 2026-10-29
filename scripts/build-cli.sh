#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
target=x86_64-unknown-linux-musl
output=
print_plan=0
selected=

fail() { printf '%s\n' "$1" >&2; exit 2; }
add() {
    local value=$1
    case ,$selected, in
        *,$value,*) return 0 ;;
    esac
    selected=${selected:+$selected,}$value
}

while (($#)); do
    case $1 in
        --target|--out)
            (($# >= 2)) || fail MISSING_OPTION_VALUE
            [[ -n $2 && $2 != -* && $2 != *$'\n'* && $2 != *$'\r'* ]] || fail INVALID_OPTION_VALUE
            if [[ $1 == --target ]]; then target=$2; else output=$2; fi
            shift 2 ;;
        --wg|-wg) add wireguard; shift ;;
        --hy2) add hysteria2; shift ;;
        --vless|--vmess|--tuic|--trojan|--shadowsocks|--naive|--anytls|--shadowtls|--socks|--http)
            add "${1#--}"; shift ;;
        --all)
            for protocol in vless vmess hysteria2 tuic trojan shadowsocks wireguard naive anytls shadowtls socks http; do add "$protocol"; done
            shift ;;
        --print-plan) print_plan=1; shift ;;
        --help|-h)
            printf '%s\n' 'Build the Linux router CLI: --target TARGET --out DIRECTORY [--hy2 --vless --wg | --all]. Default: Hysteria2. --print-plan does not compile.'
            exit 0 ;;
        *) fail UNKNOWN_OPTION ;;
    esac
done

case $target in
    x86_64-unknown-linux-musl|aarch64-unknown-linux-musl) ;;
    *) fail UNSUPPORTED_TARGET ;;
esac
[[ -n $selected ]] || add hysteria2
features=$selected
if ((print_plan)); then
    printf 'target=%s\nfeatures=%s\nprofile=release\n' "$target" "$features"
    exit 0
fi
[[ -n $output ]] || fail OUTPUT_DIRECTORY_REQUIRED

cd "$root"
cargo build --locked --release -p foxcore-cli --no-default-features --features "$features" --target "$target"
artifact="${CARGO_TARGET_DIR:-$root/target}/$target/release/foxcore-cli"
[[ -f $artifact && ! -L $artifact ]] || fail BUILD_ARTIFACT_MISSING
mkdir -p "$output"
install -m 755 "$artifact" "$output/foxcore-cli"
printf '%s\n' "$features" > "$output/foxcore-cli.features"
printf '%s\n' "$target" > "$output/foxcore-cli.target"
