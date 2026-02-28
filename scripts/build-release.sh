#!/usr/bin/env bash
set -euo pipefail

ALL_TARGETS=(
    x86_64-unknown-linux-musl
    aarch64-unknown-linux-musl
)

VERBOSE=0
DIST_DIR="target/dist"

usage() {
    cat <<EOF
Usage: $(basename "$0") [-v] [-h] [TARGET ...]

Build static release binaries using cargo-zigbuild.

Targets:
  x86_64-unknown-linux-musl     x86_64 static binary
  aarch64-unknown-linux-musl    aarch64 static binary

If no targets are specified, all targets are built.

Options:
  -v    Verbose output
  -h    Show this help
EOF
}

target_to_binary() {
    local target=$1
    case "$target" in
        x86_64-unknown-linux-musl)  echo "sdme-x86_64-linux" ;;
        aarch64-unknown-linux-musl) echo "sdme-aarch64-linux" ;;
        *) echo "sdme-${target}" ;;
    esac
}

while getopts "vh" opt; do
    case "$opt" in
        v) VERBOSE=1 ;;
        h) usage; exit 0 ;;
        *) usage >&2; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

targets=("${@:-${ALL_TARGETS[@]}}")

for cmd in cargo zig; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "error: $cmd not found in PATH" >&2
        exit 1
    fi
done

if ! cargo zigbuild --help &>/dev/null; then
    echo "error: cargo-zigbuild not installed (run: cargo install cargo-zigbuild)" >&2
    exit 1
fi

mkdir -p "$DIST_DIR"

for target in "${targets[@]}"; do
    binary=$(target_to_binary "$target")
    echo "Building $target -> $DIST_DIR/$binary"

    rustup target add "$target" 2>/dev/null || true

    cargo_args=(zigbuild --locked --release --target "$target")
    if (( VERBOSE )); then
        cargo_args+=(--verbose)
    fi

    cargo "${cargo_args[@]}"

    cp "target/$target/release/sdme" "$DIST_DIR/$binary"

    echo "  size: $(du -h "$DIST_DIR/$binary" | cut -f1)"
    echo "  file: $(file "$DIST_DIR/$binary")"
    echo
done

echo "Binaries in $DIST_DIR:"
ls -lh "$DIST_DIR"/sdme-*
