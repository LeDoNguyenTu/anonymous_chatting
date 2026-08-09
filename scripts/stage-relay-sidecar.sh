#!/usr/bin/env bash
#
# Builds the relay and puts it where Tauri expects a sidecar.
#
# Tauri's `externalBin` requires the binary to be named with the target triple
# appended — `pouch-relay-x86_64-pc-windows-msvc.exe` — and strips that suffix
# again at install time so it lands beside the main executable as plain
# `pouch-relay.exe`. That is the name `relay_process::sidecar_path` looks for.
#
# This exists as a script rather than as two copies of the same commands in a
# workflow file and a README, because the triple-suffix rule is the kind of
# detail that is silently wrong in one of two copies. It also fails loudly if
# the binary did not appear, rather than letting `tauri build` produce an
# installer with no relay in it — an installer that looks complete and is not is
# worse than a failed build.

set -euo pipefail

cd "$(dirname "$0")/.."

triple="$(rustc -vV | sed -n 's/^host: //p')"
if [ -z "$triple" ]; then
  echo "Could not determine the host target triple from rustc." >&2
  exit 1
fi

case "$triple" in
  *windows*) ext=".exe" ;;
  *)         ext="" ;;
esac

echo "Building pouch-relay for $triple"
cargo build --release --locked -p pouch-relay --bin pouch-relay

built="target/release/pouch-relay${ext}"
if [ ! -f "$built" ]; then
  echo "FAIL: cargo reported success but $built does not exist." >&2
  exit 1
fi

dest_dir="clients/desktop/src-tauri/binaries"
dest="${dest_dir}/pouch-relay-${triple}${ext}"

mkdir -p "$dest_dir"
cp "$built" "$dest"

# Not a formality. `tauri build` fails with a bare "sidecar not found" that does
# not say which name it wanted, so confirming the exact expected filename here
# turns a confusing bundler error into a clear one.
if [ ! -f "$dest" ]; then
  echo "FAIL: could not stage the sidecar at $dest" >&2
  exit 1
fi

echo "ok: staged $(stat -c%s "$dest" 2>/dev/null || stat -f%z "$dest") bytes at $dest"
