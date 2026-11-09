#!/usr/bin/env bash
# Downloads the Wintun driver the Windows build ships next to netbird.exe into
# .wintun/ and checks it against the pinned checksum before every use.
set -euo pipefail

readonly url="https://www.wintun.net/builds/wintun-0.14.1.zip"
readonly sha256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"

root=$(cd "$(dirname "$0")/../.." && pwd)
dest="$root/.wintun"
zip="$dest/wintun-0.14.1.zip"

verify() {
  echo "$sha256  $1" | sha256sum --check --status
}

mkdir -p "$dest"
if [ ! -f "$zip" ] || ! verify "$zip"; then
  curl --fail --silent --show-error --location --proto '=https' --output "$zip.tmp" "$url"
  if ! verify "$zip.tmp"; then
    rm -f "$zip.tmp"
    echo "wintun archive does not match the pinned checksum" >&2
    exit 1
  fi
  mv "$zip.tmp" "$zip"
fi

rm -rf "$dest/wintun"
unzip -q "$zip" -d "$dest"
