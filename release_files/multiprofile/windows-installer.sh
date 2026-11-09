#!/usr/bin/env bash
# Builds the NSIS installer of the fork from one goreleaser Windows build.
# Usage: windows-installer.sh <netbird.exe> <arch> <version> <X.Y.Z> <output.exe>
set -euo pipefail

if [ $# -ne 5 ]; then
  echo "usage: $0 <netbird.exe> <arch> <version> <X.Y.Z> <output.exe>" >&2
  exit 2
fi

root=$(cd "$(dirname "$0")/../.." && pwd)
binary=$(realpath "$1")
arch=$2
version=$3
numeric=$4
output=$(realpath -m "$5")

wintun="$root/.wintun/wintun/bin/$arch/wintun.dll"
if [ ! -f "$wintun" ]; then
  echo "missing $wintun, run release_files/multiprofile/fetch-wintun.sh" >&2
  exit 1
fi

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp "$binary" "$stage/netbird.exe"
cp "$wintun" "$stage/wintun.dll"
cp "$root/release_files/multiprofile/path.ps1" "$stage/path.ps1"

mkdir -p "$(dirname "$output")"
makensis -V2 -NOCD \
  "-DARCH=$arch" \
  "-DVERSION=$numeric.0" \
  "-DDISPLAY_VERSION=$version" \
  "-DSRC_DIR=$stage" \
  "-DROOT_DIR=$root" \
  "-DOUT_FILE=$output" \
  "$root/client/installer_multiprofile.nsis"
