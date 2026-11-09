#!/usr/bin/env bash
# Builds the NSIS installers of the fork from a finished goreleaser run in
# dist/ and adds them to its checksum file. Needs makensis, jq and wails3.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
dist="$root/dist"

version=$(jq -r .version "$dist/metadata.json")
project=$(jq -r .project_name "$dist/metadata.json")
numeric=$(sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/' <<<"$version")
if [[ ! "$numeric" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "cannot derive X.Y.Z from version $version" >&2
  exit 1
fi

binary() {
  local id=$1 arch=$2 path
  path=$(jq -r --arg id "$id" --arg arch "$arch" \
    '.[] | select(.type == "Binary" and .goos == "windows" and .goarch == $arch and .extra.ID == $id) | .path' \
    "$dist/artifacts.json")
  if [ -z "$path" ] || [ ! -f "$root/$path" ]; then
    echo "no $id binary for windows/$arch in dist" >&2
    exit 1
  fi
  echo "$root/$path"
}

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

# One copy of the WebView2 bootstrapper serves both architectures.
wails3 generate webview2bootstrapper -dir "$stage"

checksums=$(ls "$dist"/*_checksums.txt)
for arch in amd64 arm64; do
  wintun="$root/.wintun/wintun/bin/$arch/wintun.dll"
  if [ ! -f "$wintun" ]; then
    echo "missing $wintun, run release_files/multiprofile/fetch-wintun.sh" >&2
    exit 1
  fi

  src="$stage/$arch"
  mkdir -p "$src"
  cp "$(binary netbird-multiprofile-windows "$arch")" "$src/netbird.exe"
  cp "$(binary "netbird-ui-multiprofile-windows-$arch" "$arch")" "$src/netbird-ui.exe"
  cp "$wintun" "$src/wintun.dll"
  cp "$stage/MicrosoftEdgeWebview2Setup.exe" "$src/"
  cp "$root/release_files/multiprofile/path.ps1" "$src/"

  name="${project}_${version}_windows_${arch}_installer.exe"
  makensis -V2 -NOCD \
    "-DARCH=$arch" \
    "-DVERSION=$numeric.0" \
    "-DDISPLAY_VERSION=$version" \
    "-DSRC_DIR=$src" \
    "-DROOT_DIR=$root" \
    "-DOUT_FILE=$dist/$name" \
    "$root/client/installer_multiprofile.nsis"
  (cd "$dist" && sha256sum "$name") >>"$checksums"
done
