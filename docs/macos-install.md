# Building and installing the fork on macOS

The fork publishes no macOS build: without an Apple Developer ID and notarization, Gatekeeper would block a
downloaded binary. Build the client yourself instead. A binary built on your own Mac carries no quarantine
attribute, so Gatekeeper does not check it.

## Prerequisites

- macOS 11 or later, Intel or Apple Silicon.
- Xcode Command Line Tools: `xcode-select --install` (for `git`, `codesign` and the C compiler the UI needs).
- Go at the version on the `toolchain` line of `go.mod`. A newer Go downloads the missing toolchain itself.

## Build the daemon and CLI

```bash
git clone https://github.com/ondrejnov/netbird.git
cd netbird
git checkout v0.82.0-multiprofile          # the fork release you want

# Version without the suffix: the multiprofile tag appends "+multiprofile" itself.
VERSION=$(git describe --tags --exact-match | sed -E 's/^v([0-9]+\.[0-9]+\.[0-9]+).*/\1/')

mkdir -p build
(cd client && CGO_ENABLED=0 go build -tags multiprofile -trimpath \
  -ldflags "-s -w -X github.com/netbirdio/netbird/version.version=$VERSION" \
  -o ../build/netbird .)

# Ad-hoc signature. Apple Silicon refuses to run an unsigned binary.
codesign --force -s - build/netbird
./build/netbird version                     # 0.82.0+multiprofile
```

Without the `multiprofile` build tag you get the upstream client with auto-update enabled, which would replace
the fork with the official release.

## Build the desktop UI (optional)

The UI needs Node.js 22, pnpm 11 and the `wails3` CLI at the version of `github.com/wailsapp/wails/v3` in `go.mod`:

```bash
npm install -g pnpm@11
go install github.com/wailsapp/wails/v3/cmd/wails3@$(go list -m -f '{{.Version}}' github.com/wailsapp/wails/v3)

(cd client/ui && wails3 generate bindings -clean=true -ts)
(cd client/ui/frontend && pnpm install --frozen-lockfile && pnpm build)
(cd client/ui && CGO_ENABLED=1 MACOSX_DEPLOYMENT_TARGET=11.0 CGO_LDFLAGS=-mmacosx-version-min=11.0 \
  go build -tags production,multiprofile -trimpath \
  -ldflags "-s -w -X github.com/netbirdio/netbird/version.version=$VERSION" \
  -o ../../build/netbird-ui .)

mkdir -p build/NetBird.app/Contents/MacOS build/NetBird.app/Contents/Resources
cp client/ui/build/darwin/Info.plist build/NetBird.app/Contents/
cp client/ui/build/darwin/icons.icns build/NetBird.app/Contents/Resources/
cp build/netbird-ui build/NetBird.app/Contents/MacOS/
codesign --force --deep -s - build/NetBird.app
```

## Remove the upstream client

The fork and upstream share the `netbird` service and binary, so only one of them can be installed.

```bash
sudo netbird service stop
sudo netbird service uninstall
which netbird                               # remove the binary according to where it came from
brew uninstall netbird                      # only for a Homebrew install
brew uninstall --cask netbird-ui            # the same for the UI
```

An upstream `.pkg` install also puts the UI in `/Applications/NetBird.app`; replace it with the fork's UI or
delete it. The configuration in `/var/lib/netbird` stays and the fork takes it over.

## Install

```bash
sudo install -m 0755 build/netbird /usr/local/bin/netbird
sudo netbird service install --enable-concurrent-profiles
sudo netbird service start
netbird up --management-url https://management.example.com

# Only if you built the UI:
sudo rm -rf /Applications/NetBird.app
sudo cp -R build/NetBird.app /Applications/
```

`--enable-concurrent-profiles` turns on concurrent profiles; without it the daemon behaves like upstream. Working
with profiles is described in the [README](../README.md).

## Update

The fork does not update itself. Build the new version as described above and swap the binary:

```bash
sudo netbird service stop
sudo install -m 0755 build/netbird /usr/local/bin/netbird
sudo netbird service start
```

Replace `/Applications/NetBird.app` the same way if you use the UI.

## Uninstall

```bash
sudo netbird down
sudo netbird service stop
sudo netbird service uninstall
sudo rm /usr/local/bin/netbird
sudo rm -rf /Applications/NetBird.app       # if you installed the UI
sudo rm -rf /var/lib/netbird                # only to delete the configuration and profiles too
```
