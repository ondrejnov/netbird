# Sestavení a instalace forku na macOS

Fork se pro macOS nedistribuuje: bez Apple Developer ID a notarizace by Gatekeeper stažený binární soubor
zablokoval. Klient si proto sestavíte sami. Binárka sestavená na vlastním Macu nemá atribut karantény,
takže ji Gatekeeper nekontroluje.

Návod pokrývá CLI a daemon. Desktop UI není součástí v1 (viz [concurrent-profiles.md](concurrent-profiles.md)).

## Předpoklady

- macOS 11 nebo novější, Intel i Apple Silicon.
- Xcode Command Line Tools: `xcode-select --install` (kvůli `git` a `codesign`).
- Go ve verzi z řádku `toolchain` v `go.mod`. Novější Go si chybějící toolchain stáhne samo.

## Sestavení

```bash
git clone https://github.com/ondrejnov/netbird.git
cd netbird
git checkout v0.82.0-multiprofile          # vybrané vydání forku

# Verze bez přípony: tag multiprofile k ní sám přidá "+multiprofile".
VERSION=$(git describe --tags --exact-match | sed -E 's/^v([0-9]+\.[0-9]+\.[0-9]+).*/\1/')

mkdir -p build
(cd client && CGO_ENABLED=0 go build -tags multiprofile -trimpath \
  -ldflags "-s -w -X github.com/netbirdio/netbird/version.version=$VERSION" \
  -o ../build/netbird .)

# Ad-hoc podpis. Apple Silicon bez podpisu binárku nespustí.
codesign --force -s - build/netbird
./build/netbird version                     # 0.82.0+multiprofile
```

Bez tagu `multiprofile` vznikne upstream klient se zapnutým auto-updatem, který by fork přepsal
oficiálním vydáním.

## Odstranění upstream klienta

Fork a upstream sdílejí službu i binárku `netbird`, nainstalovaný může být jen jeden.

```bash
sudo netbird service stop
sudo netbird service uninstall
which netbird                               # binárku odstraňte podle toho, odkud pochází
brew uninstall netbird                      # jen při instalaci přes Homebrew
brew uninstall --cask netbird-ui            # totéž pro UI
```

Upstream instalace z balíčku `.pkg` obsahuje i `/Applications/NetBird.app`. UI forku nepatří, takže ho
smažte nebo aspoň nespouštějte. Konfigurace v `/var/lib/netbird` zůstává a fork ji převezme.

## Instalace

```bash
sudo install -m 0755 build/netbird /usr/local/bin/netbird
sudo netbird service install --enable-concurrent-profiles
sudo netbird service start
netbird up --management-url https://management.example.com
```

`--enable-concurrent-profiles` zapíná souběžné profily. Bez něj se daemon chová jako upstream. Další kroky
s profily jsou popsané v [concurrent-profiles.md](concurrent-profiles.md).

## Aktualizace

Klient forku se sám neaktualizuje. Novou verzi sestavte podle kapitoly Sestavení a vyměňte binárku:

```bash
sudo netbird service stop
sudo install -m 0755 build/netbird /usr/local/bin/netbird
sudo netbird service start
```

## Odinstalace

```bash
sudo netbird down
sudo netbird service stop
sudo netbird service uninstall
sudo rm /usr/local/bin/netbird
sudo rm -rf /var/lib/netbird                # jen pokud chcete smazat i konfiguraci a profily
```
