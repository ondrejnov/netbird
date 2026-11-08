# Souběžné profily ve forku NetBird

Jeden počítač s jedním daemonem je připojený k více NetBird sítím najednou. Každý profil má vlastní
identitu, interface, ACL, routy a DNS. Funkce je za feature gate: bez ní se klient chová jako upstream
se stejnými názvy, pravidly a soubory.

Platí pro Linux, CLI a self-hosted Management. Závazný návrh je ve
[specifikaci](specs/concurrent-profiles.md). NetBird Cloud, desktop UI a jiné platformy nejsou součástí v1.

## Zapnutí gate

Nová instalace služby:

```bash
sudo netbird service install --enable-concurrent-profiles
sudo netbird service start
```

Existující služba. Příkaz službu přeinstaluje, a pokud běžela, spustí ji znovu, takže se všechna spojení přeruší:

```bash
sudo netbird service reconfigure --enable-concurrent-profiles
```

Hodnota se ukládá do `service.json` a platí po restartu služby. Gate odmítne start služby mimo Linux, Windows a macOS a na TCP
socketu daemonu nebo zapnutém JSON socketu na TCP, kde volající nemá identitu.

Session se s gate nespustí, když:

| Podmínka | Co s tím |
|---|---|
| Netstack (`NB_USE_NETSTACK_MODE`) | Vypnout netstack |
| Legacy routing (`AdvancedRouting` je false) | Jádro s podporou fwmark pravidel, po opravě restart služby. Podpora se zjišťuje jednou za běh daemonu |
| `NB_DNS_STATE_FILE` | Odebrat proměnnou, všechny session by se dělily o jeden state soubor |
| Jádro starší než 5.6 | Novější jádro, `own` v izolaci to vyžaduje |
| iptables bez modulů ipset | Doinstalovat moduly, izolace nemá náhradní cestu |
| Explicitní `interface_name` v profilu (`conflict=interface`) | `netbird up --profile X --interface-name wt0`. Hodnota `wt0` znamená automatický název slotu |
| Bez nativního firewallu a s vypnutým firewallem session | Nainstalovat nftables nebo iptables, nebo firewall session nevypínat |

Výchozí limit je 4 session, nad ním `up` vrátí `ResourceExhausted`.

## Použití

```bash
netbird up --profile prace --management-url https://mgmt.prace.example --setup-key <klíč>
netbird up --profile doma --management-url https://mgmt.doma.example --setup-key <klíč>
netbird status
ping <peer-v-praci>                 # jde přes wt0
ping <peer-doma>                    # jde přes wt1
netbird down --profile doma         # routy, firewall i DNS profilu "prace" zůstanou beze změny
```

`up --profile` neexistující profil založí. Slot, a tím interface a port, dostane profil při prvním startu a
zůstane mu až do odstranění profilu. `netbird status` za souhrn přidá tabulku:

```text
Sessions:
  default  NeedsLogin  -    -
  doma     Connected   wt1  100.72.253.109/16  focused, conflict: dns
  prace    Connected   wt0  100.71.231.76/16
```

| Příkaz | Chování s gate |
|---|---|
| `netbird up --profile X` | Přidá session X a přesune na ni focus, ostatních se nedotkne. Když se X nespustí, vrátí focus session, která ho měla předtím |
| `netbird down` | Odpojí `focused` a vypíše, co dál běží |
| `netbird down --profile X`, `--all` | Odpojí pojmenovanou session, nebo všechny, na které volající dosáhne |
| `netbird status --profile X` | Souhrn session X, JSON přidá pole `sessions` |
| `netbird profile select X` | Změní `focused`, nic neodpojí |
| `netbird profile list` | Přidá stav připojení |
| `netbird profile remove X`, `deregister` | Běžící session odmítne, nejdřív `netbird down --profile X` |
| `networks`, `debug`, `ssh`, `expose` | Přijímají `--profile`, výchozí je `focused` |

Neprivilegovaný uživatel řídí a čte jen své session a sdílenou `default`. Výjimka: `status` a `down` bez
`--profile` dál čtou a odpojují `focused` kohokoli, jako dnes. Uživatel s tečkou ve jméně má bez oprávnění jen
`default`, protože jeho adresář profilů se sanitizací jména může sdílet s jiným účtem.

## Konflikt overlay sítí

Dvě sítě se stejným nebo překrývajícím se IPv4 rozsahem spolu běžet nemůžou, překlad adres není součástí v1.
Rozsah se vybírá náhodně z `100.64.0.0/10` po /16, takže shoda dvou nezávislých sítí má pravděpodobnost 1/64.

Poznáte to takto:

```text
$ netbird up --profile doma
Error: daemon up failed: call service up method: rpc error: code = FailedPrecondition desc = This session was not started: its overlay range overlaps another running session. Change network_range in the Management of one of the networks, or bring the other session down
$ netbird status --profile doma
  doma     Idle        -    -                  conflict: overlay
```

Běžící session se odmítnutí nedotkne. Focus se vrátí session, která ho měla před příkazem, prosté `netbird down`
tedy nemíří na odmítnutou session. Řeší se změnou rozsahu v Managementu jedné ze sítí, v
self-hosted instalaci je to nastavení účtu `network_range` (minimum /28 a musí pojmout peery s rezervou):

```bash
curl -s -H "Authorization: Token $PAT" https://mgmt.doma.example/api/accounts > account.json
ID=$(jq -r '.[0].id' account.json)
jq '{settings: (.[0].settings | .network_range = "100.72.0.0/16")}' account.json |
  curl -X PUT -H "Authorization: Token $PAT" -H "Content-Type: application/json" \
    -d @- "https://mgmt.doma.example/api/accounts/$ID"
netbird up --profile doma
```

**Změna přečísluje všechny peery té sítě.** Připojení klienti si novou adresu vezmou sami a restartují engine,
pravidla a záznamy obsahující staré adresy je potřeba upravit. Session si drží slot, takže po změně běží znovu na
stejném interface.

Mezi dvěma změnami rozsahu nechte peery doběhnout, restart engine trvá pár sekund. Peer, který se znovu připojuje právě
ve chvíli další změny, může zůstat na adrese z předchozí změny, viděli jsme to v testu na obyčejném klientovi. Pozná se
ve `netbird status` podle IP mimo nový rozsah a napraví ho `netbird down` a `netbird up`.

Překryv IPv6 se neodmítá: nová session přeskočí v6, běží na v4 a dostane událost `ipv6_overlay_skipped`.
Session, která v6 takto ztratila, ho získá až po svém restartu.

## Konflikt DNS domény

Dvě sítě se stejnou DNS doménou se kvůli sdílenému hostitelskému DNS chovají hůř. Starší self-hosted instalace mají
výchozí `netbird.selfhosted`, takže se to týká každé dvojice, která doménu nezměnila. Správce nastaví doménu jedné ze sítí:

- Na úrovni účtu: `dns_domain` ve stejném `PUT /api/accounts/<id>` jako výše, přednost má před výchozí.
- Na úrovni Managementu: `management --dns-domain`, v `setup.env` `NETBIRD_MGMT_DNS_DOMAIN`. Kombinovaný server
  (`netbird-server`) bere výchozí doménu ze své veřejné adresy, dvě jeho instance se tedy liší samy.

Změnou domény se změní FQDN všech peerů té sítě.

## Známá omezení

### Desktop UI

UI ze sestavení forku od větve `ui/concurrent-profiles` gate pozná. Výběr profilu jen přesune focus a profil bez
spojení připojí, ostatní session běží dál. Dropdown profilů a tray ukazují stav každé session a konflikt, dropdown
umí odpojit každou běžící session zvlášť. Hlavní okno a stránky Peers a Networks ukazují `focused`. Podrobnosti
jsou v sekci 2.7 specifikace.

Starší UI gate nezná a vidí jen `focused`. Přepínač profilů přepne a zavolá `Down`, který s gate míří na nový
`focused`. **Původní session proto běží dál a v UI není vidět**, ukáže ji jen `netbird status`.

### SSH config dalších session

Session ve slotu N (`wt1` a dál) zapisuje `/etc/ssh/ssh_config.d/99-netbird-N.conf` s právy 0644, stejně jako slot 0
svůj `99-netbird.conf`. Soubor obsahuje overlay IP a FQDN peerů té session a přečte ho každý lokální uživatel, i ten,
kterému daemon stav cizí session přes `status` nevydá. Práva 0600 nejdou, protože OpenSSH čte soubory z
`ssh_config.d` pod účtem, který `ssh` spouští, a vlastník session by soubor nepřečetl. Na stroji, kde se adresy a
jména peerů jedné sítě nemají dostat k ostatním lokálním uživatelům, souběžné profily nezapínejte.

### Konflikty

| Konflikt | Chování |
|---|---|
| IPv4 overlay se překrývá | Session se nespustí, `conflict=overlay`. Kontrola po loginu a znovu při změně adresy z Managementu |
| IPv6 overlay se překrývá | Session přeskočí v6 a běží na v4 |
| Stejný prefix routy | Vlastní ho první session, po jejím odchodu přejde na další, varování v události |
| Routa pokrývá overlay jiné session | Routa se odmítne (`route_overlay_refused`) |
| Exit node | Jeden na počítač, první vyhrává. Ruční výběr v další session vrátí `FailedPrecondition`, auto-apply se přeskočí s varováním a `conflict=exit_node`. Po odchodu vlastníka se nepředává, provoz jde fyzickým defaultem a je potřeba `networks deselect` a `networks select` |
| Stejná DNS doména | systemd-resolved: jména bez kolize fungují v obou sítích, jméno v obou je závod. Ostatní backendy: doménu má první session, jména druhé nefungují, IP ano, `conflict=dns` |
| DNS catch-all | Jeden vlastník, první vyhrává. Domény Managementu session bez root handleru pak překládá DNS sítě, která catch-all vlastní |
| Limit session | `up` vrátí `ResourceExhausted` |

V kontejneru s backendem `file` má hostitelský DNS jen jedna session, druhá tedy hlásí `conflict: dns` a dál funguje přes IP.

### Co dál v provozu čekat

Vybráno ze sekce 2.3 specifikace, čísla odkazují tam:

- **DNS backendy (Q5, Q8):** skutečně je ověřený jen `file`. systemd-resolved a NetworkManager běžely proti falešným službám na D-Bus, Debian `resolvconf` se bere jako openresolv bez ověření.
- **Kolize jména v DNS (Q6):** nezjišťuje se. Varování `dns_domain_shared` je proto přísnější a platí pro celou doménu.
- **Uvolněný DNS (Q4):** nepředává se aktivně, další session ho zkusí získat při své další aktualizaci configu.
- **Předání routy (Q1):** když selže, zůstane ve frontě a opakuje se při další operaci, časovač není.
- **ICE blacklist (Q7):** porovnává prefixem, `wt1` tedy vyloučí i `wt10`. Chyba je na straně vyloučení.
- **IPv6 izolace (Q13, Q23):** když nejde nainstalovat, v6 se odebere a session pokračuje na v4. V nainstalované rovině iptables se session odmítne.
- **Kontrola izolace (Q14):** běží každých 5 s. Rozdíl izolaci obnoví a pošle `isolation_restored`, neúspěch zastaví všechny session. Okno je tedy až 5 s, vlastní tabulky session po `flush ruleset` nikdo neobnoví.
- **Port (Q18):** explicitní `WgPort` obsazený cizím procesem se nahradí portem z alokátoru, stejně jako dnes. `51820+N` je v ephemeral rozsahu, port slotu se proto může posunout.
- **Cizí link se jménem slotu (Q19):** cizí typ se odmítne při startu session, cizí WireGuard se jménem `wtN` start služby považuje za zbytek po pádu a smaže ho.
- **Foreground (Q20, Q25):** zůstává jednoprofilový a vedle daemonu s gate se odmítne. Foreground spuštěný vedle startujícího daemonu může přijít o state soubor a link.
- **`ip_forward` (Q21):** s gate ho poslední session vrací na původní hodnotu.
- **Po pádu daemonu (Q22, Q24, Q27):** originály sysctl jsou jen v paměti a po pádu se ztratí, zůstane probe pravidlo 32321. Neuklizený state soubor se opakuje při každém startu a vedle běžící session `up` vrátí `FailedPrecondition`.

Panic v jedné session shodí daemon a s ním všechny sítě. Po restartu služby se obnoví session, které byly nahoře.

## Upgrade

Fork se staví a instaluje samostatně a nikdy se nepublikuje:

```bash
goreleaser release --snapshot --clean --config .goreleaser_multiprofile.yaml
sudo apt install ./dist/*.deb                        # nebo rpm
netbird version                                      # např. 0.70.1+multiprofile
```

Balíček `netbird-multiprofile` má `conflicts` a `replaces` na `netbird`, nainstaluje stejnou binárku a službu a
`/var/lib/netbird` nechá být. Oficiální repozitář se nepřidává a dotaz na `pkgs.netbird.io` je v tomto sestavení vypnutý.
Management, Signal a Relay se nemění. Konfiguraci balíčku zatím kontroluje jen test, skutečně ho nikdo nesestavil.

Bez gate se po upgradu nic nezmění. Po prvním startu s gate:

- Profil s jediným state souborem dostane slot 0, takže běží pod dosavadními názvy. Víc souborů dá slot 0 aktivnímu profilu a ostatní start uklidí.
- Vznikne `<config>/sessions.json` se sloty a požadovaným stavem. Neobsahuje tajemství. Neznámé pole nebo poškozený soubor odmítnou start služby a soubor zůstane na místě k opravě.
- Starý klient (UI, CLI) dál funguje a vidí jen `focused`. Nový klient se starým daemonem odmítne `--profile` s vysvětlením, místo aby zasáhl jeho jediné spojení.

## Vypnutí gate

```bash
sudo netbird service reconfigure --enable-concurrent-profiles=false
```

Stejně funguje `netbird service reset-params`, ten ale vrátí i ostatní uložené parametry. Změna platí po restartu
služby a odpojí všechny session. Při dalším startu:

- Uklidí se zbytky všech profilů ze state souborů, linky a izolace podle `sessions.json`.
- Automaticky se připojí jen `focused` profil, a to pod názvy ze svého configu, tedy `wt0`.
- `--profile` u `down`, `status`, `networks` a dalších vrátí chybu s návodem, `up --profile` přepne profil jako upstream a předchozí spojení ukončí.
- `sessions.json` zůstane jen ke čtení. Po opětovném zapnutí se sloty a požadovaný stav použijí znovu.

Před návratem na balíček z upstreamu nejdřív vypněte gate a restartujte službu: upstream `sessions.json` nezná a izolaci
ani linky slotů by neuklidil.
