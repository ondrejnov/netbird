# F0: zpráva ze spiku souběžných profilů

Commit `3c996c91d`. Nezávislá kontrola výsledků agentů, 2026-11-04.

**Stav po bráně (2026-11-04):** vlastník schválil navržené změny specifikace a zapracoval je. Fork se používá jen se self-hosted Managementem (D7), ověření cloudu z Q4 tím odpadá. R1 až R6 zůstávají otevřené. Verdikt níže popisuje stav před bránou.

**Verdikt pro bránu F0: do F1 zatím nejít.** Sekce 5 až 7 je nutné upravit (Q1, Q2, Q5) a otázka 4 není plně zodpovězená, protože dostupnost v cloudu nikdo na účtu neověřil. Sdílená tabulka a LPM (Q3) potvrzují architekturu D1. Největší problémy: izolace I3/I4 nainstalovaná jako další nft tabulka se dá obejít, flow události jedné sítě odcházejí do druhé a souběžný start přepne celý proces na legacy routing. Vlastník musí před F1 rozhodnout R1 až R6 (konec zprávy) a ověřit cloud na účtu. Selhaní agenti: žádní. Otázky bez výsledku od agentů: žádné, ale viz Q4.

| Q | Odpověď | Jistota | Dopad na spec |
|---|---|---|---|
| 1 | Tabulky koexistují, drop vždy platí, I3/I4 z množin fungují, ale engine do izolační tabulky vloží accept před drop | spuštěno | **Ano:** 5.1, 5.8, I3, I4, sekce 4 |
| 2 | Shodná doména na resolved funguje pro jména jedné strany. Kolize jmen je závod, chybový rcode určuje jedna linka, nereagující server blokuje negativní dotazy 120 s | spuštěno (resolved 257) | **Ano:** 5.3, 6 |
| 3 | Sdílená 7120, LPM i `suppress_prefixlength 0` fungují. Routy v main mají přednost před čímkoli v 7120 | spuštěno | Ne, jen doplnění 5.2, 6 a otevřené R4 |
| 4 | Management: ano, obojí. Cloud: dokumentace to tvrdí, účet nikdo nezkoušel | z kódu; **cloud neprůkazné** | Ne, cloud zůstává otevřený |
| 5 | wireguard-go čistý, klient ne: 8 nálezů, z toho 2 nově potvrzené spuštěním | spuštěno N1, N2; zbytek z kódu | **Ano:** 5.2, 5.3, 5.8, I5, tabulka režimů v 7 |
| 6 | Linux updater binárku nepřepíše (stub). Riziko je oficiální repozitář balíčků a buildy pro Windows a macOS | z kódu; apt/dnf vyvozeno | Ne pro 5 až 7, **ano pro 2.1** |

Co nikdo nespustil: iptables backend, `uspfilter` a forwarder (I3/I4 v userspace), NetworkManager, Debian `resolvconf`, skutečný WireGuard, skutečný DNS server NetBirdu, dvě session v jednom procesu daemonu, IPv6 množiny I3/I4, náklady hooků, jiné jádro než 6.8.0 a jiný systemd než 257. F0 předepisuje `make test-privileged` nebo VM a prototyp ve větvi. Běželo se v Docker kontejnerech (`NET_ADMIN`, část i `SYS_ADMIN`) a přes `go build -overlay`, větev nevznikla.

## Q1: nftables tabulky

Odkazy sedí, výstupy jsem porovnal s `/tmp/nb-f0/net/repro.out`.

- Pořadí: naposledy zaregistrovaná jde první (`repro.out:143,146`). Nic na něm nesmí stát.
- Accept nekončí zpracování, drop ano, v obou pořadích (`repro.out:151-155`).
- Množiny: `pocet pravidel ... = 5 (beze zmeny)`. Množina `own` (`ifname . ipv4_addr`) je nutná, jinak I4 zahazuje přístup A na vlastní overlay IP.
- **Obejití:** `isExternalChain` (`client/firewall/nftables/chains_linux.go:539-565`) vylučuje jen vlastní tabulku, `firewalld` a iptables tabulky. Filter chain na forward/input v jiné NetBird nebo izolační tabulce dostane na začátek `iifname wtN accept`. Stane se to při startu i z monitoru po vzniku nového chainu (`external_chain_monitor_linux.go:176-190`), takže nepomůže ani pořadí vytvoření. `repro.out:224,226`: `B->A OK` i s nbiso.
- **Upřesnění oproti agentovi:** `B->A` v tomto testu prošlo, protože engine B měl route ACL na B->A. `A->B` bez ACL zahodila vlastní tabulka. Jde tedy o případ routing peeru, který I3 výslovně pokrývá.
- Drop v prerouting (priority -300) držel (`repro.out:250`), ale nepokryje I3 pro cíl mimo overlay prefixy.
- Tagy: engine při `init` smaže všechny konstantní tagy (`family_linux.go:132`, `chains_linux.go:474-490`), pak vloží své. Sekce 4 tvrdí opak, že B své pravidlo nevloží. Platí to jen pro monitor (`existing`, `chains_linux.go:339`). Výsledek: `po startu engine 2: A->LAN ZAHOZEN B->LAN OK` a stav trvá (`repro.out:199-206`). Stop jedné session smaže stejným kódem pravidla druhé (`family_linux.go:158`, z kódu, nespuštěno).
- Po smazání tabulky jednoho enginu prošlo `A->B(transit): OK` (`repro.out:161`), per-engine drop tedy izolaci nezajišťuje.

Zopakování: `sh /tmp/nb-f0/net/reproduce.sh > /tmp/nb-f0/net/repro.out 2>&1` (jen kontejner `nb-f0-run`).

## Q2: systemd-resolved

Agent testoval `~netbird.cloud` a uvedl, že to odpovídá klientovi. Neodpovídá: zóna peerů nemá `SearchDomainDisabled` (`shared/management/networkmap/peers_custom_zone.go:29-32`), takže `MatchOnly=false` (`client/internal/dns/host.go:114`) a jde o search doménu. Proto jsem testy zopakoval s `netbird.cloud` bez vlnovky. **Závěry se nezměnily.**

| Situace | Výsledek (opakovaný běh) |
|---|---|
| Jméno zná jedna strana | `NOERROR`, dotaz jde na oba servery. Pozitivní odpověď přebije NXDOMAIN, i když přijde o 1 s později (`1.02s`) |
| Jméno znají obě strany | Závod: `27 10.1.1.100`, `13 10.2.2.200` z 40 (agent 14/6) |
| Neznámé, obě NXDOMAIN | `NXDOMAIN` |
| NXDOMAIN + SERVFAIL/REFUSED | Rcode z linky s vyšším ifindexem, obrátí se po znovuvytvoření linky (`T4a 20 SERVFAIL`, `T6c 10 NXDOMAIN`) |
| Jedna linka nereaguje, druhá NXDOMAIN | `Connection timed out`, `trvani 120 s` |
| Jedna linka nereaguje, druhá zná jméno | `NOERROR`, `0.02s` |
| `ip link del` nebo `revert` linky | Linka zmizí, druhá síť dál funguje. První dotaz po `link del` trval `4.02s` |
| Jednoslovné jméno (`resolvectl query a`) | `a: 10.1.1.1 -- link: nbA0`, přes search doménu funguje |

Vyvozeno, nespuštěno: DNS NetBirdu vrací pro neznámé jméno v zóně NXDOMAIN (`local/local.go:449-451`), REFUSED jen bez handleru (`handler_chain.go:267`). Reálný výskyt 120s blokace by vyžadoval živý interface s mrtvým listenerem.

**resolvconf (5.3 "ověřit ve spike", agent netestoval):** klient volá u openresolv `resolvconf -x -a <iface>` (`resolvconf_unix.go:145`). Spuštěno na openresolv 3.13.2: `[wt0 -x] nameserver 10.1.0.1`, `[+wt1 -x] nameserver 10.2.0.1`. **Vyhrává poslední**, po odebrání se vrátí předchozí. Bez `-x` by se sloučily oba. To odporuje 6 ("doménu má první session"). NetworkManager a Debian `resolvconf` nikdo nezkoušel.

Zopakování: viz [Příkazy kontroly](#příkazy-kontroly), původní skripty agenta jsou v `/tmp/nb-f0/dns/`.

## Q3: sdílená tabulka a LPM

Spuštěný kód `systemops.SysOps`, výstup `/tmp/nb-f0/net/q3_run.out`, odkazy sedí (`systemops_linux.go:83-86,144-155,193-199`, `routemanager/manager.go:237,323`).

- `8.8.8.8 -> wt0(A)`, `192.168.77.5 -> wt1(B)`, overlay obou přes main, `mark 0x1bd00 -> uplink(U)`, v4 i v6.
- `suppress_prefixlength 0` potlačí jen default v main. Bez pravidla 105: `LAN 198.51.100.50 -> wt0(A)` (`q3_run.out:119`). Specifická routa v main vyhraje i nad delší routou B (`198.51.100.130 -> uplink(U)`, `:98`).
- Po odebrání exit nodu jde provoz fyzickým defaultem, žádný blackhole v4 (T7).
- Stejný prefix: `netlink add route: file exists` (`:182`), potvrzuje požadavek 5.2 na vlastníka a předání.
- `CleanupRouting` jiného enginu smaže vše, potvrzuje sekci 4 (`:226-228`).
- Exit node bez v6 přidá `unreachable ::/0` do sdílené tabulky, specifická v6 routa B dál funguje.

Omezení: `nbrt` je samostatný proces na operaci a místo WireGuardu byl veth. Testuje chování jádra a skutečný kód SysOps, ne koordinátor. `rp_filter` a `src_valid_mark` z `sysctl.Setup` neověřeny. Zopakování: `reproduce.sh`, část Q3.

## Q4: rozsah sítě a doména v Managementu

Z kódu, odkazy sedí: `openapi.yml:341-351`, `account.go:386-388` (`reallocateAccountPeerIPs`), `account.go:576-588`, `accounts_handler.go:113-141`, `controller.go:1148-1156`, `management/cmd/root.go:80`, `combined/cmd/config.go:139`.

Cloud: `docs.netbird.io/manage/dns` říká "The block is randomly selected per account and can be customized", `/manage/dns/custom-zones` "in Settings > Network > DNS Domain" (ověřeno `curl`). **Na cloudovém účtu nikdo nezkoušel, proto neprůkazné.** Zopakování: `curl -sL` obou stránek a `grep -n 'network_range\|dns_domain' shared/management/http/api/openapi.yml`.

## Q5: globální stav

wireguard-go `v0.0.0-20261021152105-0de46b309cdb` (`go.mod:91`, bez replace): namátkově sedí `controlfns` jen v `init()`, `sockPath` podle jména interface a ladění bufferů volá jen `client/embed` (`embed.go:258-261,582`). Nálezy N1 až N8 jsou v další sekci, N1 a N2 jsem spustil.

**N1, spuštěno:** skutečný `conntrack.ConnTrack` session A (`wt0`, `10.1.0.0/24`) a skutečný nftables engine B na `wt1`. Bez značky `udalosti v loggeru A: 0`, s enginem B `EVENT-A type=1 src=10.2.0.2 dst=192.168.50.2 proto=ICMP dir=ingress` (`/tmp/nb-f0/review/ct.out`). Předání do Flow služby je z kódu (`logger.go:93-103,149-161`).

**N2, spuštěno:** `RuleAdd znovu (EXCL): file exists`, `init pri existujicim probe pravidle: AdvancedRouting = false`. Dvě souběžná `Init`: false v 64 z 200 kol, s `-race` v 117 z 200 a 11× `WARNING: DATA RACE` na `env_linux.go:77` (test zkoušel Init záměrně v těsné smyčce, četnost neodpovídá provozu).

Zbytek je z kódu, scénáře nespuštěny. Oprava proti agentovi je u N5 a N7, viz níže.

## Q6: updater

Z kódu, odkazy sedí.

- Linux: `isAutoUpdateSupported` vrací false (`supported_other.go:3-7`), `SetVersion` přejde na download-only (`manager.go:177-181`), instalátor je stub (`installer/installer.go:1-3,40-47`). `netbird update` existuje jen pro Windows a macOS (`cmd/update_supported.go:1`).
- Dotaz na `https://pkgs.netbird.io/releases/latest/version` (`version/update.go:18`) odchází jen po `Manager.Start`. To volá jediné místo (`server.go:2787-2793`, `event.go:19`) při `SubscribeEvents`, a ten v repu používá jen UI (`client/ui/services/daemon_feed.go`). Upřesnění oproti agentovi: čistě CLI provoz tento dotaz neposílá.
- Windows, macOS: pevné URL GitHub releasů (`installer_run_windows.go:32-33`, `installer_run_darwin.go:25`), ověřuje se oficiální podpis, takže oficiální release fork přepíše. Tag `devartifactsign` nestačí (`repourl_dev.go`: LAN adresa).
- Balíčky: nfpm `netbird`, `/usr/bin` (`.goreleaser.yaml:310-325`), repozitář přidává `release_files/install.sh:114-145`. Přepsání přes apt/dnf je vyvozené, nespuštěné.

Zopakování: `sed -n 1,7p client/internal/updater/supported_other.go`, `grep -n startUpdateManagerForGUI client/server/*.go`.

## Vyvrácené a opravené údaje

1. Q1: "tabulku slotu lze pojmenovat přes `NB_NFTABLES_TABLE`". Pod D1 neplatí. Proměnná je procesová (`manager_linux.go:32-37,67,394,531`), harness běžel jako dva procesy.
2. Q2: "konfigurace odpovídá klientovi (`~netbird.cloud`)". Klient použije search doménu. Opakovaný test závěry nezměnil.
3. Q4: "citace `network.go:44-48` je posunutá". Není, ř. 44-45 uvádí 64 podsítí a 46-50 je výběr. Citace ve spec může zůstat.
4. Q5, N5: "EDNS 1392". `ipUDPHeaderSize = 60 + 8` (`upstream.go:99`), správně 1352 pro MTU 1420. Závěr platí, 1352 je stále nad MTU 1280.
5. Q5, N7: cesta `client/client.go`. Správně `client/internal/routemanager/client/client.go:1171-1179`.
6. Q2: `specChallenged` jen na sekci 6 je málo, totéž se týká 5.3.

## Nové nálezy do sekce 4

| ID | Místo | Problém | Jistota |
|---|---|---|---|
| N1 | `internal/netflow/conntrack/conntrack.go:356-359`, `net/fwmark.go:71` | Sdílené značky a conntrack celého hostitele: **flow sítě B odchází do Flow služby A** (jen kernel režim, `netflow/manager.go:50`) | spuštěno |
| N2 | `net/env_linux.go:23-27,77-81,111-125`, `internal/connect.go:230` | `nbnet.Init` při každém startu session přepisuje globální přepínač. Probe pravidlo 32321 s `NLM_F_EXCL` způsobí, že **celý proces přejde na legacy**. Pak se přestanou značit sockety (`net_linux.go:12,28`) a `CleanupRouting` nesmaže 105/110 (`systemops_linux.go:138-140`) | spuštěno; dopad z kódu |
| N3 | `systemops_linux.go:180,208`, `systemops_generic.go:97-101,330-333`, `net/dialer_dial.go:80` | V legacy režimu spouští dial A hooky i refcounter B, stop B může smazat sdílenou exkluzní routu | z kódu |
| N4 | `internal/certproof/collector.go:38,136`, `engine_certposture.go:31` | Sdílený slot: při souběžném sběru jedna session pošle prázdné důkazy a posture nesplní (`collector.go:58`), další pokus za 5 min | z kódu |
| N5 | `internal/dns/upstream.go:58,88`, `connect.go:766` | Globální `currentMTU`: poslední zápis platí pro všechny session a jde o datový závod | z kódu |
| N6 | `internal/netflow/conntrack/sysctl.go:16-46` | `nf_conntrack_acct`: příznak na instanci, stop A vypne čítače B | z kódu |
| N7 | `internal/dns/mgmt/mgmt.go:346-351`, `stdnet/stdnet.go:112`, `dynamic/route.go:369` | Session bez root handleru překládá přes systémový resolver, takže domény Managementu A vidí DNS sítě B, která vlastní catch-all | z kódu |
| N8 | `firewall/firewalld/firewalld_linux.go:43-55,68-71,102-113`, `engine.go:766` | Globální `parentCtx`: zrušení B způsobí, že `TrustInterface` pro A tiše nic neudělá | z kódu |
| N9 | `firewall/nftables/chains_linux.go:539-565`, `external_chain_monitor_linux.go:176-190` | Engine vkládá accept do tabulek ostatních session a do izolační tabulky | spuštěno |
| N10 | `firewall/nftables/manager_linux.go:32-37` | `NB_NFTABLES_TABLE` je procesová, název tabulky slotu musí jít parametrem | z kódu |
| N11 | `internal/dns/resolvconf_unix.go:145` | openresolv `-x`: DNS má jen poslední session | spuštěno (bez klienta) |
| N12 | `systemops_linux.go:68` | `sysctlFailed` je globální jako `originalSysctl`, doplnit do řádku Sysctl | z kódu |

**Oprava řádku "nft accept pravidla":** "`init` engine B smaže všechny konstantní tagy včetně tagů A a vloží své. A ztratí průchod a monitor ho neobnoví, protože tag už vidí. Stop kterékoli session smaže pravidla všech." Text nad tabulkami "nic zatím nebylo spuštěno" nahraď odkazem na tuto zprávu.

## Navržené změny specifikace

Návrhy, nic v návrhu jsem neměnil.

1. **2.1, Auto-update:** "Linux: updater binárku nepřepíše (`supported_other.go`, stub instalátoru). Riziko je oficiální repozitář balíčků: fork se vydává pod jiným názvem balíčku a oficiální repozitář se nepřidává. Sestavení pro Windows a macOS musí vracet `isAutoUpdateSupported() == false`, jinak je přepíše oficiální release." Upravit i sekci 1: "chovat jako dnes" platí kromě auto-updatu.
2. **5.1:** "Název tabulky je parametr konstruktoru. `NB_NFTABLES_TABLE` je pro proces a určuje nejvýš základ názvu."
3. **5.2, doplnit:** "`nbnet.Init` běží jednou při startu daemonu, před první session. `CheckFwmarkSupport` nepřepíná globální proměnnou. `nf_conntrack_acct` má refcount 0→1 a 1→0. Vlastník exit nodu vlastní i `unreachable ::/0` v tabulce."
4. **5.2, accept pravidla:** "Tag v cizím chainu: slot 0 beze změny, slot N s suffixem `-N`. Start a stop mažou jen přesně vlastní tag." Slot 0 tak zůstává shodný s dneškem (I1).
5. **5.3, řádek resolved:** "Dotaz jde na všechny linky se shodnou doménou. Pozitivní odpověď vyhrává, jméno v obou sítích je závod, chybový rcode určuje jedna linka, nereagující server blokuje negativní dotazy až 120 s. Ověřeno na systemd 257." Řádek NetworkManager označit "neověřeno".
6. **5.3, řádek resolvconf:** "openresolv se kvůli `-x` chová jako `file`: hostitelský DNS má jedna session, viz R5." Debian `resolvconf` "neověřeno".
7. **5.4, doplnit:** "`currentMTU` je pole resolveru z configu session. `TrustInterface` dostává kontext parametrem. Certproof při platném držiteli slotu čeká s kontextem, nevrací prázdné důkazy."
8. **5.1 a 5.8, `bringUpMu`:** sjednotit "serializuje start" a "omezený souběh". Dnes si texty odporují.
9. **5.8, řádek Izolace I3, I4:** "Jedna izolační tabulka s množinami `ifaces`, `overlays` a `own` (`ifname . prefix`). Všechny NetBird tabulky se vyloučí z `findExternalChains`. Správnost nezávisí na pořadí tabulek."
10. **5.8, fwmarky:** doplnit rozhodnutí R1, sdílené značky neurčují session.
11. **6, řádek Stejná DNS doména:** nahradit "ověřit ve spike" textem z bodu 5 a pro kolizi jména přidat varování. Rozhraní pro zjištění kolize nebylo testováno. Do "Známého omezení" doplnit: "Na resolved fungují obě sítě pro jména bez kolize." Cloudové řešení přes `dns_domain` a `network_range` až po ověření.
12. **6, Exit node:** doplnit výsledek R4. **3:** "LPM platí uvnitř tabulky, routy v main mají přednost."
13. **7, I3, I4:** "Test běží se skutečnými enginy, včetně route ACL povolující cíl v druhé síti, a ověřuje průchod paketu, nejen přítomnost pravidla." **I5:** přidat Flow službu. **I6:** "Izolace se ověřuje i po instalaci enginu."
14. **7, tabulka režimů:** přidat "legacy routing: při zapnuté gate podle R2".
15. **9 a F3:** `-race` a test souběžného startu, MTU a certproof. F1 musí pokrýt iptables a `uspfilter`, F0 je neověřil.

## Otevřená rozhodnutí vlastníka

- **R1 Flow:** Doporučuji při zapnuté gate brát jen flow s overlay session v tuple a ostatní zahodit, protože jinak dojde k úniku I5. Cena: flow přes routy bez overlay adresy se nereportuje. Značka na session by odporovala 5.8.
- **R2 Legacy routing:** Doporučuji při gate odmítnout `up`, pokud `AdvancedRouting()` je false, stejně jako netstack. Cena: hostitelé bez podpory funkci nedostanou.
- **R3 Systémový resolver (N7):** přijmout jako známé omezení, nebo dát session pevný resolver mimo overlay? Doporučuji přijmout pro v1 a uvést v 5.3, oprava zasahuje do řídicí cesty.
- **R4 Odchod vlastníka exit nodu:** tichý přechod na fyzický default, předání další session, nebo blackhole? Spec to neřeší a 5.2 předání stejného prefixu naopak předepisuje. Doporučuji žádné automatické předání a varování v `SystemEvent`.
- **R5 openresolv:** ponechat `-x` a řešit jako jednoho vlastníka se stavem "první vyhrává" (doporučuji), nebo `-x` při gate vypnout a sloučit?
- **R6 Distribuce forku:** jen Linux ve v1? Název balíčku? Ponechat dotaz na `pkgs.netbird.io` z UI, nebo změnit `version/update.go`?
- **Ověření:** na cloudovém účtu změnit `network_range` a `dns_domain` a výsledek doplnit do Q4.
- **Bez změny:** před prvním pushem je nutné URL forku (2.1).

## Příkazy kontroly

Soubory jsou v `/tmp/nb-f0/review/`, repozitář zůstal beze změny (`git status`: jen `.ultracode/`, `docs/specs/`). Test běžel s `--network none`, sítě a firewallu hostitele se nedotkl, jen sestavení obrazů použilo síť Dockeru. Obrazy kontroly jsou smazané, po agentovi zůstal `alpine:3.20`.

```bash
R=/tmp/nb-f0/review; cd /var/www/netbird
GOPROXY=off CGO_ENABLED=0 go build -overlay=$R/overlay.json -o $R/nbinit.bin ./client/net/nbf0init
GOPROXY=off CGO_ENABLED=1 go build -race -overlay=$R/overlay.json -o $R/nbinit.race ./client/net/nbf0init
GOPROXY=off CGO_ENABLED=0 go build -overlay=$R/overlay.json -o $R/ctflow.bin ./client/internal/netflow/conntrack/nbf0ct
docker build -t nb-f0-rev-tools -f $R/Dockerfile.tools $R
docker build -t nb-f0-rev-resolved /tmp/nb-f0/dns
docker build -t nb-f0-rev-openresolv -f $R/Dockerfile.openresolv $R
docker run --rm --network none --cap-add NET_ADMIN --cap-add NET_RAW -v $R:/rev:ro nb-f0-rev-tools /rev/nbinit.bin
docker run --rm --network none --cap-add NET_ADMIN --cap-add NET_RAW -v $R:/rev:ro nb-f0-rev-resolved /rev/nbinit.race
docker run --rm --network none --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN --sysctl net.ipv4.ip_forward=1 \
  -v $R:/rev:ro -v /tmp/nb-f0/net:/work:ro nb-f0-rev-tools sh /rev/t_ct.sh
docker run --rm --network none -v $R:/rev:ro nb-f0-rev-openresolv bash /rev/t_or.sh
docker run -d --name nb-f0-rev-dns --network none --cap-add NET_ADMIN --cap-add SYS_ADMIN --tmpfs /run --tmpfs /tmp \
  -v $R/dns:/opt:ro -v $R:/rev:ro nb-f0-rev-resolved sleep infinity
docker exec nb-f0-rev-dns bash /rev/t_dns.sh; docker rm -f nb-f0-rev-dns   # stejně i t_dns2.sh v novém kontejneru
```
