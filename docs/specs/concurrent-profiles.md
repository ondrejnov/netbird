# Specifikace: souběžně připojené profily v NetBird klientovi

| | |
|---|---|
| **Stav** | Rozhodnutí D1 až D6 schválena 2026-11-04. Brána F0 prošla 2026-11-04: změny ze zprávy [concurrent-profiles-f0.md](concurrent-profiles-f0.md) jsou zapracované, R1 až R6 jsou rozhodnutá (viz 2.2). F1: všech 8 PR je otevřených ve forku, napojení přijde až v F3. Další krok je F2, před ním rozhodnout 2.3 |
| **Cíl** | Vlastní fork, nikoli upstream. Upstream [#446](https://github.com/netbirdio/netbird/issues/446) slouží jen jako zdroj informací. Závazný návrh je tento dokument |
| **Výchozí commit** | `3c996c91d`; odkazy `soubor:řádek` platí pro něj, před použitím je ověř. Poslední sloučený upstream: `313f71fb4` |
| **Fork** | <https://github.com/ondrejnov/netbird> |
| **Určeno pro** | Vývojového AI agenta a člověka, který schvaluje rozhodnutí |

## 1. Cíl

Jeden počítač s jedním daemonem může být připojený k více NetBird sítím najednou.
Každý profil má vlastní identitu, overlay interface, ACL, routy a DNS. Běh jednoho
profilu neovlivní ostatní, a pokud funkci nikdo nezapne, klient se chová přesně jako dnes.

### Akceptační scénář (Linux, CLI, v1)

```bash
netbird up --profile prace
netbird up --profile doma
netbird status                  # obě session Connected, každá se svým interface a IP
ping <peer-v-praci>             # projde přes wt0
ping <peer-doma>                # projde přes wt1
netbird down --profile doma     # routy, firewall i DNS profilu "prace" zůstanou beze změny
```

### Mimo rozsah v1

- NetBird Cloud: fork se používá jen se self-hosted Managementem (D7).
- macOS, Windows, FreeBSD: musí se dál kompilovat a chovat jako dnes (kromě auto-updatu, viz 2.1), funkci hlásí jako nedostupnou.
- Desktop UI: beze změny, omezení popisuje 5.7.
- Android a iOS (jeden TUN od hostitelského OS), WASM. `client/embed` zůstává beze změny.
- Foreground režim (`netbird up --foreground-mode`) zůstává jednoprofilový.
- Provoz přes overlay jiné session (tunel v tunelu, tranzit mezi sítěmi).
- Překrývající se overlay sítě (NAT, překlad). V1 je bezpečně odmítne.
- Změny Management, Signal a Relay. Práce se týká jen klienta.

## 2. Schválená rozhodnutí

| # | Otázka | Rozhodnutí |
|---|---|---|
| D1 | Architektura | **Jeden daemon, N session** (viz 3) |
| D2 | Cíl práce | **Vlastní fork** (viz 2.1) |
| D3 | Platformy v1 | **Linux** |
| D4 | Politika konfliktů | **Podle sekce 6** |
| D5 | Limit session | **Výchozí limit 4, návrh bez horní hranice** (viz 5.8) |
| D6 | Rozhraní v1 | **Jen CLI** |
| D7 | Management | **Jen self-hosted**, NetBird Cloud se nepodporuje ani netestuje |

### 2.1 Důsledky práce ve forku

- **Remote:** `origin` = `ondrejnov/netbird` (fork), `upstream` = `netbirdio/netbird` jen pro fetch. **Do `upstream` nic
  nepushuj a neotevírej tam PR.** V `gh` vždy uváděj `--repo ondrejnov/netbird`, protože `gh` u forků jinak cílí na upstream.
- **Větve:** `main` zrcadlí upstream, práce jde do integrační větve `multi-profile` přes PR.
  Upstream se slévá pravidelně pomocí merge, ne rebase, a v této specifikaci se vede poslední sloučený commit.
- **Minimální zásah do upstream souborů:** nová logika patří do nových souborů (`client/internal/hostcoord/`,
  `client/server/session*.go`), v `server.go` a `engine.go` jen tenké napojení. Extrakce session (F2) je
  nejkonfliktnější část: těsně předtím slij upstream a dokonči ji co nejrychleji.
- **Čísla polí v proto od 1000.** Upstream přidává další pole v řadě, takže stejná čísla by po sloučení
  kolidovala a na drátě by znamenala něco jiného mezi klientem a daemonem.
- **Auto-update nesmí přepsat fork.** Na Linuxu updater binárku nepřepíše (`client/internal/updater/supported_other.go`,
  stub instalátoru). Riziko je oficiální repozitář balíčků: fork se vydává pod jiným názvem balíčku a oficiální
  repozitář se nepřidává. Sestavení pro Windows a macOS musí vracet `isAutoUpdateSupported() == false`, jinak je
  přepíše oficiální release (pevné URL v `client/internal/updater/installer/`).
- **Sestavení a distribuce:** fork potřebuje vlastní build a verzi odlišitelnou od upstreamu, aby ji šlo
  poznat ve `status` a v debug bundlu.
- **CI a boti:** CodeRabbit, SonarCloud, Snyk a část workflow nemusí ve forku běžet. Co neběží, uveď v PR.
  Workflow se kvůli průchodu kontrol neupravují.
- **Pravidla z `AGENTS.md`** platí dál. Požadavek na odsouhlasený ticket nahrazuje tato specifikace,
  odchylky schvaluje její vlastník.

### 2.2 Otevřená rozhodnutí

Podrobnosti jsou v [concurrent-profiles-f0.md](concurrent-profiles-f0.md#otevřená-rozhodnutí-vlastníka). R1 až R5
vlastník schválil 2026-11-04 podle doporučení, R6 potvrdil ve stejný den.

| # | Otázka | Stav | Blokuje |
|---|---|---|---|
| R1 | Flow události a sdílené značky (I5) | Při zapnuté gate se bere jen flow s overlay adresou session v tuple, ostatní se zahodí. Flow přes routy bez overlay adresy se nereportuje | PR 15, 17 |
| R2 | Legacy routing při zapnuté gate | `up` se odmítne, pokud `AdvancedRouting()` je false, stejně jako netstack | PR 13 |
| R3 | Systémový resolver a domény Managementu | Přijaté známé omezení v1: domény Managementu session bez root handleru překládá DNS sítě, která vlastní catch-all | PR 6 |
| R4 | Odchod vlastníka exit nodu | Žádné automatické předání, provoz jde fyzickým defaultem a session dostane varování v `SystemEvent` | PR 2, 15 |
| R5 | openresolv a přepínač `-x` | `-x` zůstává, hostitelský DNS má jeden vlastník a první vyhrává | PR 6 |
| R6 | Distribuce forku (platformy, název balíčku, dotaz na `pkgs.netbird.io`) | Ve v1 jen Linux (D3), balíček `netbird-multiprofile`, který koliduje s `netbird`, a dotaz na `pkgs.netbird.io` vypnutý | PR 18 |

### 2.3 Otázky z implementace F1

Implementace zvolila uvedenou konzervativní variantu, vlastník ji může změnit.

| # | Otázka | Zvolená varianta | PR |
|---|---|---|---|
| Q1 | Selhání předání routy dalšímu vlastníkovi | Zůstává ve frontě, opakuje se při další operaci nebo přes `RetryHandovers`, bez časovače | 2 |
| Q2 | Identifikace vlastního `accept` v iptables | `-m comment --comment netbird-N` jen pro slot N | 4 |
| Q3 | Kam patří `ShutdownState` session | Slot nese state, klíč v souboru se nemění. Dva sloty ve sdíleném state manageru by si ho přepsaly, proto má každá session vlastní state soubor (PR 9, 11) | 4, 6 |
| Q4 | Předání uvolněného DNS | Bez aktivního předání, další update se stejnou konfigurací zkusí claim znovu | 6 |
| Q5 | Debian `resolvconf` | Výhradní backend jako openresolv, bez ověření | 6 |
| Q6 | Kolize DNS domény (sekce 6) | Neimplementováno, rozhraní pro zjištění kolize není známé | 6 |
| Q7 | Prefixové porovnání v ICE blacklistu | `wt1` vyloučí i `wt10`, chyba na straně vyloučení | 8 |
| Q8 | Ověření DNS na reálném resolved a NM | Harness je Alpine bez systemd, testy běží proti falešným službám na D-Bus | 6 |
| Q9 | **Vynucení I3, I4 v userspace režimu (sekce 7)** | **Rozhodnuto:** vynucení se řídí typem firewallu, jaderná izolace je povinná všude, kde existuje nativní backend | 5, 13 |
| Q10 | **`nativeRouter` v uspfilteru** | **Rozhodnuto:** routovaný paket jde do jádra, proto je v tomto režimu jaderná izolace povinná | 5, 13 |
| Q11 | Minimální jádro | `own` potřebuje jádro 5.6 a novější, na starším se session nespustí | 5 |
| Q12 | iptables bez modulů ipset | Izolace odmítne session (I6), bez fallbacku | 5 |
| Q13 | Session s v6 bez funkční v6 izolace | **Rozhodnuto:** v6 se odebere a session pokračuje na v4 | 5, 13 |
| Q14 | Opakování `Verify` | Jen po instalaci enginu, cizí pravidlo nad skokem v iptables by do té doby izolaci obešlo | 5, 13 |
| Q15 | Překryv v6 u běžící session | `Add` hlásí `IPv6Disabled`, daemon musí v6 odebrat za běhu | 5, 15 |
| Q16 | Adresy na interface jiné session mimo její prefix, např. `fe80::` | Nezahrnuto do `overlays` | 5 |
| Q17 | Formát `sessions.json` | **Schváleno:** `{version:1, sessions:[{profile, username, slot, desired}]}`, neznámé pole je poškození | 7 |
| Q18 | Explicitní `WgPort` obsazený cizím procesem | Port z alokátoru jako dnes, alternativa je odmítnutí | 7 |
| Q19 | Název kolidující s cizím linkem, který není session | Neřešeno, `wg_link_linux.go` by ho smazal a od zbytku po pádu ho odlišit neumí | 7, 13 |
| Q20 | Foreground režim a zámek `sessions.json` | Druhá instance se odmítne. Návrh: foreground `Slots` vůbec neotevírá | 7, 13 |
| Q21 | `ip_forward` po poslední session | Sdílený stav ho vrací (I7), bez gate zůstává jako dnes zapnutý | 5 |
| Q22 | Originály sysctl po pádu daemonu (I7) | Jen v paměti, po pádu se ztratí | 5, 11 |

**Nový nález, globální stav v závislosti:** `allocSetID` v `github.com/google/nftables@v0.3.0/set.go:48,505` je
nesynchronizovaný čítač procesu. Na `origin/main` ho shodí `TestEngine_MultiplePeers` pod `-race` (1 ze 4 běhů).
Souběžné session ho budou spouštět běžně, takže před PR 13 je nutné serializovat `AddSet` napříč managery v procesu,
nebo přiřazovat `Set.ID` ze sdíleného atomického čítače. Závislost se bez souhlasu nezvedá.

**Známá selhání i na čistém `origin/main`:** `TestUDPTracker_Cleanup` pod `-race` a občas čtyři testy
`TestNftablesManager*Compatibility*` v harnessu (`iptables-save` vrací prázdný výstup).

**Přiřazení pro PR 13:** předat jednu instanci `Isolation`, `HostState` a `Accounting` všem session, zdroj izolace
vyžadovat při zapnuté gate (nil odmítnout), volat `Add` před peery a `Verify` po enginu, `RemoveAll` pro oba backendy
při residual cleanupu, a `RetryHandovers` při obnově interface.

**Ověřování:** testy klienta se na hostiteli s běžícím daemonem nespouštějí. `TestLogin` bez `--daemon-addr` mluví se
skutečným socketem a přepíše jeho config. Privilegovaný harness se při ověřování oprav spouští s `-count=1`.

## 3. Architektura: proč jeden daemon

Komunita v #446 navrhuje N samostatných daemonů, protože to vyžaduje méně změn v RPC a
oddělené procesy izolují globální proměnné. V kódu ale narazí na toto:

| Problém | N daemonů | Jeden daemon |
|---|---|---|
| **Exit node A a konkrétní routa B** | Každý daemon má vlastní tabulku a pořadí `ip rule` přebije longest-prefix match, takže `0.0.0.0/0` v první tabulce zastíní specifickou routu v druhé | Sdílená tabulka `0x1BD0`, LPM platí uvnitř tabulky napříč session, routy v main mají přednost |
| **Řídicí provoz** | Každý proces má jiný `NB_FWMARK_BASE`. Pakety A nenesou značku B, takže je může zachytit tabulka B a vznikne tunel v tunelu | Sdílený `ControlPlaneMark`, veškerý řídicí provoz obchází tabulku |
| **Koordinace hostitele** (DNS catch-all, exit node, kolize overlay) | Vyžaduje meziprocesový protokol a zámky | Mutex a refcount v procesu |
| **Profily a UX** | `NB_STATE_DIR` na instanci rozbíjí dnešní model profilů, UI a CLI musí obsluhovat více socketů | Profily zůstávají, jeden socket |
| **Pád procesu** | Izolovaný | **Společný osud, slabina této varianty** |
| **Rozsah změn** | Menší v RPC, stejná práce na izolaci firewallu a DNS | Větší v `client/server` |

Část F1 opravuje i existující kolizi tabulky 7120 (#2023). Později ji lze nabídnout upstreamu,
a tím zmenšit rozdíl forku oproti upstreamu; není to podmínka.

```text
Server (daemon)
├── sessions map[SessionKey]*session     klíč = profil + uživatel
├── focused SessionKey                   = active_profile.json, cíl RPC bez selektoru
├── host *hostcoord.Coordinator          sdílené prostředky hostitele
└── daemon-global: logy, MDM, updater, sleep handler, IPC

session
├── config, ConnectClient, peer.Status, contextState
├── actCancel, clientRunning, clientRunningChan, clientGiveUpChan
├── oauthAuthFlow, extendAuthSessionFlow, jwtCache, activeCapture
└── slot (určuje interface, port, názvy firewallu)
```

`SessionKey` obsahuje i uživatele, protože legacy ID profilů nejsou mezi uživateli
unikátní (`client/server/server.go:1718`).

## 4. Co dnes brání souběhu

Zjištěno čtením kódu, části ověřil spike, viz [concurrent-profiles-f0.md](concurrent-profiles-f0.md). Backendy a režimy, které spike nespustil, jsou tam vyjmenované.

### Daemon

| Místo | Problém |
|---|---|
| `client/server/server.go:81,123-127,135` | Jediný `actCancel`, `clientRunning`, `connectClient` |
| `server.go:1120-1133` | `Up` s běžícím spojením se vrátí dřív, než přečte `ProfileName` |
| `server.go:2721`, `client/internal/connect.go:303-304` | `connect()` a `run()` znovu čtou aktivní profil. **Retry po přepnutí může spojit starý config se state souborem nového profilu**, což je zřejmě i dnešní latentní chyba |
| `client/server/state.go:140` | `RestoreResidualState` volá `FlushMarkedRoutes`, spouští se i při `Up` (`server.go:1134`), a zasáhne živé session |
| `client/cmd/up.go:340`, `client/cmd/profile.go:296` | CLI po přepnutí volá `Down` bez parametrů |

### Prostředky hostitele

| Oblast | Místo | Co se stane při dvou enginech |
|---|---|---|
| Interface | `client/iface/configurer/name.go:6`, `client/internal/profilemanager/config.go:531` | Každý profil má uložené `wt0`; `iface/device/wg_link_linux.go:44-66` existující link stejného jména smaže |
| Windows adapter | `client/iface/device/device_windows.go:18` | Pevné GUID, druhý adapter nevznikne |
| Port | `client/internal/connect.go:729,828` | `freePort` ověří a zavře socket, souběžné starty závodí |
| Routy Linux | `routemanager/manager.go:237,323`, `systemops/systemops_linux.go:144-155` | **Start i stop kteréhokoli enginu vyprázdní celou tabulku a smaže pravidla 105 a 110.** Refcounter druhého enginu o tom neví a routy neobnoví |
| Sysctl | `systemops_linux.go:64,67,68` | Globální `originalSysctl` a `sysctlFailed` se přepíší, druhý engine uloží už změněné hodnoty jako původní |
| IP forwarding | `routemanager/ipfwdstate/ipfwdstate.go:140-155` | Refcount na instanci, obnova bez koordinace |
| Hooky | `systemops/systemops_generic.go:97-99` | Cleanup smaže hooky všech enginů |
| Windows, macOS | `client/net/env_bound_iface.go:16,64`, `net_darwin.go:27-31`, `systemops_darwin.go:50,123` | Jediný `vpnInterfaceName`, sdílené `boundIface`, `flushScopedDefaults` maže všechny značené routy |
| nftables | `firewall/nftables/manager_linux.go:24-36,525-535` | Stejná tabulka `netbird`; init i close ji smažou |
| nft accept pravidla | `firewall/nftables/family_linux.go:45-47,132,158`, `chains_linux.go:339-413,474-490` | `init` enginu B smaže všechny konstantní tagy včetně tagů A a vloží své. A ztratí průchod a monitor ho neobnoví, protože tag už vidí. Stop kterékoli session smaže pravidla všech |
| nft cizí tabulky | `firewall/nftables/chains_linux.go:539-565`, `external_chain_monitor_linux.go:176-190` | Engine vkládá `accept` do tabulek ostatních session i do izolační tabulky |
| nft název tabulky | `firewall/nftables/manager_linux.go:32-37` | `NB_NFTABLES_TABLE` je procesová, název tabulky slotu musí jít parametrem |
| nbnet | `net/env_linux.go:23-27,77-81,111-125`, `internal/connect.go:230` | `nbnet.Init` při každém startu session přepisuje globální přepínač. Probe pravidlo s `NLM_F_EXCL` přepne celý proces na legacy routing |
| Legacy hooky | `systemops_linux.go:180,208`, `systemops_generic.go:97-101,330-333`, `net/dialer_dial.go:80` | V legacy režimu spouští dial A hooky i refcounter B, stop B může smazat sdílenou exkluzní routu |
| Flow | `internal/netflow/conntrack/conntrack.go:356-359`, `net/fwmark.go:71` | Sdílené značky a conntrack hostitele: flow sítě B odchází do Flow služby A (kernel režim) |
| Conntrack čítače | `internal/netflow/conntrack/sysctl.go:16-46` | `nf_conntrack_acct`: příznak na instanci, stop A vypne čítače B |
| Certproof | `internal/certproof/collector.go:38,58,136`, `engine_certposture.go:31` | Sdílený slot: při souběžném sběru jedna session pošle prázdné důkazy a posture nesplní |
| DNS MTU | `internal/dns/upstream.go:58,88`, `connect.go:766` | Globální `currentMTU`: poslední zápis platí pro všechny session a jde o datový závod |
| DNS Management | `internal/dns/mgmt/mgmt.go:346-351`, `stdnet/stdnet.go:112`, `dynamic/route.go:369` | Session bez root handleru překládá přes systémový resolver, takže domény Managementu A vidí DNS sítě B, která vlastní catch-all |
| Firewalld | `firewall/firewalld/firewalld_linux.go:43-55,68-71,102-113`, `engine.go:766` | Globální `parentCtx`: zrušení B způsobí, že `TrustInterface` pro A tiše nic neudělá |
| resolvconf | `internal/dns/resolvconf_unix.go:145` | openresolv `-x`: DNS má jen poslední session |
| iptables | `firewall/iptables/family_linux.go`, `chains_linux.go:30,245,335`, `ipset_linux.go:89,96` | Pevné názvy chainů a ipsetů, druhý start smaže živé chainy |
| Windows firewall | `firewall/uspfilter/interface_allower_windows.go:41,54,77-83` | Pravidlo `Netbird` se přeskočí, pokud existuje, a smaže se podle jména |
| DNS file | `dns/file_unix.go:22,46,131-135`, `file_repair_unix.go` | Jeden `resolv.conf`, jedna záloha, repair watchery se přetahují |
| DNS macOS | `dns/host_darwin.go:26-27,98,108,170` | Klíče scutil bez identifikace session |
| DNS Windows | `dns/host_windows.go:43-68,628,749` | Prefix `NetBird-*`, mazání podle prefixu odstraní všechno |
| DNS resolved, NM | `dns/systemd_linux.go:144`, `dns/network_manager_unix.go:108` | Per-link, ale souběžné `~.` a záchyt cizího NetBird DNS jako "původního" serveru |
| SSH | `client/ssh/common.go:20` | Jeden soubor `99-netbird.conf` |

### Úniky mezi sítěmi

Tyto body **dnes nejsou chyba**, protože existuje jen jedna síť. Se dvěma sítěmi se z nich
stanou bezpečnostní problémy, a proto jsou to invarianty v sekci 7:

- **Tranzit:** routing peer má `ip_forward=1`, takže peer sítě A by mohl pakety poslat do sítě B.
- **Weak host model:** Linux doručí paket z `wt0` adresovaný IP na `wt1` lokálně.
- **Metadata:** `infoSource.Current` (`internal/engine.go:1333,1359`) vylučuje jen vlastní
  overlay adresu, takže adresa druhé sítě může odejít do Managementu první sítě.
- **ICE:** blacklist (`profilemanager/config.go:56`) porovnává podle prefixu. Interface s
  vlastním jménem by se mohl dostat do ICE kandidátů pro cizí síť.
- **Self-check rout:** `isOwnAddress` (`systemops/systemops.go:116-122`) zná jen vlastní overlay.
- **Auto-update:** Management může řídit `updateManager` (`internal/engine.go:981`),
  což je prostředek celého počítače.

## 5. Návrh řešení

### 5.1 Sloty a pojmenování

Session při prvním startu dostane **trvalý slot**: nejnižší volné nezáporné číslo. Slot se uloží,
aby prostředky zůstaly stabilní, a uvolní se až odstraněním profilu. **Číslo slotu není svázané
s limitem session:** při limitu 4 může běžet slot 7, pokud profily vznikaly postupně.

| Prostředek | Slot 0 | Slot N |
|---|---|---|
| Linux interface | `wt0` | `wtN` |
| Port | `51820` | `51820+N`, pokud je volný a do 65535, jinak volný port z alokátoru |
| nft tabulka | `netbird` | `netbird-N`, název je parametr konstruktoru; `NB_NFTABLES_TABLE` platí pro proces a určuje nejvýš základ názvu |
| Tag `accept` v cizím chainu | Beze změny | Suffix `-N`. Start a stop mažou jen přesně vlastní tag |
| iptables chain, ipset | beze změny | suffix `-N` (rezerva viz 5.8) |

Windows GUID a netsh, macOS `utun` a scutil řeší až pozdější rozšíření na další platformy.

**Slot 0 musí být bajt po bajtu shodný s dneškem.** Na tom stojí zpětná kompatibilita.

- `config.WgIface == WgInterfaceDefault` znamená "automaticky" a použije se jméno slotu.
  **Hodnota se nezapisuje zpět do configu.**
- Explicitní vlastní název se respektuje. Kolize s běžící session znamená odmítnutí, nikdy smazání linku.
- Stejně se chová `WgPort`. Porty a sloty alokuje koordinátor pod krátkým zámkem `bringUpMu`, který
  serializuje jen alokaci, aby se odstranil závod ve `freePort`. Rosenpass má stejný vzor. Zámek se nedrží
  přes login ani síťové čekání, souběh celých startů omezuje 5.8.
- Slot se uloží v novém souboru `<base>/sessions.json` spolu s požadovaným stavem. Formát
  profilových configů se **nemění**.

### 5.2 `hostcoord`: koordinátor prostředků hostitele

Nový balíček `client/internal/hostcoord`, sdílený singleton v daemonu. Předává se závislostí,
nikoli jako globální proměnná. Testy a foreground režim používají vlastní instanci.

```go
type SessionKey struct {
    Profile  profilemanager.ID
    Username string
}

type Coordinator interface {
    Acquire(key SessionKey, overlay netip.Prefix, overlayV6 netip.Prefix) (*Lease, error) // ErrOverlayConflict
    ReleaseRoutingBase(key SessionKey) error // poslední uvolnění teprve maže pravidla a tabulku
    AddRoute(key SessionKey, prefix netip.Prefix, dev string) (RouteResult, error)
    RemoveRoute(key SessionKey, prefix netip.Prefix) error
    ClaimExitNode(key SessionKey) error                 // ErrExitNodeHeld
    ClaimDNSCatchAll(key SessionKey) error              // ErrDNSHeld
    SessionInterfaces() []string
    OverlayPrefixes() []netip.Prefix
}
```

Tvar rozhraní je orientační, agent ho upřesní během F1. Pravidla jsou ale závazná:

- **Pravidla 105/110, sysctl a IP forwarding** se nastaví při přechodu 0→1 a zruší při 1→0. Stejně se chová
  `nf_conntrack_acct`.
- **`nbnet.Init`** běží jednou při startu daemonu, před první session. `CheckFwmarkSupport` nepřepíná globální
  proměnnou.
- **Vlastník exit nodu** vlastní i `unreachable ::/0` ve sdílené tabulce. Výchozí prefixy se po odchodu vlastníka
  nepředávají (R4).
- **Sdílená tabulka `0x1BD0`, routy rozlišené přes `dev`.** Stejný prefix ze dvou session
  nainstaluje jen vlastník. Po uvolnění se automaticky nainstaluje další v pořadí, aby se
  neopakoval problém refcounteru, který volá add jen při přechodu 0→1.
- **`Init` ani `Stop`** už nesmí volat plošný `CleanupRouting`, pokud běží jiná session.
- **Residual cleanup po pádu** běží při startu daemonu pro všechny profily ze `sessions.json`,
  **než** vznikne první session. Cleanup při `Up` smí řešit jen vlastní state soubor a nesmí
  volat `FlushMarkedRoutes`, pokud běží jiná session.
- Starší state soubory bez čísla slotu patří slotu 0.

### 5.3 DNS

| Backend | Match domény | Catch-all (`RouteAll`) |
|---|---|---|
| systemd-resolved | Per-link. Dotaz jde na všechny linky se shodnou doménou, pozitivní odpověď vyhrává, jméno v obou sítích je závod, chybový rcode určuje jedna linka, nereagující server blokuje negativní dotazy až 120 s. Ověřeno na systemd 257 | Jeden vlastník |
| NetworkManager | Per-link, neověřeno | Jeden vlastník |
| resolvconf | openresolv se kvůli `-x` chová jako `file`: hostitelský DNS má jedna session, první vyhrává (R5). Debian `resolvconf` neověřeno | Jeden vlastník |
| `/etc/resolv.conf` (file) | Nejde sloučit: **hostitelský DNS má jen jedna session** | Jeden vlastník |

- `captureOriginalNameservers` musí vynechat **všechny** NetBird interfaces.
- Session bez hostitelského DNS dál funguje přes IP a hlásí varování v `SystemEvent`.
- Sloučený zapisovač `resolv.conf` a sdílený fan-out resolver jsou mimo v1.
- Domény Managementu u session bez root handleru překládá DNS sítě, která vlastní catch-all. V1 to přijímá jako
  známé omezení (R3).

### 5.4 Daemon: vrstva session

1. Identita se předává parametrem. Pod `session` nesmí nikdo číst aktivní profil.
   Přidej `GetStatePathFor(key)` a `connect.go:303-304`, `server.go:2721` přestanou číst stav profilu.
2. `Server` drží `sessions` a `focused`. Pořadí zámků: `guardedConfigMu` → `Server.mutex` → `session.mu`.
   Rozšiř `client/server/lock_order_test.go`.
3. `contextState` je na session, ne v `rootCtx` (`client/cmd/service.go:103`).
4. Sleep handler a MDM restart procházejí všechny session.
5. `updateManager` ovládá jen `focused` session; ostatní dostanou `nil`. V sestavení forku platí 2.1.
6. `localMetrics` dostane label `profile`, debug bundle pokryje všechny session zvlášť.
7. `currentMTU` je pole resolveru z configu session. `TrustInterface` dostává kontext parametrem. Certproof při
   platném držiteli slotu čeká s kontextem a nevrací prázdné důkazy.
8. Běžná chyba session (login, retry, konflikt) nesmí ovlivnit ostatní. Panic takto izolovat
   nejde: `recover` chytí jen vlastní gorutinu a engine jich spouští mnoho, takže panic ukončí
   celý daemon. Řeší se to obnovou všech session ze `sessions.json` po restartu služby.

### 5.5 Feature gate

`netbird service install --enable-concurrent-profiles` podle vzoru `--enable-capture`
(`client/cmd/service.go:84`, `client/cmd/service_params.go`), **ve výchozím stavu vypnuto**.

| | Gate vypnutá | Gate zapnutá |
|---|---|---|
| `Up(profil)` | Přepne profil jako dnes | Spustí další session |
| `SwitchProfile` | Jako dnes | Změní jen `focused` |
| RPC se selektorem jiného než aktivního profilu | `FailedPrecondition` | Cílí na danou session |

Na jiné platformě než Linux gate odmítne start služby se srozumitelnou chybou. Změna gate platí
po restartu služby. Po vypnutí se automaticky připojí jen `focused`. Nová MDM direktiva je mimo v1.

### 5.6 Proto (`client/proto/daemon.proto`)

Pouze přidávání polí, stávající čísla se nemění. **Nová pole v existujících zprávách začínají
od 1000** (viz 2.1). Po změně spusť `client/proto/generate.sh`, vygenerované soubory needituj.

```proto
message SessionSelector {
  string profile = 1;   // handle: ID, unikátní prefix ID nebo název
  string username = 2;
}

message DownRequest {
  optional SessionSelector session = 1000;
  bool all = 1001;
}

message StatusRequest {
  // ...stávající pole 1 až 3
  optional SessionSelector session = 1000;
}

message StatusResponse {
  // ...stávající pole 1 až 4 vždy popisují focused session
  repeated SessionStatus sessions = 1000;
}

message SessionStatus {
  string profile_id = 1;
  string profile_name = 2;
  string status = 3;
  string interface_name = 4;
  string overlay_ip = 5;
  bool focused = 6;
  optional string conflict = 7;  // overlay, exit_node, dns, interface
  FullStatus full_status = 8;    // jen při getFullPeerStatus
}
```

- Volitelný `SessionSelector` přidej do: `WaitSSOLogin`, `ListNetworks`, `SelectNetworks`,
  `DeselectNetworks`, `TracePacket`, `StartCapture`, `GetPeerSSHHostKey`, `RequestJWTAuth`,
  `WaitJWTToken`, `RequestExtendAuthSession`, `WaitExtendAuthSession`, `DismissSessionWarning`,
  `ExposeService`, `ListStates`, `CleanState`, `DeleteState`. Dohledej i další při implementaci.
- `Profile`: přidej `connection_status`; `is_active` nadále znamená `focused`.
- `SystemEvent`: přidej `profile_id`.
- `GetFeaturesResponse`: přidej `concurrent_profiles_enabled` a `max_sessions` (0 = bez limitu).
- **Bez selektoru vždy `focused`.** Starý klient tak vidí jednu síť jako dosud.
- `ForwardingRules` v serveru není implementovaný (`client/proto/daemon.proto:518`), ponech ho.

**Oprávnění (v handleru, ne v klientovi):** identita přichází z `ipcauth.CallerIdentity(ctx)`,
nikdy z pole `username`. Neprivilegovaný volající může řídit a číst jen své a sdílené
default session. Pokud identitu nelze určit, požadavek na cizí session se **odmítne**.
`Down` a `Status` bez selektoru se chovají jako dnes. Rozhraní je novým bezpečnostním
povrchem, proto ho schvaluje člověk.

### 5.7 CLI

| Příkaz | Chování při zapnuté gate |
|---|---|
| `netbird up --profile X` | Přidá session X, ostatních se nedotkne (`cmd/up.go:340` přeskočí `Down`) |
| `netbird down [--profile X \| --all]` | Bez parametru jen `focused` a vypíše, co dál běží |
| `netbird status [--profile X]` | Souhrn všech session; JSON přidá `sessions`, stávající pole beze změny |
| `netbird profile select X` | Změní `focused`, nevolá `Down` (`cmd/profile.go:296`) |
| `netbird profile list` | Přidá stav připojení |
| `netbird profile remove`, `logout` | Pro běžící session vrátí chybu, dokud ji uživatel neodpojí |
| `networks`, `debug`, `ssh`, `expose` | Přidají `--profile`, výchozí je `focused` |

**Desktop UI (známé omezení v1):** UI zůstává beze změny a vidí jen `focused`. Přepínač profilů
v UI (`client/ui/services/profileswitcher.go`) přepne a zavolá `Down`, který při zapnuté gate cílí
na nový `focused`. **Původní session tak poběží dál a v UI nebude vidět**, ukáže ji jen
`netbird status`. Chování pokryj testem a uveď v dokumentaci.

### 5.8 Příprava na neomezený počet session

Limit je dnes 4, ale jediné, co smí počet omezovat, je **jedna kontrola v `Server`**:

- Limit přichází jako parametr konstruktoru s výchozí hodnotou `defaultMaxSessions = 4`, **0 znamená
  bez limitu**. Veřejný flag přibude až se zrušením limitu; scale test si hodnotu předá sám.
- **Zakázáno:** pole pevné velikosti, rozsahy podle limitu, předpoklad o maximálním čísle slotu nebo
  jednociferném suffixu.
- **Žádný prostředek hostitele se nepřiděluje na session, pokud není nezbytný.** Fwmarky, routovací
  tabulka a pravidla 105/110 zůstávají sdílené. Sdílené značky proto neurčují session, flow se filtruje podle overlay adresy (R1).

| Prostředek | Kapacita | Požadavek |
|---|---|---|
| Název interface | `wt` + číslo, limit Linuxu 15 znaků | Bez reálného omezení, jméno vždy validuj |
| Chain iptables | Nejdelší `NETBIRD-RT-MSSCLAMP` má 19 znaků z 28 | Na suffix zbývá 9 znaků, generátor názvu to kontroluje |
| ipset | `nb-` + 8 hex + `-v6` má 14 znaků z 31 | Suffix je nutný: název je hash obsahu, stejné sety ve dvou session by jinak byly jeden objekt |
| Port | Omezený rozsah | Alokátor s kontrolou rozsahu a obsazenosti, bez spoléhání na `51820+N` |
| Izolace I3, I4 | Roste s počtem session | **Jedna izolační tabulka s množinami `ifaces`, `overlays` a `own` (`ifname . prefix`), ne pravidla pro každou dvojici.** Příchod a odchod session mění jen množiny. Všechny NetBird tabulky se vyloučí z `findExternalChains`. Správnost nezávisí na pořadí tabulek |
| Hooky nftables | Každá tabulka se vyhodnocuje na paket | Změřit ve scale testu |
| DNS listener | Na vlastní overlay IP je port 53 volný, jinak fallback | Fallback na jiný port nesmí tiše vypnout DNS, viz `supportCustomPort` |
| Restart při změně sítě | Všechny session najednou | Omezený souběh celých startů vlastním omezovačem, `bringUpMu` chrání jen alokaci. Jedna pomalá session neblokuje ostatní donekonečna |

**Kritérium pro zvýšení limitu:** scale test s 8 a 16 session v netns projde bez porušení invariantů
a změřená paměť, CPU a latence paketů jsou zaznamenané v této specifikaci.

## 6. Politika konfliktů

| Konflikt | Chování v1 |
|---|---|
| **Overlay IPv4 se překrývá** | Druhá session se **nespustí**: `backoff.Permanent`, `conflict=overlay`, srozumitelná hláška. Kontrola proběhne po loginu a před vytvořením enginu, znovu při změně adresy z Managementu. Dvě sítě z náhodného rozsahu mají shodný /16 s pravděpodobností 1/64 (`management/server/types/network.go:44-48`), takže se to reálně stane |
| Overlay IPv6 se překrývá | Nová session přeskočí v6 a pokračuje na v4 (IPv6 je soft feature) |
| Stejný prefix routy | Vlastní ho první session, po jejím odchodu přejde na další. Varování v `SystemEvent` |
| Routa pokrývá overlay jiné session | Routa se odmítne (rozšíření `isOwnAddress` na `OverlayPrefixes()`) |
| Exit node | Jeden v celém počítači, první vyhrává. Ruční výběr v další session vrátí `FailedPrecondition`, auto-apply se přeskočí s varováním. Po odchodu vlastníka se nepředává, provoz jde fyzickým defaultem, varování v `SystemEvent` (R4) |
| Stejná DNS doména | systemd-resolved: chování podle 5.3, při kolizi jména varování (rozhraní pro zjištění kolize spike netestoval). Ostatní: doménu má první session (R5), jména druhé nefungují, IP ano, varování |
| DNS catch-all | Jeden vlastník, první vyhrává |
| Limit session (výchozí 4) | `up` vrátí `ResourceExhausted` |

**Známé omezení:** dvě self-hosted sítě se shodnou DNS doménou fungují na systemd-resolved jen pro jména
bez kolize, ostatní backendy doménu dávají jedné session. Správce self-hosted Managementu se tomu vyhne vlastní
doménou (`--dns-domain`, `dns_domain` v nastavení účtu), překryv overlay sítí řeší změnou `network_range`.

## 7. Závazné invarianty

Každý invariant musí mít test.

| ID | Invariant |
|---|---|
| I1 | Při vypnuté gate se chování nezmění: stejné názvy, stejná pravidla, stejný formát souborů |
| I2 | Start, stop, restart ani pád session nezmění routy, firewall a DNS jiné session |
| I3 | **Peer z A nedosáhne do B:** forward mezi NetBird interfaces je zakázaný, a to i na routing peeru. Test běží se skutečnými enginy, včetně route ACL povolující cíl v druhé síti, a ověřuje průchod paketu, nejen přítomnost pravidla |
| I4 | **Peer z A nedosáhne na lokální službu přes IP sítě B:** drop při `iif=A`, `daddr∈overlay B`. Test jako u I3 |
| I5 | Adresy a flow jiné session neodchází do Managementu, Signalu, Flow služby ani ICE kandidátů |
| I6 | Selhání bezpečnostní kontroly znamená odmítnutí, nikdy průchod. Pokud nejde nainstalovat izolační pravidla, session se nespustí. Izolace se ověřuje i po instalaci enginu |
| I7 | Po ukončení poslední session i po pádu se hostitel vrátí do původního stavu |
| I8 | Změna ve druhé session nespustí restart jiné session přes `networkmonitor` |
| I9 | Secrets a tokeny patří jedné session. JWT cache ani SSO flow se nesdílí |
| I10 | Starý klient funguje s novým daemonem a nový klient se starým (`GetFeatures`) |

**I3 a I4 musí platit ve všech režimech. Vynucení se řídí typem firewallu (Q9, Q10):**

| Režim | Vynucení |
|---|---|
| Nativní firewall (kernel i userspace bind) | Povinně nftables/iptables izolace |
| Bez nativního firewallu | `uspfilter` a forwarder |
| netstack | Při zapnuté gate se ve v1 nepovoluje, `up` vrátí srozumitelnou chybu |
| legacy routing | Při zapnuté gate se nepovoluje, `up` vrátí srozumitelnou chybu (R2) |

**I8:** Linux monitor sleduje jen default routy v main tabulce (`networkmonitor/check_change_linux.go:39`).
`GetNextHop` musí vynechat všechny NetBird interfaces.

## 8. Plán po fázích

PR proti větvi `multi-profile` ve forku: cca do 400 řádků a 20 souborů, jeden účel, titulek
`[client] ...`. Malé PR tu nejsou kvůli upstreamu, ale kvůli revizi a slévání.

### F0: Spike (žádný produkční kód)

Prototyp v jednorázové větvi, testovat jen přes `make test-privileged` nebo ve VM.

Výstup je krátká zpráva s odpověďmi:

1. Koexistují dvě nftables tabulky se stejným hookem a prioritou podle očekávání?
2. Jak se chová systemd-resolved při shodné routing doméně na dvou linkách, včetně NXDOMAIN?
3. Funguje sdílená tabulka a LPM s exit nodem A a routou B? Jak se chová `suppress_prefixlen`?
4. Je možné změnit rozsah sítě a DNS doménu v Managementu, a je to dostupné v cloudu?
5. Mají `wireguard-go` a `nbnet` další globální stav, který tento průzkum nenašel?
6. Jak updater získává balíčky a jak ho v sestavení forku vypnout nebo přesměrovat?

**Brána:** vlastník zprávu přečte. Pokud odpověď zpochybní sekci 5 až 7, návrh se upraví před F1.
**Prošlo 2026-11-04**, zpráva je v [concurrent-profiles-f0.md](concurrent-profiles-f0.md). Otázka 4 je díky D7
zodpovězená pro self-hosted, cloud se neověřuje.

### F1: Izolace hostitele (slot 0 beze změny, gate zatím neexistuje)

| PR | Obsah | Hotovo, když |
|---|---|---|
| 1 | `hostcoord` a refcount routing base, `originalSysctl` na instanci | Dva `SysOps` v netns: stop prvního nezmění routy druhého |
| 2 | Sdílené routy s vlastnictvím a předáním, cleanup bez plošného flushe | Test předání vlastnictví |
| 3 | Název nft tabulky ze slotu, tagy a `isExternalChain` podle interface | Dva managery v netns, nezávislý stop |
| 4 | Suffix iptables chainů a ipsetů | Totéž pro iptables |
| 5 | Izolace I3, I4 a výjimka rout (`OverlayPrefixes`) | Pakety v netns mezi sítěmi se zahodí |
| 6 | DNS: resolved a NM, záchyt originálů, vlastník catch-all | Dvě session v resolved, stop nesmaže cizí konfiguraci |
| 7 | Zpracování `sessions.json`, sloty a porty, odlišení auto a explicitního interface | Migrace starých state souborů, restart zachová slot |
| 8 | Filtry I5: `infoSource`, ICE blacklist | Test odeslaných metadat |

U všech PR ve F1 platí: stejné chování ostatních platforem a žádná omezení z 5.8. F1 musí pokrýt i iptables
a `uspfilter`, které F0 neověřil. PR závislé na otevřeném rozhodnutí (viz 2.2) čekají.

### F2: Refaktor daemonu (stále jedna session, beze změny chování)

| PR | Obsah |
|---|---|
| 9 | Identita parametrem, odstranění čtení aktivního profilu pod session. Regresní test na závod retry a přepnutí |
| 10 | Extrakce struktury `session` z `Server`, s rozdělením na menší PR podle skupin polí |
| 11 | Stav `contextState` na session, residual restore podle profilu při startu daemonu |

### F3: Více session za gate (Linux)

| PR | Obsah |
|---|---|
| 12 | Proto: selektory, `SessionStatus`, features (samostatné PR s výstupem generátoru) |
| 13 | Feature gate a mapa session, životní cyklus |
| 14 | Směrování RPC podle selektoru a oprávnění z `CallerIdentity` |
| 15 | Detekce konfliktů a `conflict` ve stavu, exit node, varování |
| 16 | CLI (`up`, `down`, `status`, `profile`) |
| 17 | Metriky, debug bundle, SSH config, auto-update jen z `focused` |
| 18 | Fork: build, označení verze, vypnutí nebo přesměrování auto-updatu |
| 19 | Scale test (8 a 16 session) a záznam výsledků podle 5.8 |

**Brána v1:** `e2e/` test se dvěma Management instancemi prochází a akceptační scénář funguje.
Před zapnutím gate v provozu proběhne bezpečnostní revize I3 až I6 a oprávnění RPC.

### F4: Dokumentace a provoz

Dokumentace ve forku: zapnutí gate, známá omezení ze sekce 6 a 5.7, řešení konfliktu overlay sítí.

### Po v1 (vyžaduje nové rozhodnutí)

- **Zrušení limitu:** podle kritéria v 5.8.
- **Desktop UI:** tray a stránky pro více session, stav indexovaný podle `profile_id`, fronta SSO dialogů.
  Go: `client/ui/tray*.go`, `client/ui/services/{daemon_feed,profileswitcher,connection}.go`.
  Frontend: `contexts/{Profile,Status,Networks}Context.tsx`, `lib/connection.ts`.
- **macOS:** názvy `utun`, scutil se slotem, `flushScopedDefaults`, `boundIface` refcount, split `/1`.
- **Windows:** GUID z `SessionKey`, netsh pravidla, NRPT, `vpnInterfaceName` jako množina, route cache.
- **FreeBSD:** route flagy a marked flush.
- **DNS:** fan-out resolver pro sdílené domény jako `netbird.cloud`.

## 9. Testy

| Vrstva | Co ověřit |
|---|---|
| Unit | Alokace slotů, předání vlastnictví, selektor, oprávnění včetně neznámé identity, zamykání |
| Privileged (`make test-privileged`, netns) | Dva enginy: routy, nft, iptables, I2 až I4, I7, pád a residual cleanup |
| E2E (`e2e/`) | Dvě Management instance, data mezi peery v obou sítích, odmítnutí overlappu |
| Kompatibilita | Starý CLI proti novému daemonu, gate vypnutá se shoduje se snapshotem pravidel z `main`, UI přepínač při zapnuté gate |
| Scale | Injektovaný limit, 8 a 16 session: invarianty, předání rout, vznik a zánik session, měření podle 5.8 |
| Stres | 100× up/down jedné session při provozu druhé, `go test -race` na `client/server` a `client/internal/...`, souběžný start, MTU a certproof |
| Cross-build | Linux, macOS, Windows, FreeBSD, Android, iOS, WASM |

Testovat reálné chování: paket v netns, pravidlo po zápisu, route po stopu. Nejdřív test, který
selže ze správného důvodu, až potom oprava.

## 10. Pravidla pro agenta

**Před prací přečti:** `AGENTS.md`, `CONTRIBUTING.md`, tuto specifikaci. Po každém PR aktualizuj
její stav a nové poznatky.

**Zastav se a zeptej člověka, když:**

- Se má odchýlit od sekcí 2 a 5 až 7, zejména u `daemon.proto`, CLI nebo service flagů, formátu
  souborů, routingu, firewallu, DNS nebo oprávnění, případně když tam daný případ není popsaný.
- Potřebuješ přidat nebo zvednout závislost.
- Máš zmírnit kontrolu kvůli průchodu testu, nebo chceš force-push či obejít hooky.
- Zjistíš, že slot 0 nelze udržet shodný s dneškem.

**Neporušuj:**

- `netbird up` nikdy nespouštěj na hostiteli s důležitou konektivitou, jen ve VM nebo kontejneru.
- Privilegované testy pouštěj jen přes `make test-privileged`.
- Needituj `*.pb.go`, `*.gen.go` ani mocky.
- Čísla polí v proto se nesmí měnit ani odstraňovat, nová pole začínají od 1000.
- Nic nepushuj do `netbirdio/netbird` ani tam neotevírej PR nebo komentář.
- Nepiš kód závislý na otevřeném rozhodnutí ze sekce 2.2.
- `sessions.json` nesmí obsahovat secrets a daemon s ním pracuje jako s daty od root procesu.
- Žádné nové `os.Setenv` pro konfiguraci session; env proměnné jsou v rámci procesu sdílené.
- Žádná nová globální proměnná se stavem session.
- Zapiš IP a hostname nejvýše na úrovni debug.

**Definition of Done pro každé PR:** `go fmt`, `make lint-all`, `make test-unit`, relevantní
`make test-privileged`, `go test -race` na dotčených balíčcích, dvoufázová analýza závodů,
cross-build, odkaz na tuto specifikaci, vyplněná PR šablona. Zelené CI a komentáře botů tam, kde
ve forku běží; co neběží, uveď v PR výslovně.

## 11. Rizika

| Riziko | Dopad | Opatření |
|---|---|---|
| Regrese u uživatelů s jedním profilem | Vysoký | Slot 0 beze změny, gate, snapshot test proti `main` |
| Upstream vyřeší #446 jinak | Vysoký | Sledovat #446 a slévat pravidelně; při změně směru přehodnotit před dalším slitím |
| Rozjetí forku vůči upstreamu | Vysoký | Pravidla z 2.1, nová logika v nových souborech, pravidelné slévání |
| Auto-update přepíše fork oficiální binárkou | Vysoký, na Linuxu neověřeno | F0, případně PR 18 před prvním nasazením |
| Omylem push do upstreamu | Střední | `origin` je fork, push URL `upstream` je zablokovaná, v `gh` vždy `--repo` |
| Únik provozu mezi sítěmi | Vysoký | I3, I4, I6, testy paketů ve všech režimech, security review před F3 |
| Bouře restartů přes network monitor | Střední | I8, omezený souběh startů (5.8) |
| Panic shodí všechny sítě | Střední | Nelze plně zabránit (viz 5.4); residual cleanup a obnovení session ze `sessions.json` po restartu služby |
| Sdílená DNS doména omezí UX | Nízký | Self-hosted správce nastaví vlastní doménu (D7), varování, případný fan-out resolver později |
| Dlouhá řada PR a konflikty v `server.go` | Střední | Malé PR, slití upstreamu těsně před F2, F2 co nejrychleji za sebou |
