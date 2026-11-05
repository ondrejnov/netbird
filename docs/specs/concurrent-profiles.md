# Specifikace: souběžně připojené profily v NetBird klientovi

| | |
|---|---|
| **Stav** | Rozhodnutí D1 až D6 schválena 2026-11-04. Brána F0 prošla 2026-11-04: změny ze zprávy [concurrent-profiles-f0.md](concurrent-profiles-f0.md) jsou zapracované, R1 až R6 jsou rozhodnutá (viz 2.2). F1: všech 8 PR je otevřených ve forku, napojení přijde až v F3. F2: PR 9 (identita parametrem), PR 10 (extrakce `session`) a PR 11 (`contextState` a residual restore) jsou hotové, viz 2.4. F3: PR 12 až PR 19 jsou hotové, stejně jako opravy nálezů ve `f3/residual-links` a `f3/flow-filter` a bezpečnostní revize, viz 2.5. Kritérium 5.8 pro zvýšení limitu je změřené a prošlo, limit zůstává 4 podle rozhodnutí vlastníka. Omezovač souběhu startů z 5.8 není implementovaný, viz otázky k PR 19 |
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
| R1 | Flow události a sdílené značky (I5) | Při zapnuté gate se bere jen flow s overlay adresou session v tuple, ostatní se zahodí. Flow přes routy bez overlay adresy se nereportuje. Hotovo ve `f3/flow-filter`, viz 2.5 | PR 15, 17 |
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
| Q6 | Kolize DNS domény (sekce 6) | Kolize jména se nezjišťuje, rozhraní není známé. Od PR 15 se varuje při shodné doméně na dvou linkách, viz 2.5 | 6, 15 |
| Q7 | Prefixové porovnání v ICE blacklistu | `wt1` vyloučí i `wt10`, chyba na straně vyloučení | 8 |
| Q8 | Ověření DNS na reálném resolved a NM | Harness je Alpine bez systemd, testy běží proti falešným službám na D-Bus | 6 |
| Q9 | **Vynucení I3, I4 v userspace režimu (sekce 7)** | **Rozhodnuto a napojeno:** vynucení se řídí typem firewallu, jaderná izolace je povinná všude, kde existuje nativní backend, viz 2.5 | 5, 13 |
| Q10 | **`nativeRouter` v uspfilteru** | **Rozhodnuto a napojeno:** routovaný paket jde do jádra, proto je v tomto režimu jaderná izolace povinná. Bez nativního backendu se session s vypnutými server routes odmítne, viz 2.5 | 5, 13 |
| Q11 | Minimální jádro | `own` potřebuje jádro 5.6 a novější, na starším se session nespustí | 5 |
| Q12 | iptables bez modulů ipset | Izolace odmítne session (I6), bez fallbacku | 5 |
| Q13 | Session s v6 bez funkční v6 izolace | **Rozhodnuto a napojeno:** v6 se odebere a session pokračuje na v4 | 5, 13 |
| Q14 | Opakování `Verify` | **Změněno revizí:** kontrola běží každých 5 s, rozdíl izolaci obnoví a když to nejde, zastaví všechny session, viz `f3/security-fixes` v 2.5 | 5, 13 |
| Q15 | Překryv v6 u běžící session | `Add` běží při každém pokusu enginu a změna adresy z Managementu engine restartuje, `IPv6Disabled` proto odebere v6 v dalším pokusu. Session, která v6 ztratila, ho po odchodu druhé session získá až po svém restartu | 5, 13, 15 |
| Q16 | Adresy na interface jiné session mimo její prefix, např. `fe80::` | Nezahrnuto do `overlays` | 5 |
| Q17 | Formát `sessions.json` | **Schváleno:** `{version:1, sessions:[{profile, username, slot, desired}]}`, neznámé pole je poškození | 7 |
| Q18 | Explicitní `WgPort` obsazený cizím procesem | Port z alokátoru jako dnes, alternativa je odmítnutí | 7 |
| Q19 | Název kolidující s cizím linkem, který není session | Úklid po pádu maže jen link typu `wireguard` se jménem slotu, viz `f3/residual-links` v 2.5. Cizí WireGuard se stejným jménem od zbytku odlišit neumí. `wg_link_linux.go` při startu session smaže cokoli se stejným jménem, s gate se proto cizí typ odmítne už v `attach`, viz `f3/security-fixes` v 2.5 | 7, 13 |
| Q20 | Foreground režim a zámek `sessions.json` | Druhá instance se odmítne. Návrh: foreground `Slots` vůbec neotevírá | 7, 13 |
| Q21 | `ip_forward` po poslední session | Sdílený stav ho vrací (I7), bez gate zůstává jako dnes zapnutý | 5 |
| Q22 | Originály sysctl po pádu daemonu (I7) | Jen v paměti, po pádu se ztratí | 5, 11 |
| Q23 | Selhání v6 části izolace u session s v6 v nainstalované rovině iptables | Add vrací chybu, pokus bez overlaye nejde v harnessu otestovat | 5 |
| Q24 | Selhaný residual `Cleanup` | Zůstává v souboru a opakuje se při startu. **Rozhodnuto:** vedle běžící session `Login` zbytek neuklízí, `CleanState` se odmítne a `Up` vrátí `FailedPrecondition`, viz 2.5 | 11, 13, 15 |
| Q25 | Foreground `netbird up` vedle startujícího daemonu | Daemon uklidí i jeho state soubor neaktivního profilu a se `sessions.json` smaže i jeho link se jménem slotu | 11 |
| Q26 | `RemoveProfile` běžícího profilu | **Rozhodnuto a opraveno** ve `f3/run-config`: `FailedPrecondition` před deregistrací. `logout` podle 5.7 zůstává na PR 16 | 11, 16 |
| Q27 | Probe pravidlo 32321 po pádu | Zůstává, od cizího nejde odlišit, proces kvůli němu nepřejde na legacy. Odporuje I7 | 9 |
| Q28 | `onMDMPolicyChange` čeká na `giveUpChan` pod `Server.mutex` | **Rozhodnuto a opraveno** ve `f3/mdm-wait`: čekání běží bez zámku, viz 2.4 | 13 |
| Q29 | Config běhu proti configu vybraného profilu v `Status`, debug bundlu a kill switchích | **Rozhodnuto a opraveno** ve `f3/run-config`: oddělené configy, viz 2.4 | 13 |

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

### 2.4 Poznatky z implementace F2

**PR 9, identita parametrem:**

- `SessionKey` je v `profilemanager`, protože `GetStatePathFor(key)` patří tam a `hostcoord` tento balíček importuje.
  `hostcoord.SessionKey` je alias na stejný typ.
- Daemon předává klíč spolu s configem do `connectWithRetryRuns` a `connect`. `ConnectClient` bere state soubor i
  vlastníka úložiště certifikátů z `WithSessionKey`. Klient bez identity (foreground, embed) dostane cestu jednou při
  vytvoření přes `WithStatePath`. Diskový klient bez cesty se odmítne spustit, na aktivní profil se nevrací.
- **Závod z tabulky v sekci 4 je užší, než vypadal.** Vnitřní smyčka `Run` drží cestu po celou dobu běhu, takže
  `ErrResetConnection` se ho netýká. Vnější retry v `connectWithRetryRuns` nastane jen po chybě před spuštěním smyčky
  (nepoužitelný klíč v configu) nebo po vyčerpání tříměsíčního backoffu. Druhé okno je mezi spuštěním gorutiny v `Up`
  a začátkem `Run`. Regresní test proto vyvolá retry nepoužitelným klíčem, který opraví v mezeře mezi pokusy.
- Větev `DisableAutoConnect` četla `s.config` v gorutině bez zámku a mohla spojit config nového profilu s klíčem
  starého. Teď používá parametry.
- `NB_DNS_STATE_FILE` přebíjí state soubor všech profilů, takže se session v F3 o jeden soubor dělí (Q3). Není
  rozhodnuto.
- Aktivní profil dál čtou jen RPC na úrovni daemonu: residual restore v `Start`, `ListStates`, `CleanState`,
  `DeleteState`, debug bundle (5.4 bod 6) a state manager `updateManager` (5.4 bod 5). `Up` a `Login` od PR 11 ne.

**PR 10, extrakce `session`:**

- Rozděleno na tři větve podle skupin polí: `f2/session-lifecycle`, `f2/session-state`, `f2/session-auth`. `Server` drží
  jednu session v poli `session` nastaveném v `New`, slot zatím není potřeba.
- `session.mu` je list: chrání jednotlivá čtení a zápisy polí, nedrží se přes volání ven a `session` nemá odkaz na
  `Server`. Sekvence „zkontroluj a proveď" zůstávají pod `Server.mutex` jako dřív, takže atomické jsou jen díky němu.
  Přechod na více session je musí přesunout, až přestane stačit globální zámek.
- `statusRecorder`, `jwtCache` a `extendAuthSessionFlow` se po `newSession` nemění a synchronizují se samy, zámek nemají.
- Čtení bez zámku v `Status`, `waitForUp`, `runProbes`, `CleanState`, `DeleteState`, přihlášení a kontrolách politik byla
  datový závod, teď jsou seřazená přes `session.mu`. Čekání v `Status` čte kanály běhu v každé iteraci, aby sledovalo
  restart z MDM.
- Na `Server` zůstává `forceAccountPrompt`, `isSessionActive`, `sessionWatcher`, `bundleCapture`, `persistSyncResponse` a
  `probeThrottle`. Zadání je neřadí k žádné skupině, jejich přesun rozhodne PR 13.
- **Závada z PR 9, opravená ve `f2/nbnet-init-once`:** sekce 8 řadí `nbnet.Init` do PR 9, ale `advancedRoutingSupported`
  zůstala nesynchronizovaná. `TestServer_SubcribeEvents` na ní pod `-race` občas selhal, i na `f2/identity` (3 ze 6 běhů).
  `TestLogin` v `client/cmd` pod `-race` selhává i bez PR 10, závod je v logování v `util/log.go`.

**`f2/nbnet-init-once`, N2 a 5.2:**

- `Server.Start` volá `nbnet.Init` hned po residual restore, stejně jako foreground v `up.go`. Klient s `WithSessionKey`
  ho nevolá. Foreground a embed ho volají při každém běhu jako dřív, protože embed nastavuje netstack přes env až v `New`.
- **Rozdíl pro jednu session, schválený zadáním:** podpora se zjišťuje jednou za běh daemonu. `down` a `up` už chybu sondy
  neopraví, je potřeba restart služby. `AdvancedRouting` platí už před první session, takže `Login` před prvním `Up`
  používá značené sockety stejně jako po `down`.
- `EEXIST` na probe pravidle znamená, že pravidla fungují. Cizí pravidlo sonda nemaže, zbytek po pádu tedy zůstane
  (není rozhodnuto, viz I7). Hledá v main stejně jako výchozí 32766, zastíní jen cizí pravidla s prioritou mezi nimi.

**PR 11, `f2/context-residual`:**

- `contextState` je na session jako `session.state`. Connect client a engine ho dál čtou přes `CtxGetState`, kontext běhu
  staví `session.runContext`. `rootCtx` žádný stav nenese, foreground, embed a mobilní klienti si ho zakládají sami.
- **Start:** `restoreResidualAtStart` uklidí state soubory všech profilů (viz `f2/residual-fixes` níže), pak jednou
  zavolá `FlushMarkedRoutes`. `sessions.json` (`<DefaultConfigPathDir>/sessions.json`) jen čte přes
  `hostcoord.StoredRecords`, bez zámku, takže instalace bez něj ho nezíská. Soubor z dřívějšího běhu s gate se
  uklidí i po jejím vypnutí. Poškozený soubor zůstane na místě a zaloguje se, ostatní soubory se uklidí.
- **`Up` a `Login`:** `restoreOwnResidual` čistí jen soubor profilu, který se spouští, a `FlushMarkedRoutes` volá, jen když
  neběží session jiného profilu.
- **Rozdíl pro jednu session, vynucený 5.2:** úklid běží až po přepnutí profilu. `Up(work)` s aktivním `default` čistí
  `work`, ne `default` jako dřív. Zbytek v `default` počká na jeho `Up` nebo restart služby, který uklidí všechny profily.
  `Up`, který skončí chybou před
  výběrem profilu (`up already in progress`, chybí config), už nečistí nic. `Login(work)`, zatímco zrušený běh `default`
  ještě nedoběhl, neflushuje; flush udělá `Up`, který po něm následuje (flush dělá něco jen na macOS a BSD).
- **Migrace:** `openSlots` přes `hostcoord.WithSlotZeroOwner` předá slot 0 podle state souborů, pokud chybí `sessions.json`
  (pravidlo viz `f2/residual-fixes` níže). Nezjistitelná existence souboru znamená odmítnutí, ne „nikdo". Bez gate se
  nevolá, proto v produkci zatím nemá volajícího: PR 13 ho zavolá při zapnuté gate před `restoreResidualAtStart`.
- **Rozhodnutí vlastníka:** `ListStates`, `CleanState` a `DeleteState` v F3 cílí na `focused` session, v F2 se nemění.
  `NB_DNS_STATE_FILE` se v F2 nemění, v F3 ho gate odmítne.
- Retry gorutina `s.mutex` nepotřebuje. `connect` ho bral kolem `setClient`, zatímco MDM restart ho drží po dobu čekání na
  konec gorutiny, takže restart vypršel a RPC stála. Zápis chrání `session.mu`.
- `TestUpDaemon` nikdy neověřoval stav: daemon testu zůstává v `NeedsLogin`, stará podmínka padala jen na chybě, která
  nepřišla. Teď se ptá přes RPC a odmítá `LoginFailed`.

**`f2/residual-fixes`:**

- **Start uklízí všechny profily.** Běžící profil (`runKey`) je jen v paměti, takže po pádu nikdo neví, který běžel:
  mohl to být jiný než aktivní (`SwitchProfile` bez `Down`, `profile select` ve stavu Connecting), nebo `Down`, jehož
  teardown selhal. `ServiceManager.StateFileProfiles` proto projde `state.json` a `*.state.json` v adresářích všech
  uživatelů, jen běžné soubory s platným názvem profilu. Symlink, adresář, záloha `.corrupted.*` a podadresář, který by
  sanitizace přejmenovala, se přeskočí. Selhání jednoho souboru nebo adresáře se zaloguje a ostatní pokračují.
- **Jediný rozdíl pro jednu session bez gate (I1):** čistší hostitel. Soubor bez zbytků se nezapíše (`PersistState` bez
  změn nepíše, test hlídá obsah i čas změny). Poškozený state soubor neaktivního profilu se teď přesune na
  `.corrupted.*`, což dřív platilo jen pro aktivní.
- **Slot 0 v `openSlots`:** jeden state soubor dá slot svému profilu, i když není aktivní. Více souborů dá slot aktivnímu
  profilu, i když sám soubor nemá, protože ostatní start uklidí. Rozhoduje existence, ne obsah: úklid soubory nemaže,
  takže pořadí `openSlots` a `restoreResidualAtStart` výsledek nemění.
- **Klíč ze souboru nese sanitizované jméno uživatele,** protože jiné na disku není. Pro `first.last` vznikne `firstlast`
  a vlastník slotu 0 z jediného cizího souboru by v `sessions.json` nesouhlasil se skutečným klíčem. Aktivní profil se
  porovnává přes cestu, toho se to netýká. Není rozhodnuto, řešit v PR 13.
- **`Login`:** `restoreOwnResidual` běží pod `Server.mutex`, kontrola a úklid jsou tak atomické vůči `Up` a MDM restartu.
  Běh, který `Login` sám zrušil, se pozná podle `clientGiveUpChan` zachyceného před zrušením. Jiný kanál se stejným
  profilem znamená nový běh a úklid se přeskočí. Zrušený běh ještě může dobíhat, souběh jeho teardownu s úklidem zůstává
  jako dřív.
- **MDM restart** čte config běžícího profilu přes `storedRunningConfig`, bez provisioningu. Smazaný profil se tak nevrátí
  s novou identitou a výchozí Management URL. Selhání čtení (chybějící i nečitelný soubor) restart odmítne a běh označí
  za ukončený, jinak by další změna politiky spustila aktivní profil. Bez živého běhu se dál spouští a provisionuje
  aktivní profil. Běžící profil přes `RemoveProfile` smazat nejde (`f3/run-config`), config ale může zmizet i jinak.
- **Izolace v iptables:** `placeInterface` po jakékoli chybě `addToIfaceSet` odebere obě poloviny ze sady, protože člen se
  eviduje až po obou a `removeMember` by první nenašel. Selže-li i tento rollback, záznam v sadě zůstane a chyba to
  uvede; `Verify` pak nesouhlasí, dokud `Add` se stejným názvem neuspěje. Kernel neumí odmítnout jen druhou polovinu,
  proto má test náhradu `isolationPlane.addIfaceEntry`.
- **Neuklizený zbytek zůstává:** když `Cleanup` selže, stav v souboru zůstane a opakuje se při každém startu. S gate by
  pozdější `Up` toho profilu přes `restoreOwnResidual` mohl sáhnout na výchozí názvy běžící session (I2). Není rozhodnuto.

**`f3/mdm-wait`, Q28:**

- `onMDMPolicyChange` pod `Server.mutex` jen zkopíruje `runRestart` (klíč běhu, `giveUp`, generaci `actCancel`), zruší běh a
  zámek pustí. Po čekání zámek znovu vezme a restart provede, jen když `restartStillWanted`: `clientRunning` platí a
  nikdo mezitím nevyměnil `actCancel`. Jinak skončí bez chyby a novou politiku pro běh načte další `Up`. Vybraný config se
  přesto obnoví a odejdou události `config_changed` a `policy_applied`, protože z něj čtou kill switche politiku a `Down` v
  okně by je jinak nechal na staré. Při nečitelném souboru jde politika na kopii configu (I6), klíče, které z politiky
  zmizely, v ní zůstanou do dalšího načtení. Když není co restartovat vůbec, config se neobnoví, to je chování upstreamu.
- **Kdo v okně čekání co vidí:** `Down` a `Logout` projdou hned a restart se neprovede. `Login` a `WaitSSOLogin` projdou
  hned, převezmou session a restart se neprovede. `Up` a `Status` s `WaitForReady` počkají na konec restartu kanálem, s
  kontextem volajícího, takže se připojí k novému běhu. Ostatní RPC odpovídají ze stavu rušeného běhu.
- `runningKey` po dobu restartu hlásí běh i po konci jeho gorutiny, jinak by `Logout` a residual cleanup rozhodovaly v
  mezeře mezi starým a novým během o aktivním profilu. Platí jen pro běh, který restart vrátí: ne pro běh, který vzdal už
  před ním, ani když session mezitím převzal `Login`.
- Druhý souběžný restart `beginRestart` odmítne. Ticker běží v jedné gorutině, takže v provozu nenastává.
- **Beze změny z upstreamu:** vypršení 10 s nebo nečitelný config běhu vrátí chybu, nový běh se nespustí a config se
  neobnoví. `Up` ve `waitForUp` a `Status` s `WaitForReady`, které už čekají, když restart začne, skončí se starým `giveUp`
  jako dřív: `Up` chybou `client gave up to connect`, `Status` odpovědí.

**`f3/run-config`, Q29:**

- `session.runConfig` nastavuje `beginRun` spolu s `runKey`, `session.config` zůstává config vybraného profilu.
  `connectionConfig` vrátí config běhu, jen když běh nebo publikovaný klient patří jinému profilu než výběr. Bez přepnutí
  za běhu je to tedy vždy `currentConfig`, včetně novějšího configu z `Login`.

| Místo | Config | Proč |
|---|---|---|
| `Status`, `SubscribeStatus` (`buildStatusResponse`) | `connectionConfig` | Recorder popisuje spojení |
| Debug bundle: config a URL pro upload | `connectionConfig` | Status, sync response a metriky jsou z běhu |
| Debug bundle: state soubor a jeho `.corrupted.*` | Běhu přes `StatePath`, jen při běhu jiného profilu | Bez přepnutí zůstává cesta aktivního profilu |
| `checkNetworksDisabled` | `connectionConfig` | Sítě jsou sítěmi běžícího enginu |
| `checkProfilesDisabled`, `checkUpdateSettingsDisabled`, `checkDisableAdvancedView` | Vybraný | Správa profilů a nastavení míří na výběr |
| `onSessionExpire` | `connectionConfig` | Vypršela session spojení |
| `isLoginRequired`, `attemptLogin` z `Login` | Config vyřešený tímto `Login` | Přepnutí uvnitř `Login` nesmí poslat klíč na jiný Management |
| `attemptLogin` z `WaitSSOLogin` | `configOfFlow`: aktuální téhož profilu, jinak config flow | Token patří IdP flow. Bez přepnutí je to aktuální config jako dřív |
| `RequestJWTAuth` | Vybraný, odmítnutý při běhu jiného profilu | Flow z IdP výběru by šel na peery běhu |

- **`RequestJWTAuth`** přebírá z `RequestExtendAuthSession` kontrolu shody profilu, ne požadavek na běžící klient a engine.
  Dnes jde token získat i bez běhu a bez přepnutí se chování nemění. Hláška je společná konstanta.
- **MDM restart výběr nemění.** Dřív přepsal `session.config` configem běhu, takže `RequestExtendAuthSession` po restartu
  prošel a `configKey` neodpovídal výběru. Nově zůstává výběr i odmítnutí, dokud se výběr nevrátí nebo nepřijde `Down`.
  Vybraný config se obnoví přes `refreshSelectedConfig` kvůli politice, se stejným pravidlem pro nečitelný soubor.
- **`RemoveProfile`** se rozhoduje podle `runningKey`, tedy i během MDM restartu. Běh, který vzdal, nebo klient po něm
  odstranění nebrání. **Změna i bez přepnutí:** smazání aktivního běžícího profilu vracelo chybu až po deregistraci, nově
  `FailedPrecondition` před ní a peer zůstává registrovaný. Aktivní nebo výchozí profil, který neběží, se dál nejdřív
  deregistruje a pak odmítne, to je chování upstreamu.
- **Kill switche a neúplná obnova:** `refreshSelectedConfig` obnovuje jen vybraný config. Když restart přeskočí `Login`
  a klient jiného profilu zůstane publikovaný, `checkNetworksDisabled` čte starou politiku z configu běhu do dalšího `Up`.
  Engine je v tu chvíli zrušený, takže RPC sítí stejně neprojdou.
- **Neřešeno, není v zadání:** `SwitchProfile` a `Login` volají `localMetrics.Reconcile` s configem výběru, i když běží jiný
  profil, bez gate to tak zůstává. S gate a hlavičku `status.txt` řeší PR 17, viz 2.5.

### 2.5 Poznatky z implementace F3

**PR 12, `f3/proto`:**

- Proto podle 5.6, handlery se nemění. Nová pole existujících zpráv jsou od 1000, `SessionSelector` a `SessionStatus` jsou
  na konci `daemon.proto`, aby se nepřečíslovaly typy existujících zpráv v `daemon.pb.go`. Odebrané řádky v tom souboru
  jsou jen přečíslování `goTypes` a `depIdxs` a délky v `rawDesc`. Aditivnost se ověřuje rozdílem descriptor setů z `protoc`
  (`--descriptor_set_out`, dekódováno přes `--decode`): proti předchozímu `daemon.proto` se liší jen přidané řádky.
- **Selektor navíc oproti seznamu v 5.6:** `DebugBundleRequest`, `SetSyncResponsePersistenceRequest`,
  `StartBundleCaptureRequest`, `StopBundleCaptureRequest` a `SubscribeRequest` (`SubscribeEvents`). Pracují s enginem,
  záznamníkem stavu nebo záchytem jedné session. `SelectNetworksRequest` slouží i `DeselectNetworks`.
- **Bez selektoru:** `Login`, `Up`, `Logout`, `GetConfig`, `SetConfig` (nesou `profileName` a `username`), `TriggerUpdate`
  (jen `focused`, 5.4 bod 5), `GetLogLevel`, `SetLogLevel`, `StartCPUProfile`, `StopCPUProfile`, `RegisterUILog`,
  `GetInstallerResult` (celý proces) a `GetEvents` (server ho neimplementuje).
- Typy: `Profile.connection_status` je `string` jako `SessionStatus.status`, `max_sessions` je `uint32`.
- `session_compat_test.go` skládá schéma starého klienta z aktuálního deskriptoru (bez polí od 1000 a bez nových zpráv)
  a ověřuje oba směry I10: nová zpráva projde starým klientem bez ztráty polí 1000+ a stará zpráva se načte do nových typů
  s nenastaveným selektorem. Pevná čísla polí ze 5.6 hlídá `TestSessionFieldNumbers`.

**PR 13, první polovina, `f3/gate-sessions`:**

- **Gate** je `service install --enable-concurrent-profiles` podle `--enable-capture`, uložená v `service.json`. Mimo Linux
  skončí `Start` chybou, služba se nespustí. `server.New` bere gate jako parametr a limit přes `WithMaxSessions`, výchozí je
  `defaultMaxSessions`. Jediná kontrola limitu je `admitSessionLocked`.
- **Mapa a focus:** `sessions` je pod `Server.mutex` a platí jen s gate, bez ní zůstává prázdná a jediná session je `focused`.
  `focused` je atomický ukazatel, protože ho handlery čtou bez zámku. Session zůstává v mapě do odstranění profilu.
  `session.key` je s gate normalizovaný klíč, výchozí profil je bez uživatele.
- **Zámky, doplnění 5.4 bodu 2:** pořadí je `guardedConfigMu` → `session.lifecycle` → `Server.mutex` → `session.mu`.
  `lifecycle` je semafor jedné session, na který se dá čekat s kontextem. Drží ho `Up`, `Down`, `Logout`, `RemoveProfile`,
  závěr MDM restartu, `CleanState` a úklid v `Login`, po dobu kontroly a provedení. Pomalé kroky běží bez `Server.mutex`:
  `engine.Stop`, deregistrace a residual cleanup. Rozhodnutí a publikace běhu berou `Server.mutex` krátce. Klient zůstává
  publikovaný až do konce `engine.Stop`, aby `CleanState` nesáhl na hostitele pod ním. Ostatní RPC v té chvíli odpovídají ze
  stavu rušeného běhu, stejně jako při MDM restartu. Bez gate je jediný rozdíl, že během zastavení enginu a deregistrace
  odpovídají ostatní RPC. `Up` bez gate drží `Server.mutex` po celou dobu jako dřív.
- **Dočasné odmítnutí (do druhé poloviny PR 13):** nic zatím session nedává vlastní interface, port ani izolaci, proto `admitSessionLocked` vrací
  `Unimplemented`, když hostitele drží jiná session. Hostitele drží session s živou gorutinou, během MDM restartu a od přijetí po spuštění běhu
  (`hostClaim`). `Down` ho tedy uvolní až koncem gorutiny, a to i když se zasekne. První session běží s názvy z configu bez
  ohledu na číslo slotu, které zatím jen rezervuje místo v `sessions.json` (`Slots.Ensure`, porty nedrží).
- **Odmítnutí při gate** (`refuseUnsupportedRuntime`, `FailedPrecondition`): netstack, `AdvancedRouting()` false,
  `NB_DNS_STATE_FILE`. Platí i pro první session a pro obnovu po startu.
- **Bez selektoru `focused`, jiný selektor `FailedPrecondition`:** `checkSessionSelector` je na začátku všech RPC s
  polem `session` a platí i bez gate. Všechna selhání mají stejnou odpověď, takže selektor neprozradí existenci profilu.
  S gate od PR 14 selektor směruje, viz `f3/rpc-routing` níže.
- **`Down`** s `all` míří na všechny, kombinace se selektorem je `InvalidArgument`. `Down` a `Logout` zapisují `desired=down`.
  Zastavení služby jde přes `StopSessions`, které `desired` nemění, a stejně tak sleep.
- **`Status`:** `sessions` se plní jen s gate a obsahuje běžící session a `focused`. `interface_name` je od druhé poloviny ze `Slots.Running`.
- **Obnova:** `desired=up` startuje s focused první. Focused se připojí i bez uloženého stavu, pokud při startu neexistoval
  žádný záznam, protože migrace ukládá vlastníka slotu 0 jako `down` a daemon doposud aktivní profil připojoval. `DisableAutoConnect` má
  přednost před `desired`. Config nefocused session se čte bez provisioningu, smazaný profil se nevrátí. Bez gate se soubor jen
  čte a připojí se aktivní profil.
  Poškozený `sessions.json` s gate odmítne start služby a soubor zůstane na místě.
- **Sleep a MDM** běží přes všechny session souběžně (`forEachSession`). Probuzení vrací jen to, co sleep vzal dolů. MDM obnoví
  config i session bez běhu, protože z něj čtou kill switche. Běh, který vzdal, se nevrátí, pokud mezitím limit zaplnily jiné session.
- **`Login` s gate** cílil jen na focused. Od PR 14 cílí na pojmenovanou session, viz `f3/rpc-routing`. `up --profile X` z dnešního
  CLI funguje dál, protože nejdřív přepne.
- **`Logout` a `RemoveProfile` s gate** běžící session odmítnou před deregistrací (5.7).
- **Přesunuto na session:** `forceAccountPrompt`, `isSessionActive`, `sessionWatcher`, od PR 14 `bundleCapture` a
  `persistSyncResponse`, od PR 17 `probeThrottle`.
- **Zatím nepokryto:** Událost o změně seznamu profilů jde na předchozí i nový focus. `Profile.connection_status` se neplní, CLI stav skládá ze `Status.sessions` (PR 16). `SystemEvent.profile_id` se plní od PR 15.

**PR 13, druhá polovina, `f3/host-wiring`:**

- **Tvar:** `internal.DaemonHost` je jeden na daemon (`Coordinator`, `Slots`, `SessionIsolation`, `Accounting`), vzniká ve startu a předává se závislostí. `SessionHost` je podíl jedné session a dostává ho `ConnectClient` přes `WithSessionHost` a engine přes `EngineConfig.Session`. Nil znamená dnešní chování a všechny háčky v `engine.go` ho berou. Dočasné `Unimplemented` je pryč, `admitSessionLocked` hlídá jen limit.
- **Každý pokus enginu** projde `attach`: `Slots.Reserve` podle hodnot z configu, kontrola překryvu, `Isolation.Add`, `Sessions.Set`. `detach` běží až po zastavení enginu a pořadí pod `attachMu` je opačné. Nový `Reserve` při každém pokusu znamená, že port obsazený mezi pokusy dostane nový z alokátoru. Do configu se nic nezapisuje, `run` předává jméno a port jen v `EngineConfig`.
- **`ErrSessionRefused`** ukončí obě retry smyčky (`backoff.Permanent`). Platí pro selhání `attach`, `Verify` po `engine.Start` a pro `ErrSessionNotIsolated` z firewallu. Refused session zůstává v `sessions.json` jako `up`, zkusí se znovu po restartu služby. `Up` bez `async` zatím vrací obecné `client gave up to connect`, konkrétní důvod je v logu a patří do `conflict` v PR 15.
- **Backend se zjišťuje jednou za daemon** (`SessionIsolation`), protože `check()` odpovídá podle tabulek a první session je mění: s jedinou tabulkou `netbird` by další odpověď byla `IPTABLES`. Manager i izolace pak používají stejný backend.
- **Vynucení (Q9, Q10):** `NewSessionFirewall` odmítne nil izolaci i nil zdroj, nativní backend bez session v jaderné izolaci, nepřítomnost backendu u kernel interfacu a uspfilter s vypnutými server routes bez jaderné izolace. Poslední případ je konzervativní: `nativeRouter` se v uspfilteru nastaví až v `EnableRouting`, které bez server routes nikdo nevolá, kontrola se ale opírá o config, ne o okamžitý stav. Forced uspfilter vedle nativního backendu má obojí. `DisableFirewall` bez nativního backendu se odmítne v `attach`.
- **Přesunuto do `SessionIsolation`:** `ipfwdstate.HostState`, protože `ipfwdstate` se na WASM nepřeloží a jeho jediní uživatelé jsou nativní managery. Manager session sdílený stav při `Close` uvolní, takže `ip_forward` vrátí poslední session i bez `DisableRouting`.
- **`firewalld.SetParentContext`** session nevolá: rodič je jeden na proces a konec jedné session by jinému `TrustInterface` tiše vypnul. Parametr podle 5.4 bod 7 přidal PR 17.
- **`currentMTU`** byl atomický, dva souběžné starty ho pod `-race` shodily. Pole resolveru a certproof podle 5.4 bod 7 řeší PR 17.
- **I8:** `GetDefaultNextHopExcluding` vrátí výchozí trasu z main, když vyhledání skončí na interface některé session. Monitor dostane seznam přes `WithNetbirdInterfaces`. Sledování v `checkChange` se neměnilo, filtruje main.
- **`updateManager`** se rozhoduje při startu běhu podle tehdejšího focusu. `SwitchProfile` za běhu ho nepřesouvá, nový focus ho dostane při dalším běhu, pokud ho nedrží jiný běh (PR 17).
- **RemoveAll** běží při startu služby jen, když existuje záznam v `sessions.json`, i při vypnuté gate. Bez něj hostitel zůstane netknutý (I1), test to hlídá včetně cizí tabulky `netbird-iso`.
- **Harness:** kernel WireGuard v kontejneru je k dispozici. `TestTwoSessionsOnRealEngines` běží na userspace i kernel interfacu s nftables i iptables. Pakety mezi sítěmi se testují jen na userspace interfacu, protože se vkládají do TUN přes `Engine.InjectFromPeer` (jen pod tagem `privileged`), kernel interface takový vstup nemá. Každý drop má kontrolu: bez odesílatele v izolaci stejný paket projde, po vrácení se zahodí i známý flow. Routing peer v testech existuje jen v network map a test ho značí jako připojený, routy tak instaluje skutečný watcher. Data mezi skutečnými peery zůstávají na e2e z brány v1.
- **Výběr backendu v testu:** bez zásahu kontejner volí iptables (iptables-nft). nftables vybere tabulka `filter` s chainem, kterou test založí.
- **I1:** `testdata/host_snapshot_*.golden` jsou zapsané před napojením a jednorázově ověřené na `main` (`313f71fb4`) v dočasném worktree, shoda bajt po bajtu pro oba backendy: linky, pravidla, routy, nft, `iptables-save`, sysctl, `resolv.conf`. Soubory se kvůli průchodu testu nepřegenerovávají. Při porovnání čistého hostitele (I7) se ignorují prázdné vestavěné chainy, ty zakládá iptables-nft při každém použití, i bez NetBirdu.

**`f3/residual-links`, nález po PR 13:**

- **Problém:** kernel link přežije pád i s peery. Session, která se po restartu nepřipojí, k `attach` nedojde, takže její interface stojí mimo izolaci nového daemonu a peer přes něj dosáhne na lokální službu přes overlay jiné sítě. Okno nemá horní mez.
- **Start** po state souborech a flushi smaže linky všech záznamů ze `sessions.json`, i `desired=down`, a teprve pak izolaci. Soubor neříká, co běželo. State soubory jdou první, protože úklid DNS na systemd-resolved hledá link podle jména (`newSystemdDbusConfigurator`). Izolace jde poslední, do té doby je to jediné, co link drží od ostatních sítí.
- **Co je naše:** typ `wireguard` a jméno odvozené z čísla slotu (`wtN`), jiné jméno soubor nenese (Q17). Jiný typ se stejným jménem zůstane s varováním v logu, stejně jako WireGuard link se jménem, které žádný slot nemá. Userspace interface pád nepřežije, TUN zaniká s procesem.
- **Selhání (I6):** když link nejde smazat nebo zjistit, izolace zůstává. S gate `VerifyNoSessionLinks` po úklidu odmítne start služby, kontrola je nezávislá na průběhu úklidu. Bez gate se to jen zaloguje, jako ostatní selhání úklidu.
- **Bez `sessions.json`** se nic nemaže (I1). Soubor z dřívějšího běhu s gate spustí úklid i po jejím vypnutí, stejně jako u izolace.
- **Zůstává krátké okno:** mezi úklidem state souboru a smazáním linku je link živý bez pravidel své session, izolace ale ještě platí. Trvá po dobu úklidu.
- **Test** spouští skutečný daemon v podprocesu a zabíjí ho přes `SIGKILL`, takže na hostiteli zůstane přesně to, co po pádu. Peer je kernel WireGuard v samostatném netns přes veth. Kontrola před restartem ověří, že tunel přes `wt1` doručuje, což neprůchodnost po startu dělá průkaznou. Test čeká na peera ve stavu session, protože ACL se aplikuje dřív než peery a před první network mapou by firewall session peera nepustil.
- **Session s explicitním `WgIface`** má jméno jen v profilovém configu, její link po pádu zůstane. Od `f3/security-fixes` ji gate odmítne.

**`f3/flow-filter`, R1:**

- `SessionHost.conntrackOptions` dává session `WithSessionFlows` a značka pro ni nerozhoduje. Bez `SessionHost`, tedy bez gate, se `relevantFlow` nemění a filtr nevzniká.
- **Overlay adresa znamená prefix, ne vlastní IP.** Provoz routing peeru má v tuple adresu jiného peera téže sítě a je to flow této session. Overlay sítě se mezi session nepřekrývají (sekce 6), takže je prefix jednoznačný.
- **Navíc oproti doslovnému R1, podle I5:** flow s adresami dvou session se zahodí v obou. Vzniká, když lokální proces pošle z adresy jedné sítě peerovi druhé, izolace hlídá jen input a forward, takže `output` projde a událost přijde. Jinak by Flow služba jedné sítě dostala adresu peera druhé.
- **Cena podle R1:** flow přes routy bez overlay adresy v tuple se s gate nereportuje, ani když má značku. Test ho ověřuje spolu s kontrolou bez gate, která tytéž události bere.
- Zahození v `Logger` by nestačilo, kernel režim nemá po `relevantFlow` jinou kontrolu. Userspace režim conntrack hostitele nepoužívá, flow bere z vlastního uspfilteru.
- **Filtr čte session v okamžiku události.** Flow s adresou session, která už skončila nebo ještě nezačala, filtr jako flow mezi sítěmi nepozná. Týká se to jen případu dvou sítí v jednom tuple, včetně konce flow, jehož začátek se zahodil.
- **Test** běží v `client/internal`, aby šel přes skutečné volby z `SessionHost`. Skutečné události jádra v netns, `CONNMARK` jako pravidla session, skutečný `Logger`, IPv4 i IPv6. Mutace: bez větve v `relevantFlow` projdou flow druhé sítě do obou loggerů, bez kontroly ostatních session projde flow mezi sítěmi, vlastní IP místo prefixu ztratí flow routing peeru a bez v6 části vlastní v6 flow.

**PR 14, `f3/rpc-routing`:**

- **Rozsah:** selektor směruje 24 RPC, oprávnění podle 5.6 a nálezy z revize F3: `CallerIdentity` u nových povrchů, TOCTOU mezi selektorem a focusem, logout nefocused profilu a `bundleCapture`. Bez gate se nemění nic, selektor jiné session zůstává `FailedPrecondition` a identita se nečte, testy to hlídají.
- **Kód:** `session_access.go`. `checkSessionSelector` vrací session a handler dál pracuje jen s ní, druhý pohled na focus nikde není. `checkOpenSelector` je totéž pro `Down`, `Status` a `SubscribeStatus`, které bez selektoru neověřují nikoho.
- **Kdo je vlastník:** `key.Username` se přes účetní databázi hostitele (`user.Lookup`) převede na UID a porovná s UID z `CallerIdentity`. Tím se shodne i alias stejného UID. Neznámý účet s číselným jménem rovným UID volajícího je vlastní, protože tak `InvokingUser` pojmenuje uživatele bez záznamu v `passwd`. Selhání databáze znamená cizí session (I6). Klíč se sanitizovaným jménem ze state souboru (2.4) vlastníka nenajde, ovládá ho jen root. Dva účty, jejichž jména se sanitizují stejně, sdílejí adresář profilů už dnes, session mají ale každý svou. Privilegovaný je `IsPrivilegedCaller`, takže i bezrootový kontejner.
- **Pořadí kontrol:** identita běží před rozlišením handle, takže cizí uživatel dostane stejnou odpověď bez ohledu na to, jestli profil existuje, a neprozradí se ani kandidáti nejednoznačného handle. Vlastní uživatel dostane `NotFound` nebo `InvalidArgument`. Selektor bez handle, případně s handle jiným než `default` a bez jména uživatele, je `InvalidArgument`. Rozlišení je `ResolveProfile`: ID, unikátní jméno, unikátní prefix ID.
- **Zvolený výklad, potvrzený revizí, až na jeden bod:**
  - **Volající s neurčenou identitou** nedosáhne na nic, ani na default session (změna v `f3/security-fixes`, AGENTS Security).
  - **Bez selektoru** projdou všichni jen u `Down`, `Status` a `SubscribeStatus`. Ostatní RPC ověří, že focused session volajícímu patří. Bez toho by selektor nic nechránil, `SwitchProfile` a RPC bez selektoru by ho obešly.
  - **`Status` se selektorem** popisuje v polích 1 až 4 pojmenovanou session, i když komentář v 5.6 říká „vždy focused". Bez selektoru je to focused. Příznak `SessionStatus.focused` ukazuje skutečný focus.
- **RPC pojmenovávající profil** se kontrolují stejně, jsou to povrchy řízení a čtení téže session: `Up`, `Login`, `Logout`, `RemoveProfile`, `SwitchProfile`, `GetConfig`, `SetConfig`. `SwitchProfile` na cizí session by jinak otevřel cestu přes `Down` bez selektoru. `ListProfiles`, `AddProfile`, `RenameProfile` a `GetActiveProfile` kontroluje od `f3/security-fixes` `authorizeProfilesOf` a `authorizeActiveProfile`.
- **`Down{all}`** bere jen session, na které volající dosáhne, ostatní běží dál a `desired` se jim nemění. Když žádná nebyla nahoře, vrací `ErrServiceNotUp`. **`Status.sessions`** se filtruje stejně, cizí záznam nevznikne, takže nevznikne ani jeho `full_status`.
- **Co zůstává podle rozhodnutí:** `Down` a `Status` bez selektoru na cizím focusu fungují jako dnes, takže kdokoli lokální přečte horní pole `Status` včetně `full_status` focused session a shodí ji. Ochrana platí, jen když focus patří volajícímu nebo je default.
- **`Login`** cílí na pojmenovanou session a nemění focus ani aktivní profil. Metriky se srovnávají jen u focused. Kill switch profilů hlídá login jiné než focused session, jako dřív přepnutí. Brány `Login` čtou uložený config z klíče session, ne z druhého rozlišení handle, které by mohlo vést jinam. `Logout` ze stejného důvodu odmítne, když handle mezitím ukazuje na jiný profil.
- **`Logout` s gate** na cílové session zruší čekající flow včetně čekání, vyčistí `jwtCache`, výzvu k výběru účtu a nastaví `NeedsLogin`, focused nebo ne. Flow jde první, protože `cleanupConnection` záznam smaže bez zrušení čekání.
- **State soubor:** `ListStates`, `CleanState`, `DeleteState` a debug bundle ho s gate berou z `ss.key` přes `GetStatePathFor`, bez gate zůstává `GetStatePath`. Bez gate nemá session vlastní klíč, jedna session sleduje aktivní profil. `CleanState` nově kontroluje běh až po získání nároku, běh spuštěný během čekání by jinak přišel o stav.
- **`bundleCapture` a `persistSyncResponse` jsou na session.** Bundle přibalí jen záchyt téže session a jiné session na záchyt nesahá. `RemoveProfile` záchyt ukončí, jinak by na něj nic nedosáhlo a soubor by zůstal. `bc.owner` je pryč. Log celého daemonu v bundlu řeší PR 17.
- **Streamy:** se selektorem zůstávají na session. Bez selektoru sledují focus: `SubscribeStatus` se přepíše při změně a `switchFocus` ho probudí přes `NotifyStateChange` předchozí session. `SubscribeEvents` se přepne po první události. Když focus přejde na session, kterou volající nesmí číst, stream skončí `PermissionDenied` a událost, která přepnutí ohlásila, se mu už nepošle, protože by nesla název cizího profilu.
- **`nil` config:** session pojmenovaná selektorem může být bez configu. `buildStatusResponse` to snese. `networksDisabledFor` pak spadne na příznak služby, RPC sítí stejně skončí na `not connected`.
- **Harness:** `TestSessionAccessOverTheRealSocket` pustí test binárku jako `nobody` a roota proti skutečnému unix socketu s `SO_PEERCRED` a skutečné databázi `passwd`, včetně podvržených metadat `x-netbird-fwd-*`. Tabulkový test spojuje 24 RPC, čtyři volající a tři cíle. Propuštěná volání dostanou zrušený kontext, ptají se jen, kdo projde. `TestSelectorReachesTheEngineOfItsSession` běží na skutečných enginech a kontroluje sítě, výběr sítí a pcap v bundlu.

**PR 15, `f3/conflicts`:**

- **Odmítnutí:** `noteRefusedRun` uloží `session.refusal` dřív, než se zavře `giveUp`, takže `waitForUp` vrátí `FailedPrecondition` se srozumitelnou hláškou místo `client gave up to connect`. Přidá se `SystemEvent` `session_refused` (ERROR). Odmítnutí vymaže nový běh (`beginRun`, tedy i MDM restart) a `Down`, `Logout` (`markClientDown`). Pozdní záznam po `Down` se zahodí, oba zápisy jsou pod `session.mu`. Stav je `Idle`, `conflict` a událost říkají proč.
- **Kde se kontroluje překryv:** `attach` po loginu a před `NewEngine`. Změna adresy z Managementu jde cestou `updateConfig`, `ErrResetConnection`, nový login a znovu `attach`. Test mění `network_range` skutečným `UpdateAccountSettings`.
- **`conflict` se ve stavu odvozuje:** odmítnutí má přednost, jinak `DaemonHost.Conflict` čte aktuální stav z `Routes` a `DNSOwners`. Nic se neukládá, takže nemůže zastarat, když se například vlastník uvolní. Pole je jedno, pořadí je odmítnutí, `exit_node`, `dns`. Session s exit nodem i DNS konfliktem hlásí jen `exit_node`.
- **Hodnoty:** `overlay`, `interface` (i pro obsazený port), `exit_node`, `dns`. **Odmítnutí bez konfliktu** (selhaná izolace I6) nemá hodnotu, důvod říká jen `Up` a událost, viz otázky níže.
- **Hlášky a události nejmenují druhou session,** může patřit jinému uživateli (5.6), a hláška o konfliktu neobsahuje adresy. Událost obsahuje vlastní prefix routy, čte ji jen ten, kdo smí číst tuto session.
- **Události:** `peer.Status.SetEventProfile` razí `profile_id` na všechny události recorderu session, jen s gate (I1). Mapování `RouteEvent` na `SystemEvent` je v `client/internal/session_conflict.go`. `kind` v metadatech: `route_shadowed`, `route_acquired`, `route_handover_failed`, `exit_node_held`, `exit_node_released`, `route_overlay_refused`, `host_dns_held`, `dns_catch_all_held`, `dns_domain_shared`, `ipv6_overlay_skipped`, `session_refused`.
- **Callback:** běží na gorutině session, která změnu způsobila, a sahá jen na recorder cílové session, kde `PublishEvent` nečeká (neblokující zápis do streamu). Žádný zámek `Server` ani `session`. `TestRouteWarningDoesNotWaitForAnySession` ho spouští s drženým `Server.mutex` a `session.mu` a `lifecycle` obou session.
- **Exit node:** ruční výběr hlídá `refuseHeldExitNode` v `SelectNetworks` před změnou výběru, celý požadavek se odmítne a výběr zůstane. Vlastník je ten, kdo má routu v tabulce, ne ten, kdo ji vybral: výběr, jehož peer ještě není připojený, nic nedrží. `All` není ruční výběr, spadne na auto-apply. Auto-apply se přeskočí v `Routes.addDefault`, varování a `conflict` z toho plynou.
- **Známé chování exit nodu:** přeskočený exit node zůstává v `ListNetworks` jako `Selected`, watcher ho považuje za nainstalovaný. Po odchodu vlastníka se požadavek zahodí (R4), opětovný `SelectNetworks` na už vybranou síť nic neudělá, je potřeba `DeselectNetworks` a pak `SelectNetworks`. Přepočet watcheru (změna routing peeru) může volnou routu zabrat sám, to je nový požadavek, ne předání.
- **Routa přes cizí overlay:** `validateRoute` ji odmítal už od PR 5, nově `route_overlay_refused`, jednou za engine a prefix, protože route manager se ptá opakovaně.
- **IPv6:** překryv dál jen odebere v6 v `attach`, nově s událostí `ipv6_overlay_skipped`. Událost navíc oproti tabulce sekce 6, `conflict` se nenastavuje, session běží.
- **DNS:** `HostDNSCoordinator.ServeDomains` po každém úspěšném použití configu na per-link backendu. Shodná doména varuje obě session, jednou, dokud se sdílení nezmění. Kořen je catch-all, ten má vlastní claim. Kolize jména se nezjišťuje (Q6), varování je proto přísnější: platí pro doménu, ne pro jméno. Dvě sítě s výchozí `netbird.selfhosted` ho dostanou vždy. `DNSOwners` si pamatuje odmítnuté claimy, `ForgetSession` v `detach` je smaže, držené claimy neruší.
- **Q24:** `refuseResidualBesideOthers` čte state soubor jen přes `GetSavedStateNames`, nemění ho. Stav s obsahem i nečitelný soubor znamenají `FailedPrecondition` před zápisem `desired`, takže odmítnutý `Up` session po restartu nevrátí. Prázdný soubor z čistého stopu nevadí, `null` hodnoty se nepočítají. Při obnově po startu se taková session jen zaloguje, `desired` jí zůstane.
- **Testy:** tabulka sekce 6 je v `session_conflict_privileged_test.go` na skutečných enginech, limit v `TestGate_RefusedSessionLeavesEverythingAlone`, v6 v `TestAttachWarnsAboutTheSkippedIPv6`, doména na dvou linkách v `TestResolved_SharedDomainWarnsBothSessions` proti falešnému resolved (Q8).

**PR 16, `f3/cli`:**

- **Zjištění gate:** `GetFeatures`. `Unimplemented` znamená starý daemon, tedy dnešní chování. Jiná chyba příkaz zastaví, protože neznámá odpověď nesmí znamenat „vypnuto": `up --profile` by pak shodil spojení, které měl nechat. Kód je v `client/cmd/session_cli.go`.
- **Kdy se ptá:** bez `--profile` se `status`, `networks`, `debug`, `expose` a `ssh` nezeptají na nic, jejich RPC jsou tytéž jako dřív. `up --profile` se ptá jen ve větvi, kde by dnes volal `Down` (stav Connected po přepnutí), `down` po úspěchu (kvůli výpisu běžících session), `profile select` a `profile list` vždy. Každé `--profile` ověří gate dřív, než odešle cokoli.
- **`--profile` se řeší v CLI** přes `ListProfiles` jako ID, unikátní jméno, unikátní prefix ID, stejně jako v daemonu. Selektor nese plné ID a jméno uživatele z `InvokingUser`, takže nejednoznačný handle skončí v CLI s odkazem na `--show-id`. Bez gate: starý daemon i vypnutá gate vrátí chybu „needs concurrent profiles" s tím, co udělat. Starý daemon by selektor ignoroval a zasáhl své jediné spojení.
- **`up --profile X`** s gate: po přepnutí je `Status` bez selektoru stav X. Connected znamená „Already connected", jinak jde `SetConfig`, `Login`, `Up` pro X a `Down` se nevolá. Přepnutí (`SwitchProfile`) zůstává, takže `up --profile X` přesouvá focus na X a lokální zrcadlo aktivního profilu. Bez gate beze změny.
- **`down`:** bez parametru `Down{}` (focused), po úspěchu vypíše `Still running: <jméno> (<stav>, <interface>)` pro nefocused session ve stavu Connected nebo Connecting a příkazy, kterými je odpojit. Session čekající na login se nepočítá. Při chybě (focused neběží, jiné ano) se seznam připojí k chybě. `--profile` a `--all` se vylučují už v CLI. Bez gate `--profile`/`--all` vrátí chybu, plain `down` je beze změny včetně textu `Disconnected`.
- **`status`:** `--profile X` pošle selektor a zobrazí souhrn X. S gate se za souhrn (výchozí i `--detail`) přidá tabulka `Sessions:` (jméno, stav, interface, overlay, `focused`, `conflict: ...`). `--table`, `--ipv4`, `--ipv6` jsou beze změny. JSON a YAML dostanou pole `sessions` (`omitempty`), ostatní pole zůstávají. Overlay adresy se při `--anonymize` anonymizují. Bez gate je výstup bajt po bajtu dnešní, test to hlídá textem i klíči JSON.
- **`profile select`** s gate nevolá `Status` ani `Down`. **`profile list`** s gate přidá sloupec `STATUS` ze `Status.sessions`, profil bez session je `Idle`. Má-li daemon `Profile.connection_status`, má přednost. **`profile remove` a `deregister`** s gate překládají `FailedPrecondition` daemonu na zprávu s příkazem `netbird down --profile <jméno>`. Bez gate zůstává původní chyba.
- **`networks`, `debug bundle|persistence|config|for`, `expose`, `ssh`** mají `--profile`. `debug for` pošle selektor i na `Status`, `Up`, `Down`, záchyt a persistenci. `debug config` předá ID jako `profileName` v `GetConfigRequest`, která selektor nemá. `ssh` předává selektor přes interceptor v `client/ssh/client`, který doplní `GetPeerSSHHostKey`, `RequestJWTAuth` a `WaitJWTToken`, takže se nemění podpisy exportovaných funkcí.
- **Testy:** `session_cli_test.go` běží proti falešnému daemonu s vlastní TCP adresou (zaznamenává RPC a jejich pořadí), `TestCLI_TwoSessionsOnARealDaemon` (privileged) proti skutečnému daemonu s gate v podprocesu, se dvěma Managementy, skutečnými enginy a unix socketem s `SO_PEERCRED`. Daemon je v podprocesu, protože CLI při každém příkazu volá `util.InitLog` a to je pod `-race` závod s gRPC logováním (stejný jako u `TestLogin`). Žádný test nepoužívá výchozí socket. Příčina dřívějšího selhání `TestUpDaemon` se „setup key is invalid" je v `f3/security-fixes` níže.
- **UI přepínač (5.7):** `TestGate_UISwitchLeavesTheOriginalSessionRunning` v `client/server` na skutečném daemonu s gate: po `SwitchProfile` a prosté `Down{}` skončí session nového focusu a původní běží dál. `profileswitcher_test.go` v `client/ui/services` hlídá, že přepínač posílá `Down` bez selektoru a bez `all` až po přepnutí. **Tento test se v harnessu nespustí:** balíček `services` závisí na Wails, který potřebuje GTK4 a WebKitGTK, a image `golang:alpine` je nemá. Prošel jen `go vet`.

**PR 17, `f3/per-session`:**

- **`localMetrics`:** s gate `NewSessionManager` vydává jeden endpoint a každá řada má label `profile` s ID profilu. Legacy ID vznikají ze jména, takže dva uživatelé mohou mít stejné. Pak má label tvar `ID@uživatel`, duplicitní řada by shodila celý scrape. Klientské metriky enginu label dostanou při sběru. Bez gate zůstává `NewManager` a výstup je bajt po bajtu dnešní, řady bez labelu.
- **Kdo je na endpointu:** endpoint a jeho adresu dál řídí config `focused` (`Reconcile` se s gate volá jen pro něj, `SwitchProfile` ho přepne). Ostatní session se objeví, jen když běží a jejich vlastní config metriky zapnul. Endpoint je bez autentizace a čtení cizí session se u RPC odmítá (5.6), proto ji nesmí zpřístupnit jen to, že focused metriky zapnul. Aby vypnutí platilo hned, `SetConfig` s gate předá nový config session téhož profilu (`adoptStoredConfigLocked`), takže ho od té chvíle vidí i `Status` a kill switche té session.
- **Bundle bez selektoru:** horní úroveň zipu je `focused` beze změny názvů, ostatní session, které volající smí číst, jdou do `sessions/<ID>/`: `status.txt`, `config.txt`, `resolved_domains.txt`, `network_map.json`, `state.json`, `corrupted_states/`, `metrics.txt`, `wgshow.txt`. Profily, stack trace a služební parametry popisují proces a jsou jednou. **Se selektorem** je v zipu jen pojmenovaná session. Záchyt patří jen session na horní úrovni, cizí záchyt bundle nebere (`f3/rpc-routing`).
- **`status.txt` a metrika v bundlu:** hlavička bere název z `session.key`, ne z aktivního profilu (`GeneratorDependencies.ProfileName`), `metrics.txt` je z enginu téže session. Bez gate je jméno prázdné a platí dnešní čtení aktivního profilu.
- **Log daemonu a systémové informace:** když na hostiteli běží session, kterou volající číst nesmí, bundle je vynechá a README to řekne (`OmitHostWide`). Log neumí oddělit session a routy, interfaces a nft mluví o všech. Root a jediný uživatel dostanou všechno.
- **Zámek:** `generateDebugBundle` drží `Server.mutex` jen na odebrání CPU profilu a záchytu a přečtení `uiLogPath`. Záchyt si odebere celý (`takeBundleCaptureLocked`): nový `StartBundleCapture` během zápisu tak nesmaže soubor, ze kterého se čte, a ze dvou souběžných bundlů ho má jeden. Generování trvá nejméně 5 s kvůli `addProf`, dřív po tu dobu stála všechna RPC všech session. Je to jediný rozdíl bez gate: ostatní RPC během bundlu odpovídají, obsah zipu je stejný.
- **SSH config:** `NewForSlot`, slot 0 je `99-netbird.conf`, slot N `99-netbird-N.conf`. Stop a `ShutdownState` mažou jen svůj soubor. **Nález:** engine po stopu záznam `ssh_config_state` ve state souboru nechával a ten se při dalším `Up` vedle běžící session četl jako zbytek (Q24), `Up` skončil `FailedPrecondition`. S gate se teď po smazání souboru záznam ruší, bez gate zůstává.
- **Auto-update:** `claimUpdates` při startu běhu dá `updateManager` jen `focused` a jen když ho nedrží jiný běh. Běh, který focus ztratil, ho drží do svého konce (přesun za běhu se nedělá), a nový focus ho do té doby nedostane: dvě sítě by jinak střídavě určovaly, co se na stroj instaluje. Držitel je atomický ukazatel, protože `connect` nesmí brát `Server.mutex`. `SubscribeEvents` nefocused session updater nespustí, bez gate ho spouští každý odběr jako dnes.
- **`currentMTU`** je pryč, stejně jako `SetCurrentMTU`. `upstreamResolverBase.mtu` se plní z `WGIface.MTU()` při vzniku handleru, `ExchangeWithFallback` a `ExchangeWithNetstack` berou MTU parametrem, dnsinterceptor a iOS resolver ho čtou ze svého interface. Interface má hodnotu z `EngineConfig.MTU`, tedy z configu session.
- **`TrustInterface(ctx, iface)`:** `SetParentContext` a globální rodič jsou pryč. `NewFirewall` a `NewSessionFirewall` berou kontext enginu a předávají ho přes `uspfilter.Config.TrustContext` a `SetTrustContext` nativních managerů. `UntrustInterface` zůstává na `Background`, musí doběhnout i při stopu.
- **Certproof:** `Collector.WaitForSlot`, s gate zapnuté (`NewEngine` podle `config.Session`). Platný držitel je běžící sběr mladší než `lostAfter` krát deadline, tedy až 450 s. Sběr na něj čeká a nevrací prázdné důkazy. Čekání končí uvolněním slotu, ztrátou držitele (sběr pak běží vedle něj) nebo kontextem enginu. Když jsou všechny sloty ztracené, odpověď je okamžitě prázdná a engine hlásí zaseknuté úložiště jako dřív. Bez gate se nemění nic. Čeká gorutina `watchCertificatePosture`, která po tu dobu neopakuje ani `retryPendingChecks`, sync cesta dál posílá poslední keš.
- **`probeThrottle`** je na session, sonda jedné session neříká nic o relayích druhé.
- **Testy:** `session_report_privileged_test.go` na skutečných enginech a Managementech: scrape skutečného endpointu, zip z `DebugBundle`, soubory v `/etc/ssh/ssh_config.d` a state soubory po stopu, MTU linků, updater, firewalld přes falešný `firewall-cmd` (harness nemá system bus). `TestResolverAdvertisesTheMTUOfItsSession` čte EDNS0 velikost na skutečném UDP upstreamu, `TestEngine_SessionsSideBySideAllProve` podepisuje ze skutečného úložiště. Klientské metriky ověřuje řada `netbird_login_duration_seconds_count` s labelem na scrapu a `peer_id` v `metrics.txt`. Mutace: bez `NewForSlot` se soubor slotu 1 neobjeví, bez `ProfileName` nesedí hlavička `status.txt`, metriky focused v cizím adresáři shodí porovnání `peer_id`.
- **Nález mimo rozsah:** `version.Update.StopWatch` čte `fetchTicker`, který `StartFetcher` zapisuje bez synchronizace, zrušení kontextu těsně po `Manager.Start` je pod `-race` závod. V produkci jde o konec daemonu. Testy updateru proto `rootCtx` nerušit, `version/update.go` se nezměnil.

**PR 18, `f3/fork-build`:**

- **Build řídí tag `multiprofile`.** Bez něj se nemění nic: `fork_off.go` má prázdný `forkMarker`, `NetbirdVersion()` vrací `version` jako dřív a `.goreleaser.yaml` ani workflow se nedotkly. Tag má jen `.goreleaser_multiprofile.yaml`, který staví Linux (amd64, arm64) a balíčky deb a rpm `netbird-multiprofile`. Spuštění: `goreleaser release --snapshot --clean --config .goreleaser_multiprofile.yaml`. `release.disable`, žádný `publishers`, `brews`, `blobs` ani Docker: nic se nenahrává a oficiální repozitář se nepřidává (`install.sh` z `release_files` se pro fork nepoužívá, přidává právě ten repozitář). `TestForkReleaseConfig` hlídá Linux, tag, název balíčku, `conflicts` a `replaces` na `netbird` a nepublikování, `TestUpstreamReleaseConfigHasNoForkTag` hlídá, že tag není v upstream konfiguraci.
- **Označení verze je build metadata `+multiprofile`** (`0.70.1+multiprofile`, `development+multiprofile`), takže ho nese status, `netbird version`, debug bundle (`status.txt` bere obě verze z `NetbirdVersion()`), User-Agent i verze, kterou klient hlásí Managementu a peerům. Metadata se při porovnání verzí nepočítají a `MeetsMinVersion` i `IsDevelopmentVersion` s nimi pracují, takže fork se řadí jako upstream vydání, ze kterého vychází (`TestForkVersionStaysComparable`). Označení se nepřidá dvakrát, kdyby ho vložil `ldflags`. Prerelease `-multiprofile` jsem nezvolil, protože by se řadilo pod vydání a `sanitizeVersion` ho odřezává.
- **Dotaz na `pkgs.netbird.io`** (`version.Update.fetchVersion`) se s tagem nepošle: `StartFetcher` skončí hned a `fetchVersion` vrací false. `TestForkBuildDoesNotQueryReleaseEndpoint` počítá požadavky na testovací server, počet je nula. Updater klienta tím nikdy nezjistí „novější“ upstream verzi. Directive z Managementu (`SetVersion`) na Linuxu dál padá na download-only, protože `isAutoUpdateSupported` je tam false.
- **Windows a macOS:** `isAutoUpdateSupported` vrací false, když `version.ForkBuild()`. Bez tagu se `supported_windows.go` chová jako dřív (`!false`). Fork se pro ty platformy nedistribuuje, build ale projde (`GOOS=windows` a `darwin`, s tagem i bez).
- **Balíček:** deb a rpm instalují `/usr/bin/netbird` a službu `netbird` jako upstream, proto `conflicts` a `replaces` na `netbird`. Skripty `post_install.sh` a `pre_remove.sh` se berou beze změny. Přechod z upstream balíčku tedy odstraní jeho službu a nainstaluje službu forku (`/var/lib/netbird` zůstává).
- **Existující testy:** `version/update_test.go` má `//go:build !multiprofile`, protože testuje právě dotaz, který fork vypíná. V `client/status/status_test.go` hlídá `withUpstreamVersion` fixtury s `development` i pro tagovaný build.
- **Neověřeno:** samotný `goreleaser` v prostředí není, konfiguraci proto čte jen test (YAML), balíček se nestavěl. Test na Windows a macOS se jen kompiluje (`go vet` s tagem), neběží.
- **Nález mimo rozsah (beze změny):** `TestDoNotUpdate` v `version` je pod `-race` červený, závod `StopWatch` a `StartFetcher` z PR 17 (viz výše). Platí s tagem i bez něj.

**PR 19, `f3/scale-test`:**

- **Testy** jsou v `session_scale_privileged_test.go` a `session_scale_measure_privileged_test.go`. Limit předává test přes `WithMaxSessions`. Výchozí zůstává 4 a test to hlídá.
- **Co prošlo pod `-race` na 8 a 16 session:**

| Test | Režim | Co ověřuje |
|---|---|---|
| `TestScaleSessions` | Userspace a kernel, nftables a iptables | Interface a port slotu, `Status`, `ResourceExhausted` nad limitem a beze změny hostitele, limit 0, I3 a I4 paketem mezi všemi dvojicemi (jen userspace), I5 adresy, I2 a I8 při stopu, startu a restartu slotu 1 vedle slotů 10 a výš, předání sdílené routy přes všechny session, I7 |
| `TestScaleChurn` | Userspace, nftables a iptables | Start všech najednou, 4 kola, kdy jedna skupina odchází a druhá přichází, třetí běží beze změny, I3 a I4 na konci, I7 |
| `TestScaleStress` | Userspace, nftables a iptables | 100× up a down druhé session při provozu první (200 paketů/s), I2, ztráta paketů, gorutiny, deskriptory, I7 |
| `TestScaleCrash` | Kernel, nftables a iptables | `SIGKILL` daemonu se 16 session, obnova všech na jejich sloty, I7 kromě sysctl (Q22) |
| `TestScaleMeasure` | Oba režimy, oba backendy | Měření níže, I4 skutečným peerem přes skutečný tunel s kontrolou odebráním izolace, 200 cyklů, úklid |

- **Žádný invariant neselhal.** Bez nálezu I2 až I8 v rozsahu tabulky. Kontroly: bez `WithMaxSessions` test skončí na `the limit of 4 concurrent sessions is reached`. Když se `wt10` a výš vynechají z izolace, session se odmítne (`wt10 is not in the kernel isolation`). Bez předání routy skončí test na `one of [wt1 ...] should hold the shared prefix alone`.
- **Názvy se dvěma číslicemi:** stop slotu 1 vedle slotů 10 až 15 vezme jen svůj interface, tabulku, chainy a sety. Porovnává se celý snapshot přesnou shodou názvu včetně bajtového zápisu v pravidlech cizích chainů.
- **Oprava, únik v `externalChainMonitor`:** `subscribe` zavíral monitor knihovny, jehož gorutiny čekají na neblokovaném předání události. Když v okamžiku stopu běžela událost, typicky od jiné session, zůstaly viset dvě gorutiny na monitor. `closeMon` teď kanál dočte. Oprava je ve sdíleném souboru, ale na pravidla ani názvy nemá vliv (I1, `TestNoGateHostSnapshotMatchesToday` prochází).
- **Bez úniku po 200 cyklech:** po odchodu všech session a 135 s zbývá 36 gorutin ve všech režimech, z toho 16 značí routing peera v testu, heap je 5 až 6 MiB a deskriptory se vrátí na původní počet. Před tím je gorutin dočasně až 170: NAT-PMP dotaz zastaveného enginu čeká v `go-nat-pmp` až 128 s a nejde zrušit. Zůstává 1 `SessionWatcher` na session, protože session je v mapě do odstranění profilu. Test všechny tři hodnoty hlídá.

**Měření.** Daemon běží v samostatném procesu, Management, vzorkování a echo server jsou mimo něj, takže do RSS a CPU nepatří. Čísla jsou **bez `-race`**, protože ten zkresluje paměť a CPU. Je to jediný běh mimo `-race`, ve stejném harnessu, s `-race` test prochází také. Prostředí: kontejner `golang:1.26.10-alpine`, jádro 6.8, hostitel přitom v běžném provozu. Rozptyl mezi opakováním je ±1 až 2 µs u p50. Řádek 0 u RTT je po odchodu poslední session, protože peer potřebuje klíč session. CPU je procento jednoho jádra.

Kernel WireGuard, nftables:

| Session | RSS MiB | Heap MiB | Gorutiny | CPU v klidu % | Tunel RTT p50/p99 µs | Lokálně RTT p50/p99 µs | Forward RTT p50/p99 µs |
|---|---|---|---|---|---|---|---|
| 0 | 55 | 3 | 5 | | | 4,9/15,5 | 5,8/12,6 |
| 1 | 67 | 4 | 60 | 0,20 | 77,4/145,5 | 6,4/14,9 | 6,5/11,4 |
| 2 | 69 | 4 | 111 | 0,35 | 82,2/153,3 | 5,8/16,4 | 7,0/12,5 |
| 4 | 74 | 5 | 215 | 0,45 | 83,4/158,1 | 7,3/12,3 | 8,3/18,3 |
| 8 | 82 | 6 | 423 | 0,85 | 93,8/186,5 | 7,2/16,5 | 9,7/17,7 |
| 16 | 97 | 9 | 839 | 1,60 | 102,4/191,6 | 10,6/25,5 | 12,9/28,1 |

Kernel WireGuard, iptables:

| Session | RSS MiB | Heap MiB | Gorutiny | CPU v klidu % | Tunel RTT p50/p99 µs | Lokálně RTT p50/p99 µs | Forward RTT p50/p99 µs |
|---|---|---|---|---|---|---|---|
| 0 | 55 | 3 | 5 | | | 5,9/19,8 | 5,9/13,2 |
| 1 | 66 | 4 | 56 | 0,30 | 80,1/146,1 | 6,0/10,5 | 6,6/11,8 |
| 2 | 67 | 4 | 103 | 0,40 | 80,2/155,6 | 5,7/14,6 | 7,0/17,2 |
| 4 | 72 | 5 | 199 | 0,60 | 88,3/164,0 | 7,2/17,3 | 9,3/18,1 |
| 8 | 80 | 6 | 391 | 1,05 | 87,4/165,9 | 8,1/12,5 | 11,2/23,0 |
| 16 | 92 | 9 | 775 | 1,95 | 95,9/178,6 | 8,4/16,5 | 12,9/27,9 |

Userspace WireGuard, nftables (iptables se liší jen ve stejném rozsahu jako v kernelu):

| Session | RSS MiB | Heap MiB | Gorutiny | CPU v klidu % | Tunel RTT p50/p99 µs | Lokálně RTT p50/p99 µs | Forward RTT p50/p99 µs |
|---|---|---|---|---|---|---|---|
| 0 | 57 | 3 | 5 | | | 5,9/13,3 | 6,5/12,8 |
| 1 | 68 | 38 | 117 | 0,30 | 103,7/189,9 | 6,3/12,8 | 6,7/18,6 |
| 2 | 82 | 72 | 223 | 0,25 | 102,8/190,3 | 5,8/13,4 | 8,2/16,7 |
| 4 | 90 | 141 | 437 | 0,45 | 101,2/204,6 | 6,0/13,6 | 7,9/19,9 |
| 8 | 117 | 278 | 865 | 0,95 | 111,8/214,7 | 6,7/15,3 | 10,7/23,5 |
| 16 | 174 | 553 | 1721 | 1,80 | 114,3/234,1 | 9,1/17,6 | 13,0/25,8 |

- **Cesty RTT:** jeden UDP paket naráz, 20 000 vzorků a 64 B. Peer je kernel WireGuard v netns na veth. Tunel jde přes `wt0` na lokální echo, lokálně mimo tunel na adresu veth hostitele, forward přes hostitele do dalšího netns. Poslední dvě cesty se session netýkají, takže jejich růst je to, co platí každý paket hostitele.
- **Náklad nftables hooků:** session přidá 2 base chainy na forward, prerouting a postrouting, 1 na input, nic na output. Izolace je jedna tabulka s jedním forward a jedním input chainem. Při 16 session je to forward 34, prerouting 32, postrouting 32, input 18 (včetně izolace a tabulky `filter` testu) a 18 pravidel na session. Lokální RTT projde 82 chainy a roste o 3 až 6 µs, tedy asi 50 ns na chain. Forward RTT jich projde 196 a roste o 6 až 8 µs, asi 35 ns na chain. Přepočteno: 0,3 až 0,5 µs RTT na session a platí to i provoz, který se NetBirdu netýká. V iptables (iptables-nft) je chainů stále stejně, roste počet pravidel (25 na session) a forward RTT roste stejně, lokální o něco méně. Začátek křivky je v rozptylu měření. Propustnost se neměřila.
- **Paměť:** kernel režim přidá 2 MiB RSS a 0,4 MiB heapu na session. **Userspace přidá 34,5 MiB heapu na session.** Jsou to 64KiB buffery `wireguard-go` držené na každý příjmový kanál zařízení. Stránky se dotknou až při použití, proto je RSS v klidu jen 174 MiB. **Po cyklech se RSS zvedne na 1,7 až 1,8 GiB:** buffery nového zařízení se alokují z paměti dříve použité a vynulování ji dotkne, GC si k tomu drží rezervu. Po odchodu všech session se vrátí na 110 MiB. Paměť jádra (kernel WireGuard, nft) v RSS není a neměřila se.
- **CPU:** v klidu 0,1 % jádra na session, bez skutečných peerů, routing peer jen nikdy neodpovídá. Daemon při tunelu s 10 000 RTT/s: kernel 0 %, userspace 70 % jádra, nezávisle na počtu session. Provoz ve více session zároveň se neměřil.
- **Trvání (Management je lokální):** sekvenční start 16 session 1,7 s na nftables a 3,3 s na iptables. Pod `-race` všech 16 najednou 0,5 a 2,7 s, po pádu 2,6 a 10,9 s. Jeden cyklus stresu vedle běžící session pod `-race`: up 107 a 307 ms, down 116 a 583 ms. Běžící session přitom ve všech bězích neztratila žádný paket a nejdelší ticho bylo nejvýš 131 ms při 200 paketech/s.
- **Port slotu se může posunout:** `51820+N` leží v ephemeral rozsahu Linuxu (32768 až 60999) a čím víc session, tím víc soketů z něj bere. Jednou za celé testování dostal slot 4 místo 51824 port z alokátoru, jak dovoluje 5.1. Test to loguje a hlídá jen, že jsou porty různé.
- **Neověřeno na této škále:** I3 paketem v kernel režimu (kernel interface nebere vkládané pakety, I4 ale ověřuje skutečný peer), DNS mimo backend `file` (Q8), I9 a I10 (na počtu session nezávisí, testy z PR 14 a PR 12), propustnost, data mezi skutečnými peery všech sítí.

**Otázky k PR 19:**

- **Omezovač souběhu startů z 5.8 neexistuje.** Tabulka 5.8 ho žádá, žádné PR ze sekce 8 ho neobsahuje a spec neříká kolik souběžných startů ani jaký časový limit. Stejně jako start po změně sítě běží všechny session najednou. Měření s lokálním Managementem problém neukázalo, 16 najednou doběhne do 2,7 s. Se vzdáleným Managementem a pomalým loginem to změřeno není. Má vzniknout, a s jakými hodnotami, nebo se má řádek 5.8 škrtnout?
- **Userspace a limit:** při zvýšení limitu znamená 34,5 MiB heapu a až 1,8 GiB RSS při častých restartech reálný náklad, který je v `wireguard-go`. Má limit platit stejně pro oba režimy?
- **Náklad hooků platí všechen provoz hostitele.** Je 3 až 8 µs RTT při 16 session přijatelné pro stroj, který forwarduje velké objemy, nebo se má před zvýšením limitu změřit propustnost?

**Bezpečnostní revize F3, `f3/security-fixes`:**

- **Překryv běhů:** `Down` čeká na konec běhu 5 s, `engine.Stop` může trvat déle a další `Up` spustil druhý běh vedle prvního. Konec prvního pak odebral druhému izolaci. `launchSession` teď čeká na konec předchozího běhu, nejvýš minutu nebo do kontextu volajícího, pak `FailedPrecondition`. `lifecycle` přitom drží, takže `Down` téže session čeká s ním. Navíc `Slots.Release` hlásí, zda lease ještě platil, a `detach` s nahrazeným lease nesahá na nic. Po `Close` hlásí platnost, protože nic nového už nevznikne a izolaci je potřeba odebrat.
- **I5 při loginu:** filtr adres je na všech cestách k Managementu: login běhu, `Login`, registrace, `IsLoginRequired`, `ExtendAuthSession`. `auth.NewAuth` má volbu `WithInfoFilter`, server ji předává jen s gate. Filtr je podle prefixu všech session. Foreground, embed a mobilní klienti filtr nemají, protože nemají session.
- **Vzdálený bundle:** s `config.Session` má state soubor a název své session a `OmitHostWide`. Log a systémové informace tedy Management přes job nedostane ani při jediné session. Bez gate beze změny.
- **Izolace za běhu:** `DaemonHost` spouští s první session kontrolu každých 5 s (`session_isolation_watch.go`), poslední session ji končí. Rozdíl znamená `Restore`: nftables jednou dávkou, iptables po krocích (nemá dávku, do konce obnovy jde izolaci obejít, stejně jako před ní). Každá session dostane událost `isolation_restored` (WARNING). Když obnova nebo další `Verify` selže, všechny session skončí přes `ErrIsolationLost`: `Idle`, `session_refused`, `desired` zůstává `up`, `conflict` prázdný. Nová session čeká, až půjde zbytek pravidel odstranit (`recoverIsolationLocked`). **Zůstává:** okno až 5 s a vlastní tabulky session po `flush ruleset` nikdo neobnoví, to je stejné jako bez gate.
- **Nález navíc, zablokování:** `attach` při odmítnutí bez firewallu a při selhání `Sessions.Set` volal `detach`, který bere `attachMu`, držený už v `attach`. Běh i všechny další `attach` a `detach` by stály navždy. Regresní test `TestAttachWithoutAnyFirewallRefusesAndMovesOn`.
- **Explicitní `WgIface`, odchylka od 5.1:** s gate se odmítne v `attach` (`ErrExplicitInterface`, `conflict=interface`), i pro roota. Tím končí oba nálezy: link se jménem, které `sessions.json` nezná, a smazání cizího linku přes `SetConfig{interface_name}` bez oprávnění. Do `privilegedConfigChange` se změna nepřidala, s gate by nic nechránila a bez gate by porušila I1. Config se zapíše dál, session pak hlásí, co změnit.
- **Cizí link na jméně slotu:** `RefuseForeignLink` v `attach` odmítne existující link jiného typu než `wireguard` a `tun`, chyba zjišťování také. `tun` projde, protože zavíraný TUN předchozího pokusu může krátce zůstat, cizí TUN se jménem `wtN` by proto v kernel režimu `recreate` smazal. Cizí WireGuard viz Q19.
- **RPC profilů:** `ListProfiles`, `AddProfile`, `RenameProfile` a `GetActiveProfile` kontrolují identitu jen s gate. `GetActiveProfile` na cizí focus vrací `PermissionDenied`, CLI (`getActiveProfileName`) to bere jako prázdný název. Událost `Profile list changed` s gate nenese název profilu, UI z ní čte jen `kind`.
- **Sanitizované jméno:** `owns` navíc žádá, aby se jméno sanitizací neměnilo a aby žádný jiný UID ve `/etc/passwd` nesdílel stejný adresář. Chybějící soubor znamená žádné účty, jiné selhání odmítnutí. NSS neumí účty vypsat, účet jen v LDAP s jiným sanitizovaným jménem se proto pozná jen, když sám volá. **Cena:** uživatel s tečkou ve jméně má s gate bez oprávnění jen default session, viz otázky.
- **Neurčená identita:** `mayReach` a `requireProfileReachable` ji odmítnou i pro default session. `Down` a `Status` bez selektoru zůstávají podle 5.6 otevřené. Služba s gate navíc odmítne start na TCP socketu (`checkConcurrentProfilesTransport`), kde by neurčený byl každý.
- **Bundle:** log se vynechá, když je v mapě nebo v `sessions.json` jakákoli cizí session, i zastavená. Stačí jediný záznam jiného uživatele, takže na sdíleném hostiteli neprivilegovaný volající log prakticky nedostane.
- **JWT u `netbird ssh`:** s gate ověří server vyžadující JWT jen daemon, ve stejné session jako token. `known_hosts` ani vypnutá kontrola neplatí. Bez `--profile` to znamená, že peer v jiné session skončí chybou host key. Neznámý stav gate znamená odmítnutí, `Unimplemented` starý daemon. Token se přitom od daemonu vyžádá dřív než handshake, neodejde ale ven.
- **`TestUpDaemon`:** „setup key is invalid" nepocházel z testovacího Managementu, ale z `api.netbird.io`. Stejně selhává na `multi-profile`, regrese těchto větví to není. Upstream `a8dff998e` změnil foreground login na `ReadConfigOrDefault`, který `--management-url` nečte, a test tak každým během posílal testovací klíč a metadata hostitele na produkční službu. Test má teď configy s vlastním Managementem a výchozí config ve vlastním adresáři. **Pod `-race` dál selhává** na `grpclog.SetLoggerV2` z `util.InitLog` (známý závod jako u `TestLogin`), bez `-race` prochází celý. **Nález upstreamu:** `netbird login -m X` ve foreground režimu `-m` ignoruje.
- **Testy:** `session_isolation_privileged_test.go` na skutečných enginech s oběma backendy, po obnově znovu `assertIsolated` s pakety. `TestLostIsolationStopsAllSessions` drží ipset cizím pravidlem, skutečně tak selže teardown. Falešný Management `client/testutil/mgmtmeta` čte skutečný `PeerSystemMeta`. `TestJWTGoesOnlyToAServerTheSessionKnows` má skutečný SSH handshake se serverem, který token zaznamenává.
- **Historie větve:** první dva commity a oprava testu po nich se kvůli špatně vystagovaným hunkům `session_host.go` nepřeloží, opravuje to commit `[client] Keep a remote debug bundle to the session that asked`. Historie se podle zadání nepřepisovala. Při slévání squash nevadí, `git bisect` by tyto tři commity musel přeskočit.

**Otázky k revizi:**

- **Explicitní `WgIface`:** odmítnutí je odchylka od 5.1 „explicitní název se respektuje". Má zůstat, nebo se má jméno ukládat do `sessions.json` (změna schváleného formátu Q17, starší daemon by soubor bral jako poškozený)?
- **Uživatel s tečkou ve jméně** nemá s gate bez oprávnění vlastní profily, ani když kolize neexistuje. Zvoleno podle revize. Alternativa je povolit ho, dokud žádný účet adresář nesdílí, nebo adresář klíčovat přes UID (změna formátu na disku).
- **`interface_name` bez gate:** neprivilegovaný volající dál smí přes `SetConfig` a `Up` smazat libovolný link, i na `main`. I1 brání opravě ve forku. Hlásit upstreamu přes security policy?
- **`99-netbird-N.conf` (0644)** ukazuje overlay IP a FQDN až 200 peerů komukoli lokálnímu, což obchází filtr 5.6. Nechá se to popsat jako známé omezení, nebo se má soubor slotu N přesunout do `~/.ssh` vlastníka (změna CLI a chování OpenSSH)? Soubor s 0600 nejde, OpenSSH by ho vlastník nepřečetl.
- **Vlastní tabulky session po `flush ruleset`:** kontrola obnoví jen izolaci. ACL session zůstanou pryč do jejího restartu, jako bez gate. Má je kontrola také hlídat a session při rozdílu restartovat?
- **Interval kontroly 5 s** je volba bez měření. Netlink událost by okno zkrátila, ale znamenala by další vlastní kód pro oba backendy.
- **`Status` a `Down` bez selektoru** dál čtou a shazují cizí focus kýmkoli lokálním (5.6). Revize je nezpochybnila, zůstávají.

**Otázky k PR 17:**

- Focused bez metrik a jiná session s metrikami: endpoint neběží. Má ho držet kterákoli zapnutá session, a čí adresa pak platí? Zvoleno nejmenší: adresu i existenci určuje focused, dvě různé adresy se nespouští.
- `sessions/` v bundlu bez selektoru je výklad „pokryje všechny session zvlášť" vedle pravidla „bez selektoru focused" (5.6). Sedí, nebo má bundle bez selektoru být jen focused a `debug bundle --all` samostatně?
- Vynechání logu a systémových informací pro neprivilegovaného volajícího je přísnější, než říká spec. Stačí, nebo má `Bundle` pro něj log filtrovat?
- `config.txt` v bundlu ukazuje hodnoty z configu, u slotu N tedy `WgIface: wt0`, protože název se do configu nezapisuje (5.1). Skutečný název je ve `status.txt`. Má se config v bundlu doplňovat?
- Události updateru jdou do recorderu session, která byla focused při startu daemonu (`updater.NewManager`), `TriggerUpdate` selektor nemá. Má je UI vidět i po změně focusu?
- `ssh-proxy` a `ssh detect` v souboru slotu N dál jdou na focused (otázka k PR 16). Generovaný soubor už je na slot svázaný, přidání `--profile` by ale měnilo CLI a obsah souboru, nechal jsem to.

**Otázky k PR 16:**

- `up --profile X` s gate přesouvá focus na X (zdědil to z dnešního přepnutí před `Up`). Má se focus měnit, nebo má `up --profile` session jen přidat?
- `login --profile X` (`switchProfileOnDaemon`) volá `Down`, když je po přepnutí Connected. S gate to míří na X, ne na ostatní, 5.7 ho nezmiňuje a nechal jsem ho beze změny.
- `trace`, `capture` a `state` mají selektor v proto, ale 5.7 u nich `--profile` nezná. Nepřidal jsem ho.
- `ssh-proxy` (ProxyCommand nativního klienta) selektor nepředává, jde vždy na focused. Patří sem, nebo do PR 17 s generovaným SSH configem?
- `Profile.connection_status` zůstává v daemonu neplněný. CLI skládá stav ze `Status.sessions`, která je už filtrovaná podle identity. Plnit ho v `ListProfiles` by vyžadovalo kontrolu přístupu u cizího `username`.
- `Status.sessions` obsahuje i nefocused session ve stavu `NeedsLogin` (například `default` po startu). CLI ji v tabulce ukáže, ale mezi běžící ji nepočítá.

**Otázky k PR 15:**

- Odmítnutí bez konfliktu (selhaná izolace) nemá v `SessionStatus` žádnou hodnotu, 5.6 zná jen čtyři. Má přibýt pátá, například `isolation`?
- Routa z dřívějška, když cizí overlay vznikne až po ní, zůstává v tabulce a varování nepřijde. Sekce 6 ten případ neřeší. Pravidlo 105 dává přednost `main` (kde je connected route overlaye), takže provoz na cizí overlay do ní nejde, ale ostatní cíle v jejím rozsahu ano. Má se přidat kontrola při příchodu session?
- Má být přeskočený exit node v `ListNetworks` vidět jako nevybraný? Vyžadovalo by to zásah do route manageru, proto zůstává, viz výše.

**Otázky k PR 14:**

- `ListProfiles`, `AddProfile` a `RenameProfile` s cizím `username`: 5.6 je pokrýt má, opraveno v `f3/security-fixes`.
- `SetLogLevel` posílá úroveň jen klientovi focused session, proces ji má ale globální. Patří to sem, nebo do PR 17?

**Otevřené po PR 13:**

- **Residual, session sama (Q24):** když `Cleanup` selže a na hostiteli nic jiného neběží, `Up` jen zaloguje varování a běh záznam přepíše. Zadání PR 15 řeší jen případ vedle běžící session.
- **Klíč slotu 0 ze souboru (2.4):** nese sanitizované jméno uživatele. Důsledek je jen nevyužitý záznam a jiné číslo slotu pro `first.last`, názvy jsou po napojení na slotu, ne na profilu. Neřešeno.
- **DNS:** ověřen jen backend `file`, který v kontejneru vybere daemon. Pro resolved a NM platí Q8.
- **Link s explicitním `WgIface` po pádu:** vyřešeno odmítnutím v `f3/security-fixes`, viz otázky k revizi. Zůstává link z běhu před zapnutím gate, ten v `sessions.json` není.
- **Cizí WireGuard na jméně slotu:** typ a jméno ho od zbytku po pádu neodliší, start ho smaže. Odlišit by šel porovnáním veřejného klíče zařízení s klíčem profilu, nečitelný config by pak ale znamenal živý link bez izolace nebo odmítnutí startu. Rozhoduje vlastník.

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
  **S gate se od `f3/security-fixes` explicitní název odmítá, viz 2.5.**
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
`Down` a `Status` bez selektoru se chovají jako dnes. `Down{all}` provede neprivilegovaný volající
jen na svých a sdílených session a ostatní nechá běžet, se selektorem zároveň je to
`InvalidArgument`. `Status.sessions` se filtruje stejně, včetně `full_status`. `Up` s cizím
`username` se odmítne. Selektor jiné session bez gate zůstává `FailedPrecondition`. Rozhraní je
novým bezpečnostním povrchem, proto ho schvaluje člověk. Výklad a poznatky jsou v 2.5, `f3/rpc-routing`.

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
| Hooky nftables | Každá tabulka se vyhodnocuje na paket. Změřeno v 2.5, PR 19: session přidá 7 base chainů a 16 session zvýší RTT paketů celého hostitele o 3 až 6 µs lokálně a o 6 až 8 µs při forwardu | Změřeno, viz 2.5 |
| DNS listener | Na vlastní overlay IP je port 53 volný, jinak fallback | Fallback na jiný port nesmí tiše vypnout DNS, viz `supportCustomPort` |
| Restart při změně sítě | Všechny session najednou | Omezený souběh celých startů vlastním omezovačem, `bringUpMu` chrání jen alokaci. Jedna pomalá session neblokuje ostatní donekonečna |

**Kritérium pro zvýšení limitu:** scale test s 8 a 16 session v netns projde bez porušení invariantů
a změřená paměť, CPU a latence paketů jsou zaznamenané v této specifikaci. **Splněno 2026-11-05**, viz 2.5, PR 19.
O zvýšení limitu rozhoduje vlastník, dnes zůstává 4.

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

Refcount IP forwardingu a `nf_conntrack_acct` z 5.2 patří do PR 5, `nbnet.Init` do PR 9. PR 1 pokrývá pravidla
105/110 a sysctl, legacy routing nemění (R2).

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
| Auto-update přepíše fork oficiální binárkou | Střední | PR 18: build tag `multiprofile`, vlastní balíček, dotaz na `pkgs.netbird.io` vypnutý, `isAutoUpdateSupported` false |
| Omylem push do upstreamu | Střední | `origin` je fork, push URL `upstream` je zablokovaná, v `gh` vždy `--repo` |
| Únik provozu mezi sítěmi | Vysoký | I3, I4, I6, testy paketů ve všech režimech, security review před F3 |
| Bouře restartů přes network monitor | Střední | I8, omezený souběh startů (5.8) |
| Panic shodí všechny sítě | Střední | Nelze plně zabránit (viz 5.4); residual cleanup a obnovení session ze `sessions.json` po restartu služby |
| Sdílená DNS doména omezí UX | Nízký | Self-hosted správce nastaví vlastní doménu (D7), varování, případný fan-out resolver později |
| Dlouhá řada PR a konflikty v `server.go` | Střední | Malé PR, slití upstreamu těsně před F2, F2 co nejrychleji za sebou |
