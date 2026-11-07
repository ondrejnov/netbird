# W0: spike souběžných profilů na Windows

Zpráva k fázi W0 z [concurrent-profiles.md](concurrent-profiles.md), sekce 2.6. Nástroj je ve větvi
`win/w0-spike` (`client/w0spike`), do `multi-profile` se neslučuje.

## Prostředí a omezení běhu

- 2026-11-07, Windows 11 Pro 10.0.26200, wintun 0.14.1, Go 1.26.10.
- **Pracovní stanice, ne VM** (rozhodnutí vlastníka): běh s `-workstation`, tedy **bez WQ3**. Routy exit nodu
  (`0.0.0.0/1`, `128.0.0.0/1`) by stanici odpojily od sítě. NetBird byl odpojený (`wt0` neexistoval) a NordLynx
  odpojený, služba NordVPN ale běžela. Všechny pozitivní kontroly prošly, takže její filtry výsledky nezkreslily.
- Tři běhy: celý (bez WQ3), znovu WQ5 s přesnější detekcí adapteru a znovu WQ2 s pořadím klíčů. Stav hostitele před
  a po celém běhu se shoduje. Po žádném běhu nezůstal adapter, klíč NRPT ani pravidlo firewallu.
- Testováno jen IPv4 a jen místní úložiště NRPT, GPO úložiště ne.

## I3 a I4: příznaky adapteru

Výchozí stav wintun adapteru je pro IPv4 i IPv6 `Forwarding=false`, `WeakHostSend=false` a `WeakHostReceive=false`.
Nastavení přes `SetIpInterfaceEntry` funguje (u IPv4 s `SitePrefixLength=0`).

Pakety se vkládají do `wt1` jako od peeru. Každý případ má pozitivní kontrolu:

| Případ | Výsledek |
|---|---|
| Peer `wt2` → vlastní adresa `wt2` (kontrola) | doručeno |
| Peer `wt1` → adresa `wt2`, `WeakHostReceive` na `wt1` zapnuté (kontrola) | doručeno |
| Totéž, `WeakHostReceive` vypnuté | **nedoručeno** |
| Peer `wt1` → prefix za `wt2`, `Forwarding` na obou (kontrola) | prošlo |
| `Forwarding` vypnuté na `wt1`, zapnuté na `wt2` | **neprošlo** |
| `Forwarding` zapnuté na `wt1`, vypnuté na `wt2` | prošlo |
| `Forwarding` vypnuté na obou | neprošlo |

**Závěr:** jádro Windows I3 i I4 vynucuje příznaky adapteru, na kterém paket přišel. Rozhoduje `Forwarding`
vstupního adapteru, příznak výstupního ne. Výchozí stav izoluje. Zapnout ho může cokoli na hostiteli (ICS,
`Set-NetIPInterface`), proto ho `SessionIsolation` musí nastavit a pravidelně ověřovat, nestačí ho jen přečíst.

## WQ1 (z kódu)

`nativeRouter` se zapne při `DisableServerRoutes` a `NB_DISABLE_USERSPACE_ROUTING` vypne routing v uspfilteru.
V obou případech routovaný paket dostane jádro, a to ho podle tabulky výše při vypnutém `Forwarding` zahodí.
Izolace tedy platí, routing takové session ale nefunguje. To je stejné jako dnes bez zapnutého forwardingu.

## WQ2: NRPT se stejným namespace ve dvou session

Dva DNS servery na adresách `wt1` (A) a `wt2` (B), dvě pravidla pro `.spike.test`, po každém kole 10 dotazů:

| Kolo | Efektivní pravidlo | Odpovídá |
|---|---|---|
| Jen A (`NetBirdW0-A`) | A | A 10/10 |
| A, pak B (`NetBirdW0-B`) | A | A 10/10, B nedostal žádný dotaz |
| B, pak A smazané a zapsané znovu | A | A 10/10 |
| B, pak A pod klíčem `NetBirdW0-Z` | **B** | B 10/10 |
| Server vítězného pravidla zastavený | B | **jméno se nepřeloží**, A nedostal žádný dotaz |

**Závěr:** platí jedno pravidlo pro namespace, a to to, jehož klíč je abecedně první. Na pořadí zápisu nezáleží.
Neslučuje se, NXDOMAIN ani nedostupný server nepřepadne na druhé pravidlo. Druhá session se stejnou doménou tedy
tiše nic nepřeloží, a proto platí politika sekce 6: zapisuje jen vlastník domény a ostatní dostanou varování.
S názvy z 2.6 vyhraje slot 0 (`NetBird-` je před `NetBirdS`, `-` < `S`). Sloty N se řadí lexikálně
(`NetBirdS10` před `NetBirdS2`), na tom ale nesmí nic stavět, protože konflikt má řešit koordinátor.

## WQ3 (jen z kódu, spike na stanici neběžel)

`systemops.GetBestInterface` přeskakuje jediný interface z procesového `vpnInterfaceName`. S exit nodem na `wt1` by
pro sockety session na `wt2` vybral `wt1`. Ověřit ve VM (běh bez `-workstation`) před W3.

## WQ4: stejný prefix na dvou adapterech

Metrika interfaců je u obou pevně 5:

| Pořadí přidání | Vybere Windows i `GetBestInterface` | Po odebrání první routy |
|---|---|---|
| `wt1` m5, `wt2` m10 | `wt1` | `wt2` |
| `wt2` m10, `wt1` m5 | `wt1` | `wt1` |
| `wt1` m5, `wt2` m5 | `wt1` | `wt2` |
| `wt2` m5, `wt1` m5 | `wt2` | `wt1` |

**Závěr:** rozhoduje nižší metrika. Při shodné metrice vyhraje dřív přidaná routa, stabilně 5 z 5. Po odebrání
převezme provoz zbylá routa sama. Pravidlo 5.2 „stejný prefix instaluje jen vlastník" na Windows platí beze změny.
Kdyby se instalovaly obě, rozhodovalo by pořadí, ne koordinátor.

## WQ5: životní cyklus adapteru

- **Pád:** adapter zabitého procesu (`TerminateProcess`) zmizí sám asi za 2,25 s. GUID se pak ještě překládá na
  LUID se stavem `Down`, a PnP zařízení je chvíli `Unknown/not present`. Po skončení procesu nezůstalo nic.
  **`links_windows.go` pro úklid po pádu není potřeba,** `links_other.go` na Windows platí.
- **Kolize GUID:** druhý `CreateAdapter` s GUID živého adapteru selže s `ERROR_FILE_EXISTS` a živý adapter zůstane
  netknutý. Start slotu, jehož adapter z předchozího pokusu ještě zaniká, proto selže. Potřebuje stejné čekání
  jako `closingTunWait` na Linuxu (5 s).
- **Kolize jména:** druhý adapter se jménem `wt2` vznikne a dostane `wt2`. **Existující adapter se přejmenuje na
  `wt2 1`.** Session tedy přejmenuje cizí adapter s jejím jménem a cizí program přejmenuje adapter session.
  Kód, který adapter session hledá podle jména (`net.InterfaceByName` v `GetBestInterface`), by pak našel cizí
  adapter.

## Dopady na plán

| PR | Dopad |
|---|---|
| W1 | Úklid po pádu odpadá. `RefuseForeignLink` na Windows: odmítnout adapter se jménem slotu a jiným GUID, a na GUID slotu čekat nejvýš 5 s, než adapter předchozího pokusu zanikne |
| W2 | `SessionIsolation.Add` nastaví `Forwarding`, `WeakHostSend` a `WeakHostReceive` na false pro IPv4 i IPv6, `Verify` je kontroluje. Když nastavení selže, session se odmítne (I3, I4). **Otázka pro vlastníka:** jsou příznaky „jaderná izolace" ve smyslu Q9 (`Kernel=true`), takže by šla povolit i session s vypnutým firewallem? Do rozhodnutí se taková session odmítá jako dnes |
| W3 | Výběr bound interfacu musí přeskakovat všechny interfaces session, ne jen jeden. Adaptery session hledat podle LUID nebo indexu, ne podle jména. Vlastnictví rout podle 5.2 platí beze změny |
| W4 | Klíče NRPT podle 2.6, zapisuje jen vlastník domény a catch-all. Konflikt je tichý, proto varování v `SystemEvent` |
| W0 | Zbývá běh ve VM bez `-workstation` kvůli WQ3 |
