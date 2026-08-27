# BTL1 — SIEM / Security Monitoring Cheat Sheet

> Esame: 24h, 20 task, open-book, soglia 70%. **Tool del dominio: Splunk.**
> La skill testata: **trovare i 5 eventi che contano su 50.000 che non contano.**
>
> ⚠️ **Nel lab d'esame non c'è internet, tranne che per Splunk.** OSINT (VirusTotal, WHOIS, CVE) si fa dal **tuo** browser, fuori dalla VM. Per questo questa cheat sheet deve bastarti da sola.
>
> 📌 **`SPL` = Search Processing Language**, il nome del linguaggio di query di Splunk. Tutto quello che hai fatto nei lab **era già SPL** — il corso non lo nomina, ma è lo stesso.

---

## ⚡ START — I PRIMI 60 SECONDI DI OGNI TASK SPLUNK

```bash
sudo systemctl start Splunkd          # se Splunk non risponde
# Firefox → http://127.0.0.1:8000   (o http://<IP-SIEM>:8000)
# → app "Search and Reporting"
```

**Checklist prima di ogni ricerca — l'80% dei "0 eventi" viene da qui:**
- [ ] Time picker → **All Time** (i dati sono storici, spesso 2016!)
- [ ] Sampling → **No Event Sampling**
- [ ] La query inizia con `index=` (obbligatorio)

**Poi, SEMPRE, scopri com'è fatto il dataset prima di scrivere query complesse:**
```splunk
index=* | stats count by sourcetype
```
```splunk
index=* | stats count by index, sourcetype, source
```
👉 Questi due comandi ti dicono **quali sourcetype esistono davvero** nel tuo ambiente. Senza questo passaggio, ogni query copiata da una cheat sheet è un tiro al buio: i nomi dei sourcetype e dei campi **cambiano tra ambienti**.

**Poi verifica i nomi dei campi di quel sourcetype:**
```splunk
index=* sourcetype=<quello_che_ti_serve> | head 5
```
→ espandi un evento e leggi i nomi reali dei campi. Oppure `| fieldsummary`.

---

## 0. INDICE

| # | Sezione |
|---|---|
| **⚡** | **Start — primi 60 secondi** |
| 1 | SIM / SEM / SIEM — fondamenti |
| 2 | Logging e scoping |
| 3 | Syslog (porte, PRI, facility, severity) |
| 4 | Windows Event Logs + **tabella Event ID** |
| 5 | Sysmon |
| 6 | Log aggregation |
| 7 | Normalization + **mappa campi** |
| 8 | Regole SIEM, threshold, tuning |
| 9 | Sigma |
| 10 | **Splunk — query base (il 90% di quello che userai)** |
| 11 | **SPL — comandi core** |
| 12 | Time modifiers |
| 13 | Alert |
| 14 | Dashboard |
| 15 | **Detection query pronte** |
| 16 | **Metodologia investigativa (dai 4 lab)** |
| 17 | Pitfall e troubleshooting |
| 18 | Appendice: sourcetype, Event ID, numeri |
| **19** | **APPENDICE OPZIONALE — SPL avanzata** (solo se ti blocchi) |

---

## 1. SIM / SEM / SIEM

| | **SIM** | **SEM** |
|---|---|---|
| Focus | **Storico / gestione** log | **Tempo reale** — eventi, alert |
| Output | Report, grafici, trend | Alert immediati (anche **SMS**), correlazione live |
| Pro | Facile deploy, grandi volumi, correla log | **Centralizza**, riduce **FP/FN**, migliora tempi di risposta |
| Contro | Costoso, può non adattarsi, supporto limitato | **Difficile deploy**, costoso, può comunque produrre FP/FN |

**SEM — come valuta:** algoritmi, statistica, **database di vulnerabilità** → login anomali, richieste web insolite, software obsoleto.

### SIEM = SIM + SEM
```
Device (firewall, server, DC, endpoint) → inviano log
        ↓
Correlation Engine → analizza (regole + correlazioni statistiche)
        ↓
Database → storage
        ↓
Dashboard → l'analista identifica, fa triage, risponde
```

**Le 4 funzioni:**
| Funzione | Perché |
|---|---|
| **Aggregation** | Formati diversi in un posto — senza, la correlazione è **impossibile** |
| **Normalization** | Campi grezzi → campi **coerenti** tra sorgenti |
| **Correlation** | Pattern su **più eventi** (5 fail + 1 success; Word → PowerShell; IP malevolo noto) |
| **Retention** | Rende ricercabile il passato (incidente iniziato 3 settimane fa) |

**Setup (4 passi):** capire l'infrastruttura → capire come raccogliere i log → pianificare hardware (se non SaaS) → **scrivere regole/report** (step **continuo**).

**I 3 benefici:**
1. **Advanced Threat Detection** — rileva insider malevoli, exfiltration, minacce che sfuggono ad AV/firewall/IDS
2. **Forensics e IR** — log storici protetti e ammissibili come prova (→ Chain of Custody)
3. **Compliance** — HIPAA, PCI/DSS, SOX, FERPA, HITECH; formato **audit-ready**. Anche ISO 27001/2/3

⚠️ Un SIEM **non funziona da solo**: serve personale + security policy. Non protegge da tutto, **identifica** la maggior parte.

---

## 2. LOGGING

**Ogni attività** (email, login, update firewall) è un **security event**.

| Fonte | Cosa rileva |
|---|---|
| **Log utenti AD** | Login, password errate, uso account admin, account creati/eliminati → **brute-force**, **password spraying** |
| **Log firewall** | **Port scan**, vuln scan, **DDoS**, problemi di rete |

⚠️ **Scoping:** definire **quali** log e **da quali** device. Meno rumore = più facile analizzare i dati **rilevanti** invece di tutti quelli **disponibili**.

> 🧠 **"I SIEM non sono repository di log, sono piattaforme di analisi."**

---

## 3. SYSLOG

**RFC 5424.** Gira su switch, router, firewall, endpoint, **Unix/Linux**, web server.
⚠️ **Windows non usa Syslog nativamente** — può essere forwardato con tool terzi.

| Porta | Uso |
|---|---|
| **UDP 514** | Default |
| **TCP 514** | Più affidabile |
| **TCP 6514** | *De facto* per trasferimento **sicuro** (non ufficiale) |

⚠️ **Nessuna autenticazione né cifratura built-in** → spoofing dei log, intercettazione.

### Messaggio — 3 componenti
**1. PRI:**
```
PRI = (Facility Code × 8) + Severity Value
```
Esempio: Security/Auth (4) + Critical (2) → `(4×8)+2 = 34`

**Facility (0–23):**
| # | | # | |
|---|---|---|---|
| 0 | Kernel messages | 9 | Clock Daemon |
| 1 | User-level messages | **10** | **Security/Authorization** *(dup. del 4)* |
| 2 | Mail System | 11 | FTP Daemon |
| 3 | System Daemons | 12 | NTP Subsystem |
| **4** | **Security/Authorization** | 13 | Log Audit |
| 5 | Messages generated by syslog | 14 | Log Alert |
| 6 | Line Printer Subsystem | 15 | Clock Daemon |
| 7 | Network News Subsystem | 16–23 | Local Use 0–7 |
| 8 | UUCP Subsystem | | |

**Severity (0–7)** — 0 = più grave:
| Val | Severity | Keyword | Condizione |
|---|---|---|---|
| **0** | Emergency | `emerg` | Sistema **inutilizzabile** (panic) |
| **1** | Alert | `alert` | Azione **immediata** |
| **2** | Critical | `crit` | Errori hardware critici |
| **3** | Error | `err` | Condizioni di errore |
| **4** | Warning | `warning` | Attenzione |
| **5** | Notice | `notice` | Normale ma significativo |
| **6** | Informational | `info` | Informativo |
| **7** | Debug | `debug` | Debug |

**2. Header** → Timestamp, Hostname, Application name, Message ID
**3. Message** → il protocollo definisce solo il **formato**, non il contenuto

---

## 4. WINDOWS EVENT LOGS

**Formato:** file binari **`.evtx`**
| Versione | Path |
|---|---|
| Win2000 → XP/Server 2003 | `%WinDir%\system32\Config\*.evt` |
| Server 2008–2019, Vista → Win10+ | `%WinDir%\system32\WinEVT\Logs\*.evtx` |

### Le 6 categorie
| Categoria | Contenuto |
|---|---|
| **Application** | Eventi di applicazioni |
| **System** | SO (device loading, errori avvio) |
| **Security** | Login/logout, cancellazione file, permessi admin |
| **Directory Service** | ⚠️ Solo **DC** — eventi AD |
| **DNS Server** | ⚠️ Solo server DNS |
| **File Replication Service** | ⚠️ Solo **DC** — replica |

**Security Audit Policies monitorano:** account logon · account management · privilege use · resource usage (file)

### Event Viewer
`Windows Logs` → **Application, Security, Setup, System, Forwarded Events**
**Summary of Administrative Events** → overview 7 giorni

**Event 5379** — lettura credenziali dal **Credential Manager** al login. Campi: Security ID · Account Name/Domain · **Logon ID** (semi-univoco, unico tra reboot) · Read Operation

### ⭐ Logon vs Special Logon — sequenza reale
```
4624 (Logon)  →  4672 (Special Logon)
```
Un account **admin** genera **prima** 4624, **poi** 4672 — sono **accoppiati**.
⚠️ Nel pannello il più recente è **in cima** → visivamente appaiono al contrario.

### Custom Views
Filtri salvati per ridurre il rumore. ⚠️ **Fondamentali se un sistema NON è collegato al SIEM.**

| Proprietà | Funzione |
|---|---|
| **Logged** | Range temporale (Any Time / 1h / 12h / 24h / 7d / custom) |
| **Event Level** | Severità |
| **By Log** | Categoria (es. solo Security + System) |
| **By Source** | Componente specifico |
| **Includes/Excludes Event IDs** | Lista con virgole: `4624,4625,4634,4672` |
| **Keywords** | Parola chiave |
| **User and Computers** | Utente/sistema specifico |

### ⭐ Tabella Event ID
| ID | Log | Cosa indica |
|---|---|---|
| **4624** | Security | **Logon riuscito** |
| **4625** | Security | **Logon fallito** |
| **4634** | Security | Logoff |
| **4647** | Security | Logoff **iniziato dall'utente** |
| **4672** | Security | **Special Logon** (admin) |
| **4648** | Security | Logon con **credenziali esplicite** (runas / lateral movement) |
| **4688** | Security | **Process creation** (+ command line se advanced auditing attivo) |
| **4698** | Security | **Scheduled task creato** → 🚩 persistenza |
| **4720** | Security | **Account creato** → 🚩 persistenza |
| **4728 / 4732** | Security | Utente aggiunto a gruppo **global / local** → 🚩 priv esc |
| **4657** | Security | **Valore di registro modificato** |
| **5140** | Security | Accesso a **network share** |
| **1102** | Security | 🚩🚩 **Audit log CANCELLATO** (anti-forensics) |
| **104** | System | **System log cancellato** |
| **7045** | System | **Nuovo servizio installato** → 🚩 persistenza |
| **7036** | System | Cambio stato servizio (rileva **Sysmon stoppato**) |
| **4104** | PowerShell/Operational | **Script block logging** — PowerShell **deobfuscato** |

**Logon Type (in 4624/4625):**
| # | Tipo | # | Tipo |
|---|---|---|---|
| **2** | Interactive (fisico) | 7 | **Unlock** |
| **3** | **Network** | 8 | NetworkCleartext |
| 4 | Batch | 9 | NewCredentials (`runas /netonly`) |
| 5 | Service | **10** | **RemoteInteractive (RDP)** |
| 6 | Proxy (non usato) | | |

**Codici errore 4625:**
| Codice | Significato | Codice | Significato |
|---|---|---|---|
| `0xC0000064` | Utente inesistente | `0xC0000070` | Restrizione workstation |
| `0xC000006A` | Password errata | `0xC0000071` | Password scaduta |
| `0xC000006C` | Policy password | `0xC0000072` | **Account disabilitato** |
| `0xC000006D` | Bad username | `0xC000009A` | Risorse insufficienti |
| `0xC000006E` | Restrizione account | `0xC0000193` | Account scaduto |
| `0xC000006F` | Restrizione oraria | `0xC0000224` | Deve cambiare password |
| | | `0xC0000234` | **Account bloccato** |

🚩 **Pattern sospetti:** molti tentativi su account **disabilitato** (`0xC0000072`) o **username inesistente** (`0xC000006D`) = bruteforce / user enumeration.

---

## 5. SYSMON

Servizio + driver Windows, **persiste tra i reboot**, scrive **dentro il Windows Event Log** (canale `Microsoft-Windows-Sysmon/Operational`) — non un log separato.

### Capacità
- **Process creation con command line completa** — processo **corrente E parent**
- **Session GUID** → correlazione eventi della stessa sessione di logon
- Caricamento **driver/DLL** con **firme e hash**
- (Opz.) **connessioni di rete**: processo sorgente, IP, porte, hostname
- 🚩 Rileva modifiche al **file creation time** (tecnica anti-forense)
- **Rule filtering** dinamico

**Perché è preferito ai log nativi:** formattazione migliore, **molte più info utili**.

### Comandi
```cmd
sysmon -i                       :: installa (CMD come Amministratore)
sysmon -i sysmonconfig.xml      :: installa CON config
sysmon -c sysmonconfig.xml      :: aggiorna la config esistente
sysmon -u                       :: DISINSTALLA
sysmon -u force                 :: disinstalla forzando
```
**Vedere i log:** Event Viewer → **Create Custom View** → tutti gli Event Level → salva

### ⚠️ Il rumore
Sysmon è **molto verboso**. Config di riferimento: **SwiftOnSecurity sysmon-config** (GitHub) — commentata, funge da tutorial.
```powershell
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:1073741824   # es. 1GB di canale log
```

### ⭐ Sysmon Event ID
| ID | Evento |
|---|---|
| **1** | **Process creation** (command line + parent) |
| **3** | **Network connection** |
| **7** | **Image/DLL loaded** ← contiene gli **hash** |
| **8** | CreateRemoteThread (→ process injection) |
| **10** | ProcessAccess (→ credential dumping su lsass) |
| **11** | **File created** |
| **13** | **Registry value set** |
| **22** | **DNS query** |

---

## 6. LOG AGGREGATION

| Metodo | Come |
|---|---|
| **Syslog** | Syslog server riceve da più sistemi; l'aggregator legge direttamente |
| **Event Streaming** | **SNMP, Netflow, IPFIX** — i device forniscono info standard |
| **Log Collectors** | **Agenti** sui device: catturano, parsano, inviano |
| **Direct Access** | Accesso **diretto** via API → richiede **integrazione custom** per fonte |

| | **Structured** | **Unstructured** |
|---|---|---|
| Cosa | Campi **definiti** (`src_ip`) | Formato **variabile**, **multi-riga**, senza inizio/fine definiti |
| Esempi | Apache, IIS, Windows Events, Cisco | Applicazioni **custom** |
| Volume | Minoranza | ⚠️ **La maggioranza** dei dati in un SIEM |

---

## 7. NORMALIZATION E PROCESSING

| Concetto | Cosa fa |
|---|---|
| **Normalization** | Formato **comune** tra sorgenti diverse |
| **Categorization** | Aggiunge **significato** (system event? autenticazione? operazione remota?) |
| **Log Enrichment** | Aggiunge info. 📌 Classico: **IP → geolocalizzazione/paese** |
| **Log Indexing** | Indicizza attributi condivisi → ricerche **molto più veloci** |
| **Log Storage** | On-prem, **AWS S3**, **Hadoop**. Valutare: costo, usabilità, scalabilità |

⚠️ **Non esiste un formato universale di log.**
```
source_ip  (normalizzato)
   ├── src_ip          ← Cisco
   └── source_address  ← Juniper
```

### ⭐ Mappa campi — la tabella più utile del dominio
| Dato | Sysmon | Windows Security | Normalizzato |
|---|---|---|---|
| Nome processo | `Image` | `NewProcessName` | `process_name` |
| Processo parent | `ParentImage` | `ParentProcessName` | `parent_process` |
| Command line | `CommandLine` | `CommandLine` | `process_command_line` |
| IP sorgente | `SourceIp` | `IpAddress` | `src_ip` |
| IP destinazione | `DestinationIp` | — | `dest_ip` |
| Utente | `User` | `Account_Name` | `user` |
| Host | `Computer` | `ComputerName` | `host` |

⚠️ **Verifica sempre i nomi reali:** `| fieldsummary` oppure espandi un evento.

---

## 8. REGOLE SIEM

**2 tipologie:** **out-of-the-box** (vendor, attacchi generici) vs **custom** (scritte da chi conosce cosa è normale nel proprio ambiente).
**Esecuzione:** **real-time/continua** oppure **schedulata**.

### Cosa monitorare
**Auth/Account:** login falliti · login su **account disabilitati** · uso account admin · 🚩 **cambio SID** (priv esc)
**Process:** esecuzione da **temp/browser cache** · 🚩 **parent-child sospetti** (Word → CMD/PowerShell) · **hash malevoli noti**
**Network:** port scan · service enumeration · host discovery

### Tuning
**Problema 1 — rumore.** Alert su ogni singolo 4625 è inutile.
→ **Threshold + finestra:** `SE fallimenti > 10 in 10 min → alert`

**Problema 2 — attività legittima che sembra attacco.**
```
Regola: 1 IP → molti sistemi interni = possibile scan
   ↓ l'azienda installa un vulnerability scanner → stesso pattern → FALSO POSITIVO
   ↓ Fix: ESCLUDERE quell'IP dalla regola
   ↓ Il SIEM vede ancora l'attività, ma non alerta per quell'IP
```

> ⚠️ Le soglie sono **punti di partenza**, da tarare sulla **baseline**. Ciò che è brute-force in un'azienda di 10 persone è rumore normale in un'enterprise. **Documenta nel report la soglia usata e perché.**

---

## 9. SIGMA

Formato di firma **generico, open source, vendor-agnostic**.
```
Regola in Sigma  →  convertitore SIGMAC  →  formato del SIEM target
```
Reversibile (da formato vendor → Sigma).

**Piattaforme:** **Splunk, QRadar, ArcSight, Elasticsearch** (Elastalert, query string, DSL, Watcher, Kibana), **Logpoint**

**Benefici:** detection **condivisibile** · evita **vendor lock-in** · si allega ai report con **IOC** e **YARA** · si condivide negli **ISAC** (es. via **MISP**)

### Campi YAML
| Campo | Funzione |
|---|---|
| `title` | Brevissima descrizione |
| `id` | Identificatore univoco (opzionale) |
| `status` | `incomplete` / `experimental` / `production` |
| `description` | Cosa rileva e come |
| `author` / `date` / `modified` | Autore, creazione, ultima modifica |
| `references` | URL esplicativi |
| **`logsource`** | **Quali log servono** perché funzioni (es. `category: dns`) |
| **`detection`** | La logica: `selection` + `condition` |
| ↳ `selection` | Campo + valore (`'*'` = **wildcard**) |
| ↳ `condition` | Logica reale (es. `selection \| count(dns_query) by parent_domain > 1000`) |
| `falsepositives` | Come possono verificarsi FP |
| `level` | Urgenza |
| `tags` | Tecniche **MITRE ATT&CK** |

📌 **Esempio web shell:** keyword matching su URL. Shell su `.../shell.php?`, attaccante lancia `whoami` → la GET conterrà `=whoami` → alert. **FP bassissimi**: un utente normale non mette comandi OS in una GET.

🧠 **Logica di tuning:** da detection **generica** (`parent_domain: '*'`, soglia 1000) a **mirata su IOC noto** (dominio specifico + soglia **sotto la media osservata**, per catturare varianti con volume minore).

---

## 10. SPLUNK — QUERY BASE

### Interfaccia
| Elemento | Cosa contiene |
|---|---|
| **Apps Panel** | App installate |
| **Splunk Bar** | Cambio app, impostazioni, notifiche |
| **Explore Splunk Panel** | Documentazione, aggiungere dati |
| **Home Dashboard** | Le dashboard create appaiono qui |

### Anatomia di una query
```splunk
index="botsv1" sourcetype=wineventlog EventCode=4625 earliest=0
```
| Elemento | Significato |
|---|---|
| `index=` | **Quale dataset**. **Obbligatorio**. `index=*` = tutti (lento) |
| `sourcetype=` | **Tipo di log** — ⭐ **mettilo sempre**: rende la query veloce e garantisce che i campi che usi esistano |
| `host=` | Quale host ha generato il log |
| `earliest=0` | Dal **primo evento** (alternativa a "All Time" nel picker) |
| keyword nuda | **Full-text** nel raw event (es. `vulnerability`, `osk.exe`) |

**Event Sampling** (1:10, 1:100...) → 1 evento ogni N. **Solo per esplorare**, poi **disattiva**.

### Fields — il tuo strumento principale
**Selected Fields** = base sempre visibili (`host`, `source`, `sourcetype`)
**Interesting Fields** = altri campi rilevati

| Campo | Cosa mostra |
|---|---|
| `host` | Da quale sistema arriva il log |
| `source` | Da dove/come è raccolto (`WinEventLog:Security`, `udp:514`, `/var/log/suricata/eve.json`) |
| `sourcetype` | Tipo di dato (`wineventlog`, `fgt_traffic`, `suricata`) |

⭐ **Click su un valore → lo aggiunge automaticamente alla query.** È la scorciatoia che userai più di tutte.
⭐ Click su un field → **Top 10 valori** con conteggio e **%** → identifichi subito i valori più rumorosi.

### Booleani e wildcard
```splunk
EventCode=4624 OR EventCode=4625
index=* NOT (host="internal-monitor")
src="10.10.10.50" OR dst="10.10.10.50"
dst="10.10.10.*"              ← qualsiasi IP che inizia con 10.10.10.
Image="*\\cmd.exe"            ← qualsiasi path che finisce con cmd.exe
pass* AND fail*               ← "pass"/"password" + "fail"/"failure"
```

---

## 11. SPL — COMANDI CORE

> Questi 6 comandi + il click sui field coprono **praticamente tutto** l'esame. Ogni `|` passa i risultati al comando successivo: **l'ordine conta**.

### `stats` — aggregazione (il più usato di tutti)
```splunk
| stats count by srcip                        ← quante volte appare ogni valore
| stats count by srcip | sort -count          ← ⭐ pattern classico: chi è più attivo
| stats count by src_ip, user
| stats values(CommandLine) by host           ← elenca i valori distinti
| stats dc(user) as utenti_unici by host      ← dc() = distinct count
```

### `sort` — ordinamento
```splunk
| sort time asc         ← crescente (più VECCHIO in cima) = inizio dell'attacco
| sort time desc        ← decrescente
| sort -count           ← shorthand per decrescente
| sort limit=2 time asc ← limita i risultati
```
⚠️ Il campo `time` **dentro il log** può differire dalla colonna Time di Splunk (timezone). Nei task usa **il campo del log**.

### `table` — mostra solo i campi che ti servono
```splunk
| table _time, srcip, dstip, dstport, action, msg
| table timestamp, form_data
```
Non filtra i dati, **nasconde le colonne**. Le intestazioni diventano ordinabili con un click.

### `dedup` / `uniq` — valori unici
```splunk
| dedup action              ← ⭐ scopri QUALI valori esistono per un campo
| table srcip | uniq
```
Se `uniq` non dà risultati coerenti, usa `dedup`.

### `spath` — estrai campi da JSON/XML
```splunk
| spath timestamp | search timestamp="2016-08-10T21:46:44.453730Z"
```

### `head` / `tail` — limita l'output
```splunk
| head 20    ← primi 20 (utile per sbirciare la struttura di un sourcetype nuovo)
| tail 10
```

---

## 12. TIME MODIFIERS

```splunk
earliest=0                                  ← dal primo evento disponibile ⭐
earliest=-24h latest=now
earliest=-15m latest=now
earliest=-7d@d latest=@d                    ← ultimi 7 giorni COMPLETI
earliest=-1h@h latest=@h                    ← ultima ora COMPLETA
earliest="01/15/2024:08:00:00" latest="01/15/2024:16:00:00"
```
**`@`** = "snap to": `@d` mezzanotte, `@h` inizio ora, `@w` inizio settimana.

⚠️ **Imposta sempre un range** (query o time picker). `index=*` senza range = troppi dati.

---

## 13. ALERT

### I 4 step
| # | Step | Contenuto |
|---|---|---|
| 1 | **Search Query** | Cosa rilevare → tradotto in query |
| 2 | **Search Timing** | **Real-time** (maggioranza) vs **Scheduled** (deviazioni da **baseline**) |
| 3 | **Alert Trigger** | **Threshold** + finestra (es. 6 fallimenti per utente in 5 min) |
| 4 | **Alert Action** | Cosa succede quando scatta |

### Workflow
```
Search query → Save As → Alert
```
| Campo | Opzioni |
|---|---|
| **Permissions** | **Private** vs **Shared in App** (read di default, write per power user) |
| **Alert type** | **Scheduled** (es. "Run every week") vs **Real-time** |
| **Expires** | Scadenza (es. 24h) |
| **Trigger Conditions** | Es. "Number of Results is greater than 0" |
| **Trigger** | **Once** (1 notifica) vs **For each result** |
| **Throttle** | Limita notifiche ripetute |

**Trigger Actions:** Add to Triggered Alerts · Log Event · Output to **lookup** (CSV) · Output to telemetry endpoint · **Run a script** · Email (eventi ad alto profilo) · **Webhook** (integrazioni custom)

---

## 14. DASHBOARD

### Info tipiche in un SOC
Firewall **deny/allow** (spike deny = DDoS o problema di rete) · alert **in/attesa di** investigazione · alert **chiusi in 24h** (efficienza team) · **traffic flow per collector** (rileva outage) · **attack map** (IP su mappa) · **pie chart** tipi di evento

### ⭐ Workflow: Report → Dashboard
⚠️ **Serve prima un Report** — la dashboard si costruisce su query salvate.
```
1. Ricerca → Save As → Report
2. Apri il report → "Add to Dashboard"
```
**Naming convention Splunk:** `<group>_<object>_<description>` → es. `IT_report_FailedLogins`

| Campo | Nota |
|---|---|
| **Dashboard Permissions** | ⚠️ **Private** finché non testata |
| **Panel Powered By** | **Inline Search** (query scritta ora) o **Report** salvato |

### Modificare panel
```
Query → Save As → Existing Dashboard → seleziona
Dashboard → Edit → "Select Visualization" sul panel → Pie / Line / Bar / Table
Edit → trascina il bordo tratteggiato (::::::) per riposizionare
Edit → icona LENTE sul panel → VEDI la query che lo alimenta   ⭐
Home app → "Choose a home dashboard"
```

💡 Panel utili: **Login Failures** line chart (spike = brute-force) · **HTTP response codes** line chart

---

## 15. DETECTION QUERY PRONTE

### ⚠️ PRIMA DI USARLE — leggi questo
Queste query usano `sourcetype` e nomi di campo che **variano tra ambienti**. Non copiarle alla cieca: fai **2 passaggi**.

**Passo 1 — scopri i sourcetype del TUO ambiente:**
```splunk
index=* | stats count by sourcetype
```

**Passo 2 — sostituisci il segnaposto** nelle query sotto con quello che hai trovato:

| Segnaposto nelle query | Valori comuni da sostituire |
|---|---|
| `<WINSEC>` | `wineventlog` · `WinEventLog:Security` · `XmlWinEventLog:Security` |
| `<SYSMON>` | `xmlwineventlog` · `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| `<FW>` | `fortigate_traffic` · `fgt_traffic` · `firewall` · `pan:traffic` |
| `<PROXY>` | `proxy` · `squid` · `bluecoat` |
| `<DNS>` | `stream:dns` · `dns` · `named` |
| `<IDS>` | `suricata` · `snort` |

**Passo 3 — se una query non restituisce nulla, verifica i nomi dei campi:**
```splunk
index=* sourcetype=<il_tuo_sourcetype> | head 5
```
Poi correggi (es. `EventCode` → `EventID`, `Account_Name` → `user`).

📌 **Nota SPL:** i commenti si scrivono con backtick tripli, ` ```testo``` `. Una **pipe a inizio riga è un comando**, non un commento — sotto i commenti sono con `###` **fuori** dai blocchi.

---

### Autenticazione e brute force

**Login falliti per utente — chi è sotto attacco**
```splunk
index=* sourcetype=<WINSEC> EventCode=4625 earliest=0
| stats count by Account_Name, IpAddress
| where count > 10
| sort -count
```

**Login falliti per IP sorgente — chi sta spruzzando credenziali**
```splunk
index=* sourcetype=<WINSEC> EventCode=4625 earliest=0
| stats count, dc(Account_Name) as account_diversi by IpAddress
| sort -count
```

**Password spray — 1 sorgente, MOLTI account diversi**
```splunk
index=* sourcetype=<WINSEC> EventCode=4625 earliest=0
| stats dc(Account_Name) as account_bersagliati, count by IpAddress
| where account_bersagliati > 10
| sort -account_bersagliati
```

**Brute force RDP (Logon Type 10)**
```splunk
index=* sourcetype=<WINSEC> EventCode=4625 Logon_Type=10 earliest=0
| stats count by Account_Name, IpAddress
| sort -count
```

**Timeline di un account specifico — fallimenti e successi insieme**
```splunk
index=* sourcetype=<WINSEC> (EventCode=4624 OR EventCode=4625) Account_Name="<utente>" earliest=0
| table _time, EventCode, Account_Name, IpAddress, Logon_Type
| sort _time asc
```
⭐ Se dopo una serie di 4625 appare un 4624 dallo **stesso IP** → **brute force riuscito**. È il modo più diretto di rispondere a "l'attacco ha avuto successo?".

**Brute force su form web (pattern del Lab 1)**
```splunk
index=* sourcetype=stream:http http_method=POST uri="/joomla/administrator/index.php" earliest=0
| table timestamp, src_ip, form_data
| sort timestamp asc
```

---

### Process creation anomali

**Office che genera shell — indicatore forte di macro malevola**
```splunk
index=* sourcetype=<WINSEC> EventCode=4688 earliest=0
(ParentProcessName="*\\winword.exe" OR ParentProcessName="*\\excel.exe"
 OR ParentProcessName="*\\outlook.exe" OR ParentProcessName="*\\powerpnt.exe")
(NewProcessName="*\\cmd.exe" OR NewProcessName="*\\powershell.exe"
 OR NewProcessName="*\\wscript.exe" OR NewProcessName="*\\mshta.exe")
| table _time, ComputerName, Account_Name, ParentProcessName, NewProcessName, CommandLine
```

**Variante Sysmon (Event ID 1)**
```splunk
index=* sourcetype=<SYSMON> EventCode=1 earliest=0
(ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe")
(Image="*\\powershell.exe" OR Image="*\\cmd.exe")
| table _time, Computer, User, ParentImage, Image, CommandLine
```

**PowerShell encoded — payload base64**
```splunk
index=* sourcetype=<SYSMON> EventCode=1 earliest=0
(CommandLine="* -enc *" OR CommandLine="* -EncodedCommand *")
| table _time, Computer, User, CommandLine
```

**PowerShell download cradle**
```splunk
index=* sourcetype=<SYSMON> EventCode=1 earliest=0
(CommandLine="*Invoke-WebRequest*" OR CommandLine="*DownloadString*"
 OR CommandLine="*DownloadFile*" OR CommandLine="*IEX*" OR CommandLine="*Net.WebClient*")
| table _time, Computer, User, CommandLine
```

**LOLBins — binari legittimi abusati**
```splunk
index=* sourcetype=<SYSMON> EventCode=1 earliest=0
(Image="*\\certutil.exe" OR Image="*\\bitsadmin.exe" OR Image="*\\regsvr32.exe"
 OR Image="*\\mshta.exe" OR Image="*\\wmic.exe" OR Image="*\\rundll32.exe")
| table _time, Computer, User, Image, CommandLine
```

**⭐ Processo con nome legittimo ma path SBAGLIATO (pattern del Lab 3)**
```splunk
index=* sourcetype=<SYSMON> EventCode=1 earliest=0
Image="*\\<nomefile>.exe" NOT Image="C:\\Windows\\System32\\*"
| table _time, Computer, User, Image, CommandLine
| dedup Image
```

**Command line di un processo specifico, raggruppate per host**
```splunk
index=* sourcetype=<SYSMON> Image="*\\cmd.exe" earliest=0
| stats values(CommandLine) by host
```

---

### Rete, C2, exfiltration

**Connessioni di rete di un processo sospetto**
```splunk
index=* sourcetype=<SYSMON> EventCode=3 Image="*\\<sospetto>.exe" earliest=0
| stats count by DestinationIp, DestinationPort
| sort -count
```

**Quanti IP unici contatta un processo (pattern del Lab 3)**
```splunk
index=* sourcetype=<SYSMON> Image="<path_completo>" DestinationPort=<porta> earliest=0
| stats count by DestinationIp
```
→ il numero di righe nella tab **Statistics** = IP unici contattati.

**Hash di un file (Sysmon Event ID 7)**
```splunk
index=* sourcetype=<SYSMON> EventCode=7 ImageLoaded="*<nomefile>.exe" earliest=0
| table _time, Computer, ImageLoaded, Hashes
```
💡 Serve **un solo evento** → puoi **fermare la ricerca** (bottone quadrato) appena appare.

**Porte in uscita inusuali**
```splunk
index=* sourcetype=<FW> action=allowed earliest=0
NOT (dest_port IN (80, 443, 53, 25, 587, 993, 995))
| stats count by src_ip, dest_port, dest_ip
| sort -count
```

**C2 beaconing — molte connessioni allo stesso IP, pochi URL diversi**
```splunk
index=* sourcetype=<PROXY> earliest=0
| stats count, dc(url) as url_unici by src_ip, dest_ip
| where count > 100 AND url_unici < 5
| sort -count
```

**DNS tunneling — molte query verso lo stesso dominio**
```splunk
index=* sourcetype=<DNS> earliest=0
| stats count by query
| where count > 500
| sort -count
```

**Alert IDS su una coppia IP specifica (pattern del Lab 3 Q13)**
```splunk
index=* sourcetype=<IDS> event_type=alert src_ip=<IP1> dest_ip=<IP2> earliest=0
| table _time, src_ip, dest_ip, dest_port, alert.signature, alert.category, severity
```
⚠️ Se un campo non appare, apri il log raw con la freccia `>` — la vista preview **nasconde** alcuni campi.

**Traffico di un vulnerability scanner / attacco su un dominio (pattern del Lab 2)**
```splunk
index=* sourcetype=<FW> url_domain="<dominio>" vulnerability earliest=0
| table _time, srcip, dstip, srccountry, attack, msg
```

---

### Persistenza e defense evasion

**Scheduled task creati**
```splunk
index=* sourcetype=<WINSEC> EventCode=4698 earliest=0
| table _time, ComputerName, Account_Name, TaskName
| sort -_time
```

**Nuovi servizi installati**
```splunk
index=* sourcetype=<WINSEC> EventCode=7045 earliest=0
| table _time, ComputerName, ServiceName, ServiceFileName, StartType
| sort -_time
```

**Chiavi Run del registro (Sysmon Event ID 13)**
```splunk
index=* sourcetype=<SYSMON> EventCode=13 earliest=0
(TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\Services\\*"
 OR TargetObject="*\\Winlogon\\*")
| table _time, Computer, User, TargetObject, Details
```

**Account creati / aggiunti a gruppi privilegiati**
```splunk
index=* sourcetype=<WINSEC> (EventCode=4720 OR EventCode=4728 OR EventCode=4732) earliest=0
| table _time, ComputerName, Account_Name, TargetUserName, TargetSid
| sort _time asc
```

**🚩🚩 Log cancellati — priorità massima**
```splunk
index=* (EventCode=1102 OR EventCode=104) earliest=0
| table _time, ComputerName, Account_Name, EventCode
```

**Shadow copy eliminate — precursore ransomware**
```splunk
index=* sourcetype=<SYSMON> EventCode=1 earliest=0
(CommandLine="*vssadmin*delete*shadow*" OR CommandLine="*wmic*shadowcopy*delete*"
 OR CommandLine="*bcdedit*recoveryenabled*no*")
| table _time, Computer, User, CommandLine
```

---

## 16. METODOLOGIA INVESTIGATIVA (dai 4 lab)

### ⭐ Il pattern base — narrowing progressivo
```
1. Query ampia su un indicatore noto (URL, metodo HTTP, nome file) → quantifica
2. Interesting Fields → isola il campo chiave (src_ip) → identifica l'ATTORE
3. Click sul valore → restringe automaticamente la query
4. Trova la controparte (dest_ip) → cosa è stato COLPITO
5. Isola UN evento (via timestamp) → capisci la STRUTTURA del dato
6. Scala a TUTTI gli eventi con | table
7. Sort per timestamp ASC → ricostruisci la TIMELINE (primo evento = inizio attacco)
```

### Costruire una query da zero (quando non te la danno)
```
1. index=*  con Sampling 1:100         → esplora velocemente
2. | stats count by sourcetype         → quali log esistono?
3. Selected Fields → sourcetype        → click su quello giusto     = filtro 1
4. Interesting Fields                  → trova il campo con il dato = filtro 2
5. Keyword libere a mano (es. "vulnerability")                      = filtro 3
6. No Event Sampling                   → ricerca reale
```
🧠 Distingui sempre: è un **field=value** (click dal pannello) o una **keyword libera** (da scrivere)?

### ⭐ Pivoting tra fonti — il concetto più importante del dominio
Nessuna fonte sa tutto. Usa un **indicatore condiviso** (di solito l'IP) come **ponte**.

| Fonte | Cosa SA | Cosa NON sa |
|---|---|---|
| **Sysmon** | Processi, command line, hash, hostname, utente | Contesto di rete completo |
| **Firewall/UTM** | Traffico, categoria minaccia, **paese** (enrichment) | **Hostname**, processi |
| **IDS (Suricata)** | Pacchetti, **signature**, severity | **Quale processo** ha generato il traffico |
| **stream:http** | Richieste HTTP, `form_data`, `uri` | Contesto endpoint |
| **VirusTotal / OSINT** | Reputazione, nome malware | Il tuo ambiente |

**Esempio (Lab 4 Q11):** Fortigate ha solo `dstip` e **nessun hostname**.
→ Ragionamento: *"l'alert riguarda abuso di CMD → il sistema è Windows → Windows ha log Sysmon → Sysmon conosce il proprio hostname"*
→ Cambia sourcetype, cerca lo stesso IP. Se restituisce troppi hostname, **aggiungi un secondo indicatore** (l'IP dell'attaccante):
```splunk
index=* sourcetype=<SYSMON> <IP_attaccante> <IP_vittima> earliest=0
| stats count by SourceHostname
| sort -count
```

### Le 8 regole d'oro
1. **Non fidarti del nome del file** — verifica il **path reale** (`Image`) contro quello atteso (OSINT). `osk.exe` fuori da `System32` = **masquerading**
2. **Riusa gli indicatori già trovati** invece di ripartire da zero
3. **Mai assumere i nomi dei campi** tra sourcetype diversi — query esplorativa prima
4. **L'outlier è la cosa interessante** — 1 connessione su porta 80 tra migliaia su 6892 era l'**external IP lookup** del malware
5. **"Show as raw text"** / freccia `>` quando un campo sembra mancare
6. **I link nei log invecchiano** — estrai l'**ID** (VID, CVE) e cercalo nel portale del vendor
7. **Fonti diverse classificano diversamente la stessa minaccia** — Fortigate vedeva Cerber come **botnet** (comportamento di rete), la community come **ransomware** (natura reale). Nessuna è sbagliata
8. **Ferma la ricerca** (bottone quadrato) appena hai l'evento che ti serve

---

## 17. PITFALL E TROUBLESHOOTING

| Sintomo | Causa | Fix |
|---|---|---|
| **0 eventi** su query apparentemente corretta | **Time range** (i dati sono del **2016**!) | Time picker → **All Time** o `earliest=0` |
| **0 eventi** / risultati incompleti | **Event Sampling** attivo | → **No Event Sampling** |
| **0 eventi** ma il sourcetype esiste | **Nome campo sbagliato** per quel sourcetype | `index=* sourcetype=X \| head 5` → leggi i campi reali |
| Ricerca lentissima | `index=*` senza `sourcetype` né range | Aggiungi entrambi |
| Un campo che dovrebbe esserci non c'è | Vista preview lo nasconde | **"Show as raw text"** o espandi con `>` |
| `\| commento` dà errore | Pipe a inizio riga = **comando generatore** | Commenti: ` ```testo``` ` |
| Splunk non risponde | Servizio spento | `sudo systemctl start Splunkd` |
| Firefox "Restore Session" vuoto | Profilo isolato in "Old Firefox Data" | Vai diretto a `http://127.0.0.1:8000` |
| `stats` non aggrega come vuoi | Ordine comandi | `stats` **prima** di `sort`; `where` **dopo** `stats` |
| Troppi alert dalla tua regola | Manca il **threshold** | Soglia + finestra; escludi sorgenti legittime note |
| Sysmon riempie il disco | Canale piccolo, nessuna config | `wevtutil sl ... /ms:<byte>` + config SwiftOnSecurity |

### Confusioni concettuali
| Confusione | Distinzione |
|---|---|
| **SIM vs SEM** | **storico/gestione** vs **tempo reale/eventi** |
| **Normalization vs Categorization** | stesso **formato** vs stesso **significato** |
| **`sort` vs colonna Time** | Il campo `time` **nel log** può differire (timezone) — usa quello del log |
| **`uniq` vs `dedup`** | Entrambi unici; `dedup <field>` più affidabile |
| **`table` vs `fields`** | `table` **seleziona** cosa mostrare · `fields -` **rimuove** |
| **4634 vs 4647** | Logoff generico vs Logoff **iniziato dall'utente** |
| **Real-time vs Scheduled alert** | Maggioranza regole vs deviazioni da **baseline** |
| **Trigger Once vs For each result** | 1 notifica per esecuzione vs 1 per risultato |
| **Sysmon EventID 1 vs 7** | Process creation vs **Image loaded** (contiene gli **hash**) |

---

## 18. APPENDICE

### Sourcetype ricorrenti in BOTSv1
| Sourcetype | Contenuto |
|---|---|
| `stream:http` | HTTP (`form_data`, `uri`, `http_method`) |
| `fortigate_utm` | UTM — alert, categoria minaccia, `srccountry` |
| `fortigate_traffic` / `fgt_traffic` | Firewall (`srcip`, `dstip`, `action`) |
| `suricata` | NIDS (`event_type=alert`, `alert.signature`, `severity`) |
| `xmlwineventlog` | **Sysmon** (`Image`, `CommandLine`, `Hashes`, `DestinationPort`) |
| `wineventlog` | Windows Event Log nativi |
| `winregistry` | Modifiche al registro |
| `stream:dns` / `stream:smb` / `stream:ldap` | Traffico per protocollo |

### Numeri
| Valore | Cosa |
|---|---|
| **RFC 5424** | Standard Syslog |
| **UDP 514 / TCP 514 / TCP 6514** | Syslog: default / affidabile / sicuro |
| **PRI = (Facility × 8) + Severity** | Calcolo Syslog |
| **Facility 0–23 / Severity 0–7** | Range (Severity **0 = più grave**) |
| **Facility 4 e 10** | Entrambe Security/Authorization |
| **`.evtx`** | Estensione Windows Event Log |
| **6** | Categorie Windows Event Log |
| **4** | Metodi di log aggregation |
| **4** | Step del processo di alerting |
| **`<group>_<object>_<description>`** | Naming convention Splunk |
| **BOTSv1 / v2 / v3** | Web compromise / attacco mirato+ransomware / cloud AWS+insider |

### Se trovi Elastic invece di Splunk
Concetti identici (base search → filter → aggregate), sintassi **KQL** / **EQL**:
```
### KQL
event.code : "4625" and host.name : "dc01"

### EQL — sequence detection
sequence by host.name
  [process where process.name == "winword.exe"]
  [process where process.name == "powershell.exe" and process.parent.name == "winword.exe"]
```

### Pratica
**BOTS datasets** (Splunk CTF pubblici) · **Blue Team Labs Online** · **CyberDefenders** (tag SIEM) · **LetsDefend** · **TryHackMe** · **Splunk Fundamentals 1** (gratis) · **Splunk Search Reference** · **Splunk Security Essentials** (detection mappate su MITRE ATT&CK)

---
---

# 19. APPENDICE OPZIONALE — SPL AVANZATA

> ⚠️ **Questa sezione NON è coperta dal corso BTL1 e non serve per il percorso principale.**
> I comandi in §11 (`stats`, `sort`, `table`, `dedup`, `spath`, `head`) + il click sui field bastano per l'esame, che chiede di **trovare risposte**, non di costruire detection rule di produzione.
>
> Usa questa sezione **solo se ti blocchi**: tipicamente quando un campo che ti serve **non esiste** (va creato o estratto con regex) o quando devi fare un calcolo.

### `where` — filtro dopo l'aggregazione
```splunk
| stats count by src_ip | where count > 100
| where src_ip != "10.0.0.1"
| where match(CommandLine, "(?i)invoke-expression|iex|downloadstring")
| where NOT cidrmatch("10.0.0.0/8", src_ip)
```
🧠 **`where` vs base search:** la base search filtra **prima** (usa l'indice, veloce); `where` filtra **dopo** — necessario per confronti su **campi calcolati o aggregati** (es. il `count` prodotto da `stats`).

### `eval` — creare campi calcolati
```splunk
| eval hour=strftime(_time, "%H")                        ← estrai l'ora (attività notturna?)
| eval size_mb=round(bytes/1024/1024, 2)
| eval len_cmd=len(CommandLine)                          ← command line anomalmente lunghe
| eval len_query=len(query) | where len_query > 50       ← DNS tunneling
| eval combined=src_ip.":".src_port                      ← concatenazione con "."
| eval sospetto=if(match(CommandLine,"(?i)-enc"), "SI", "NO")
```

### `rex` / `erex` — estrazione con regex da testo grezzo
```splunk
| rex field=CommandLine "-EncodedCommand\s+(?P<encoded>[A-Za-z0-9+/=]+)"
| rex field=url "https?://(?P<domain>[^/]+)"
| rex field=form_data "passwd=(?P<password>[^&]+)"
| erex CommandLine examples="powershell -enc ABC", "powershell.exe -EncodedCommand XYZ"
```
`(?P<nome>...)` = named capture group → crea il campo `nome`.
💡 **`erex` genera la regex dagli esempi** — usalo se non vuoi scrivere regex a mano.

### `timechart` / `chart` — serie temporali
```splunk
| timechart span=1h count by EventCode
| timechart span=5m sum(bytes) by dest_ip
| chart count over _time by EventCode
```
Utile per identificare **spike** o **regolarità** (beaconing C2 a intervalli fissi).

### `top` / `rare`
```splunk
| top limit=20 user              ← valori più frequenti
| rare limit=10 process_name     ← 🚩 i MENO frequenti = spesso i più interessanti
```

### `stats` avanzato
```splunk
| stats count(eval(EventCode=4625)) as fallimenti,
        count(eval(EventCode=4624)) as successi by Account_Name, IpAddress
| where fallimenti > 5 AND successi > 0
```
⭐ Questo è l'unico caso in cui la SPL avanzata vale davvero la pena: risponde in **una query** a *"il brute force ha avuto successo?"*.

```splunk
| stats earliest(_time) as primo, latest(_time) as ultimo by user
| stats avg(bytes) as media, max(bytes) as massimo by dest_ip
```

### Altri
```splunk
| rename Account_Name as user, IpAddress as src_ip
| fillnull value="N/A" user
| streamstats count as progressivo by user      ← conteggio progressivo
| transaction user maxspan=1h                    ← raggruppa eventi in "sessioni"
| lookup threat_ips.csv ip as src_ip OUTPUT threat_type
| fieldsummary                                   ← elenca i campi disponibili ⭐
```

### Subsearch
```splunk
index=<PROXY>
  [search index=* sourcetype=<WINSEC> EventCode=4625
   | stats count by src_ip | where count > 100 | fields src_ip]
| stats count by url, src_ip
```
La subsearch (tra `[ ]`) gira **prima**, genera una lista di valori che diventa filtro per la query esterna.
⚠️ **Lenta** su dataset grandi — usala con parsimonia.

---

*Fonti: materiale corso BTL1 (dominio SIEM, 4 lab Splunk) + cheat sheet pubbliche consolidate. Le sezioni e la §19 integrano contenuti non presenti nel corso: la §19 è marcata come opzionale perché non è richiesta dal percorso d'esame.*
