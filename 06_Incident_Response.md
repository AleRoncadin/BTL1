# BTL1 — Incident Response Cheat Sheet

> Esame: 24h, 20 task pratici, open-book, soglia 70%.
> Questo è il dominio più **ampio e trasversale**: collega tutti gli altri (DF, TI, SIEM, Phishing, Security Fundamentals) sotto un unico framework operativo (PICERL/NIST) e un unico framework di classificazione (MITRE ATT&CK).
> Tool pratici: **Wireshark** (PCAP), **CMD/PowerShell** (live triage), **DeepBlueCLI** (event log triage), **TheHive** (case management).

---

## 0. INDICE

| # | Sezione |
|---|---|
| 1 | Incident Response Lifecycle (NIST) e PICERL |
| 2 | CSIRT/CERT |
| 3 | Preparation — IRP, Team, Asset/Risk |
| 4 | Prevention — DMZ, Host, Network, Email, Physical, Human |
| 5 | Detection & Analysis — R2L/L2L, Baseline, Wireshark |
| 6 | **CMD/PowerShell per IR — reference comandi** |
| 7 | **DeepBlueCLI** |
| 8 | Case Management (TheHive) |
| 9 | Containment, Eradication, Recovery |
| 10 | Lessons Learned e Reporting |
| 11 | Metriche IR |
| 12 | **MITRE ATT&CK — le 12 tattiche complete** |
| 13 | Pitfall e confusioni comuni |
| 14 | Appendice: numeri, tabelle di riferimento |

---

## 1. INCIDENT RESPONSE LIFECYCLE

### NIST SP 800-61r2 — 4 fasi (ciclo continuo)
```
1. Preparation
2. Detection & Analysis
3. Containment, Eradication & Recovery
4. Post-Incident Activity (Lessons Learned)
        └──────────── torna alla Preparation ────────────┘
```

### PICERL — 6 fasi (usato dal corso per strutturare IRP e report)
```
1. Preparation
2. Identification
3. Containment
4. Eradication
5. Recovery
6. Lessons Learned
```
🧠 **Rapporto NIST↔PICERL:** stesso contenuto, granularità diversa. NIST accorpa Containment+Eradication+Recovery in una fase sola e chiama la prima fase "Detection & Analysis" invece di "Identification". **PICERL è più comodo per strutturare un report** — usalo come scheletro per i task che chiedono un documento finale.

### Preparation (dettaglio NIST)
**Essere pronti:** contact info stakeholder · **war room** · documentazione · **baseline** sistemi · equipaggiamento (digital forensic toolkit)
**Prevenire attivamente:** risk assessment aggiornati · sicurezza client/server · user awareness training

### Detection & Analysis (dettaglio NIST)
**Detection:** IDPS, AV/antispam, SIEM — il team deve sapere quali sistemi sono in campo
**Analysis:** come è avvenuto l'attacco e come si è mosso — facilitata da network baseline, knowledge base, log retention policy

**3 azioni del responder:** documentare · prioritizzare · **notificare** (via **Communication Plan** predefinito)

### Containment, Eradication & Recovery (dettaglio NIST)
⭐ **I 6 criteri NIST per la strategia di containment:**
```
1. Danno potenziale e furto di risorse
2. Necessità di preservare le prove
3. Disponibilità del servizio
4. Tempo e risorse necessarie
5. Efficacia
6. Durata della soluzione
```
**Eradication:** ricostruire da backup noti buoni · rimuovere malware · reset credenziali
**Recovery:** eliminare vulnerabilità sfruttate · patch · rafforzare rete

### Post-Incident Activity — domande guida NIST
```
Cosa è successo esattamente e quando?
Quanto bene hanno operato staff e management?
Quali info sarebbero servite prima?
Passi che hanno ostacolato il recovery?
Cosa fare diversamente?
Come migliorare l'info sharing con altre org?
Azioni correttive? Indicatori da monitorare? Risorse aggiuntive?
```
📌 Le risposte rientrano nella **Preparation** del ciclo successivo — chiude il cerchio.

---

## 2. CSIRT E CERT

**CERT** = Cyber Emergency Response Team · **CSIRT** = Cyber Security Incident Response Team

| Termine | Uso tipico |
|---|---|
| **CERT** | Team **nazionali/governativi** (AusCERT, CERT.br, CERTNZ, KrCERT, CERT-UK, **US-CERT**) |
| **CSIRT** | Team **interni aziendali** |

Sinonimi: **SIRT, IRT, CSIRC** — stessi obiettivi.

**6 funzioni:** command center centrale · security awareness training · contatto d'emergenza · investigano nuove minacce · determinano **MTTR/MDT** · condividono info con altri CSIRT/community

**Composizione:** infrastruttura, networking, **legale**, PR, sicurezza — multidisciplinare per il Communication Plan.

---

## 3. PREPARATION

### Incident Response Plan (IRP)
Documento che rende la risposta chiara/definita. **Va aggiornato costantemente**, training continuo.

**Identification** (dettaglio PICERL) — info da raccogliere:
```
Quando? Chi l'ha scoperto? Come? Quali sistemi/BU colpiti?
Impatta l'operatività? Scope (n. sistemi, entry point, danno)?
```
⭐ **2 valori di prioritizzazione:**
| Valore | Domanda |
|---|---|
| **Criticality level** | Quanto veloce deve essere la risposta? |
| **Impact level** | Per quanto tempo impatterà le operazioni? |

**Containment** (dettaglio PICERL) — ⚠️ **tensione critica**: spegnere un sistema = perdere prove volatili in RAM (→ *Order of Volatility*, Digital Forensics).

**Eradication** (dettaglio PICERL) — usa **Kill Chain/ATT&CK** per lavorare a ritroso · packet capture · log SIEM → root cause. Rimuove malware + **tutti** i meccanismi di persistenza. Alimenta NIPS/HIPS con gli IOC raccolti.

### Incident Response Teams
| Ruolo tecnico | Responsabilità |
|---|---|
| **Incident Commander** | Coordina, comunica, punto di contatto, update a management/C-suite |
| **Security Analyst** | Triage/investigazione alert IDPS/SIEM |
| **Forensic Analyst** | Acquisizione/preservazione prove per uso legale (DFIR) |
| **TI Analyst** | Attribuzione attore, exposure check con IOC, condivisione con altre org |

| Ruolo non tecnico | Perché serve |
|---|---|
| **Management/C-Suite** (CISO/COO/CTO) | Risorse per prevenire/rispondere |
| **HR** | Se causa = dipendente → azione disciplinare |
| **PR** | Obbligo di legge se colpisce pubblico/clienti (data breach) |
| **Legal** | Consulenza + garantisce prove forensicamente valide |

### Asset Inventory e Risk Assessment
**Asset Inventory (CMDB):** lista centralizzata di tutti gli asset IT (desktop, server, IoT, network device, mobile).
**3 usi per la sicurezza:** trovare OS obsoleti senza vuln scanner · da IP→owner durante un incidente · capire cosa fa/contiene un sistema sospetto

**Risk Assessment:** identifica sistemi critici, protezione **proporzionale** al rischio.
**Le 4 strategie:** **Transfer** (assicurazione) · **Accept** (costo gestione > impatto) · **Mitigate** (controlli) · **Avoid** (offline)

---

## 4. PREVENTION

### DMZ
Sottorete che separa LAN interna da reti non fidate. Contiene: **web server, proxy, email, DNS, FTP, VoIP**.

| Architettura | Come |
|---|---|
| **Single Firewall** ("three-legged") | 1 firewall, 3 interfacce (esterna/interna/DMZ). Singolo punto di fallimento |
| **Dual Firewall** ⭐ più sicuro | **Frontend** (solo verso DMZ) + **Backend** (DMZ→interna). Vendor diversi = meno vulnerabilità condivise |

**3 benefici:** access control (+ proxy per audit) · anti-reconnaissance (anche se la DMZ cade, la LAN resta protetta) · anti-IP-spoofing

### Host Defenses
| Controllo | Azione | Limite |
|---|---|---|
| **HIDS** | Solo alert | — |
| **HIPS** | Alert + azione (blocco, cancellazione) | — |
| **AV Signature-based** | Rimuove malware noto | Non rileva varianti sconosciute |
| **AV Behavior-based** | Baseline + anomalie | Più efficace su minacce nuove |
| **EDR** | Log+monitor+response, insider threat monitoring | — |
| **Local Firewall** | Regole per-host su porte/connessioni | — |

**GPO — ordine LSDOU:** Local → Site → Domain → OU (vince l'ultima, la più specifica). Refresh: **90-120 min** o reboot (0 min = ogni 7 sec, satura la rete). **Enforce** vince sempre indipendentemente dalla gerarchia.

### Network Defenses
**NIDS positioning:** Inline (= NIPS de facto, fail = blocca tutto) · Network Tap · Passive (SPAN port)
**Tool:** Snort (leader, community) · Suricata (layer applicativo) · Zeek/Bro (monitoring + IDS/IPS)

**Firewall:** Traditional (IP/porta, es. pfSense) · **NGFW** (multi-layer OSI, per-app) · **WAF** (proxy, protegge un'app specifica)

**NAC:** Pre-admission (compliance check: patch, AV) · Post-admission (**RBAC**, restrizioni continue)

**Web Proxy:** blocco preventivo di URL malevoli osservati in phishing → il click non ha effetto.

### Email Defenses
**SPF** (DNS TXT, 3 parti: dichiarazione+IP autorizzati+enforcement) · **DKIM** (hash privato→pubblico, verifica integrità) · **DMARC** (none/quarantine/reject)

**Marking external email:** prefisso subject `[EXTERNAL]` (rischia illeggibilità) vs banner colorato nel body (preferito)

**Spam filter:** Gateway (Barracuda) · Hosted (SpamTitan) · Desktop (freeware, rischioso)

**DLP:** keyword matching (`confidential`, `proprietary`) · **Sandboxing:** detona l'allegato in VM, osserva comportamento
**Estensioni malevole comuni:** `.exe .vbs .js .iso .bat .ps/.ps1 .htm/.html`

### Physical Defenses
| Categoria | Esempi |
|---|---|
| **Deterrent** | Warning signs, fences+filo spinato, guard dogs, security guards, lighting |
| **Access Control** | Mantrap (2 porte+ispezione), turnstile/badge, electronic door (per ruolo), guards |
| **Monitoring** | CCTV, guards addestrati, IDS fisico (termico/sonoro/movimento) |

### Human Defenses
**Training:** onboarding obbligatorio, **annuale**. **AUP:** regole + conseguenze esplicite.
**Security Champions:** incentivi non monetari (riconoscimento).
**Phishing simulation:** **trimestrale** (3-4 mesi), metriche su segnalati/click/repeat offender, C-suite testato periodicamente.
**Whistleblowing:** canale anonimo → contro insider threat.

---

## 5. DETECTION & ANALYSIS

### Terminologia R2L/L2R/L2L
**R2L** (Remote→Local) · **L2R** (Local→Remote) · **L2L** (Local→Local)

| Evento | Detection | Impatto |
|---|---|---|
| **R2L Port Scanning** | Firewall/WAF: molte connessioni, porte non-standard (≠80/443) | Raro immediato; può causare DoS involontario su sistemi vecchi |
| **R2L DoS/DDoS** | Baseline traffico DMZ + threshold | Offline → reputazione, vendite. **Caso Dyn 2016** (DNS provider → Amazon/BBC/PayPal/Reddit/Twitter offline) |
| **L2L Scanning** | IP privato→molti IP interni rapidi. ⚠️ Whitelist vuln scanner interni | Segnale di **lateral movement** post-persistenza (ARP/UDP/TCP/ICMP scan) |
| **Login Failures** | Event ID **4625** + failure code. Threshold=brute force; 2-3 fail su molti utenti=**password spraying** | 0xC0000064/0xC0000234 ripetuti = possibile compromissione |

### Baselining e Anomaly Detection
**Baseline** = "normale" registrato (traffico, orari, porte...). **Anomaly-based** = confronto con lo stato attuale.

| | Signature-based | Anomaly-based |
|---|---|---|
| Rileva | Solo malware noto | Comportamenti nuovi |
| Efficace su | Minacce note | **DoS/DDoS**, traffico **cifrato** |
| Contro | Varianti non rilevate | **Molti FP**, baselining lento, va rifatto periodicamente |

**Tool:** Cisco Stealthwatch, IBM QRadar, **Flowmon ADS**

### Wireshark
**Capture filter** (durante) vs **Display filter** (dopo, su dati già catturati) — non confonderli.

```
udp                                              # presenza protocollo
http.request
tcp.port == 80
ip.dst_host == 192.168.1.7 && tcp                # AND: && o and
ntp or udp.port == 20000                         # OR: || o or
not ftp                                          # NOT: ! o not
```

**Follow Stream:** right-click → Follow → TCP/UDP/SSL/HTTP Stream (rosso=request, blu=response)
**Custom column:** right-click su un campo → Apply as Column

**3 finestre statistiche:**
| Finestra | Uso |
|---|---|
| **Protocol Hierarchy** | % per protocollo/layer. 🚩 Protocollo raro e insolito = possibile exfiltration |
| **Conversations** | Chi↔chi, byte/pacchetti. 🚩 Molto inviato, poco ricevuto = possibile exfil |
| **Endpoints** | Volume per host. Riceve>>trasmette = download; Trasmette>>riceve = upload/backup (🚩 exfil) |

`Apply as Filter → Selected/Not Selected` in tutte e 3.

**Promiscuous mode** = cattura anche traffico non indirizzato all'host (visione più ampia).

---

## 6. CMD/POWERSHELL PER IR

> ⚠️ Eseguire sempre come **Amministratore**.

### CMD
```cmd
ipconfig /all                                   :: IP, MAC, hostname, DNS
tasklist                                        :: processi + PID + RAM (trova crypto miner)
wmic process get description, executablepath    :: processo + PATH REALE (trova masquerading)
net user                                        :: tutti gli utenti
net localgroup administrators                   :: chi è admin
net localgroup "Remote Desktop Users"            :: gruppi con spazi → tra virgolette
net localgroup                                  :: lista di tutti i gruppi
sc query | more                                 :: servizi + dettagli
netstat -ab                                     :: porte aperte → backdoor
```

### PowerShell
```powershell
Get-NetIPConfiguration
Get-NetIPAddress                                          # equivalenti ipconfig

Get-LocalUser
Get-LocalUser -Name BTLO | select *                       # tutte le proprietà di un utente

Get-Service | Where Status -eq "Running" | Out-GridView    # servizi attivi, finestra grafica

Get-Process | Format-Table -View priority
Get-Process -Id 'idhere' | Select *
Get-Process -Name 'nomehere' | Select *

Get-ScheduledTask                                          # persistenza
Get-ScheduledTask -TaskName 'nome' | Select *
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"}
Get-ScheduledTask | Where-Object {$_.TaskName -like "Pe*"}
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled" -and $_.TaskName -like "Pe*"}

Set-ExecutionPolicy Bypass -Scope CurrentUser              # sblocca script non firmati
```
⭐ Pattern ricorrente: **`| select *` / `| Select *`** dopo un comando specifico → tutte le proprietà disponibili invece della vista sintetica.
⭐ **`Where-Object`** (alias `?`): `-ne` (diverso da), `-eq` (uguale), `-like` (wildcard `*`), `-and`/`-or` per combinare condizioni.

---

## 7. DEEPBLUECLI

Script **PowerShell** di **SANS** per triage automatico dei Windows Event Log (`.evtx` esportati o log **live**).

**Rileva:** creazione utenti/gruppi, password guessing/spraying, **Bloodhound**, comandi obfuscated, PowerShell download remoto, servizi sospetti, **Mimikatz→LSASS dump**, e altro.

```powershell
cd Downloads\DeepBlue
Set-ExecutionPolicy Bypass -Scope CurrentUser    # se blocca per firma mancante

./DeepBlue.ps1 ../Log1.evtx                      # analizza un file specifico
./DeepBlue.ps1 -log security                     # log locali live
./DeepBlue.ps1 -log system

./DeepBlue.ps1 .\folder\* > output.txt           # tutti gli evtx di una cartella, output su file
```

**Output tipico (password spray):** account bersagliati, conteggio, username attaccante, hostname, Event ID correlato.

---

## 8. CASE MANAGEMENT

**Scopo:** registrare investigazioni, compliance, correlazione tra casi, collaborazione.
**Tool industria:** ServiceNow · IBM Resilient · Jira Service Management · **TheHive** (open source)

### TheHive — SIRP (Security Incident Response Platform)
**7 funzionalità:**
```
1. Case Management → task + observable (IOC) + alert correlati
2. Collaboration → multi-utente real-time
3. Observable Analysis → arricchimento con TI
4. Alert Management → triage auto/manuale, alert→case
5. Integrazione → MISP (enrichment automatico)
6. Template personalizzabili → standardizza il processo
7. API RESTful → SOAR (Security Orchestration, Automation, and Response)
```
💡 **Observable** = il termine TheHive per IOC (IP, domini, hash).
💡 **SOAR** esempio: bloccare automaticamente un IP malevolo sul firewall via API.

---

## 9. CONTAINMENT, ERADICATION, RECOVERY

### Containment = strategia (non solo step)
| | Short-Term | Long-Term |
|---|---|---|
| Obiettivo | Break-fix immediato | Fix enterprise, causa già nota |
| Esempio | Disabilitare account AD, isolare device, bloccare IP C2, WAF | Segmentazione rete, patching, nuovi tool, review Least Privilege |
| Limite | Non risolve la causa, può ripetersi altrove | — |

### Le 3 misure di containment
| Livello | Azioni |
|---|---|
| **Perimeter** | Blocco in/out · IDS/IPS filter · WAF · **Null route DNS** |
| **Network** | VLAN isolation · segment isolation (router) · port blocking · IP/MAC block · **ACL** |
| **Endpoint** | Disconnessione fisica · ⚠️ **spegnimento** (perdita RAM volatile!) · firewall locale · HIPS |

**Verifica efficacia:** regola SIEM dedicata (es. alert se il sistema "contenuto" genera traffico esterno → containment fallito, escalation immediata).

### Forensic Imaging in IR (ripasso applicato)
```
KAPE (RAM volatile) → write blocker hardware → FTK Imager (bit-by-bit) →
hash match → originale in secure storage, si lavora su copia
```
**Virtual desktop (Citrix):** snapshot → montato su VM forense (**SIFT**) → imaging dello snapshot.

### Identifying and Removing Malicious Artifacts
**Tool identificazione (Sysinternals):** **Process Explorer** (masquerading) · **netstat+Process Monitor** (C2/diffusione) · **Rootkit Revealer**

**5 metodi di rimozione:**
```
1. Reimaging da backup → completo ma perde dati post-backup
2. AV/NGAV (NGAV = ML/AI, rileva fileless) → limitato se non l'ha rilevato prima
3. Bootable tools → McAfee Stinger, Microsoft MSRT, Avira Rescue System
4. Rimozione file malevoli (tool offensivi, campioni)
5. Rimozione persistenza (registry key, scheduled task, cron job)
```

### Root Cause e Recovery
Uso di **Kill Chain/ATT&CK** per lavorare a ritroso. ⚠️ Root cause sbagliata/affrettata = re-infezione.

**4 azioni di Recovery:**
```
1. Patching (+ TEST MANUALE post-patch)
2. Disabilitare servizi non necessari
3. Aggiornare regole EDR/AV/IDPS/SIEM
4. Condividere IOC con altre organizzazioni
```

---

## 10. LESSONS LEARNED E REPORTING

### What Went Well / What Could be Improved
**Went Well:** apprezzare il team (previene imposter syndrome/burnout). Domande: chi ha performato bene? nuovi tool utili? metriche? comunicazione tra reparti?

**Could be Improved:** limitazioni tooling/procedure/persone, debolezza per fase NIST. ⚠️ **Identificare senza agire è inutile** → richiesta concreta di budget (personale sicurezza, altri reparti, tool, documentazione).

### Documentazione da aggiornare (4 tipi)
```
1. Case Notes (ServiceNow/IBM Resilient/TheHive) — tutte le fasi, artefatti, allegati
2. IRP — stakeholder, comunicazione sicura, contatti
3. Run-books — più dettaglio = meglio, copre più scenari
4. Policy — es. AUP che non vietava il download software = root cause
```

### Metriche IR
| Categoria | Metrica | Definizione |
|---|---|---|
| **Impact** | SLA | Accordo uptime/responsività (99%, 99.9%) |
| | SLO | Metrica specifica DENTRO l'SLA |
| | Escalation Rate | Alert assegnato all'analista giusto (junior non gestisce ransomware da solo) |
| **Time-based** | MTTD = MTTA | Tempo medio per **accorgersi** |
| | **MTTR** | Tempo da detection ad azione — ⭐ la più importante |
| | Incidents Over Time | Trend nel tempo |
| | Remediation Time | Tempo per ripristino completo |
| **Incident Type** | Cumulative per Type | Dove servono miglioramenti (es. molti da vuln internet-facing) |
| | Alerts per Incident | Quali fonti hanno/non hanno alertato → gap nella Kill Chain |
| | CPI (Cost per Incident) | Durata×costo team, o impatto business. Meglio con **BIA** già fatta |

### Reporting Format — 4 sezioni ⭐
```
1. Executive Summary — 1 pagina, no tech, business risk/costi/danno prevenuto
2. Incident Timeline — cronologica, timezone locale (1 sito) o UTC (multi-sito)
3. Incident Investigation — copre TUTTE le fasi TRANNE Preparation:
   - Detection & Analysis (come scoperto, triage, screenshot)
   - Containment/Eradication/Recovery (scoping, rimozione attore, root cause)
   - Post-Incident (cosa migliorare — anche in Exec Summary se rilevante)
4. Appendix — contenuti voluminosi (liste IP, tabelle)
```

### Reporting Considerations
**Audience:** Exec Summary = no jargon, business terms · Resto = tecnico, screenshot annotati
⭐ **"Make a Point > Provide Evidence"** — ogni affermazione supportata da prova (screenshot email, macro, log SIEM)
📌 Includere le **tattiche MITRE ATT&CK** usate nell'incidente
**Screenshot sempre con didascalia** (1-2 frasi)

---

## 12. MITRE ATT&CK — LE 12 TATTICHE

> Ogni tecnica ha sempre: **Description → Mitigations → Detection**. Tattiche = `TA00xx`, Tecniche = `Txxxx` — non confonderli.

### TA0001 — Initial Access (9 tecniche)
```
Drive-by Compromise · Exploit Public-Facing App · External Remote Services (T1133)
Hardware Additions · Phishing (T1566) · Replication Through Removable Media (T1091)
Supply Chain Compromise · Trusted Relationship · Valid Accounts (T1078)
```
- **T1566 Phishing** → mitigazioni = SPF/DKIM/DMARC/sandboxing/training (già visti)
- **T1133 External Remote Services** → spesso combinato con T1078; brute-force raro (rumoroso). Mitigazione: disable se non serve + 2FA. Detection: RDP a orari anomali
- **T1091 Removable Media** → air-gapped bypass. Mitigazione: disable AutoRun, policy, port blocker

### TA0002 — Execution (10 tecniche)
```
Windows Management Instrumentation (T1047) · User Execution (T1204, 2 sotto-tecniche)
```
- **T1047 WMI** → SMB+RPCS. Mitigazione: least privilege + restrizione uso. **Sysmon detection: ID 19 (WmiEventFilter), 20 (WmiEventConsumer), 21 (WmiEventConsumerToFilter)**
- **T1204 User Execution** → legato a Phishing. Mitigazioni: application whitelisting, NIPS, awareness training. 🚩 Winword.exe→CMD.exe = macro malevola

### TA0003 — Persistence (18 tecniche)
```
Boot or Logon Autostart Execution (T1547) · External Remote Services (T1133)
```
- **T1547** → run key/startup folder. APT18/19/29. Difficile da mitigare (legittimo per design). **Sysinternals Autoruns** per detection
- **T1133 (qui)** → credenziali valide + servizi remoti = persistenza stealth (traffico non anomalo). APT18/41, Dragonfly 2.0, FIN5

### TA0004 — Privilege Escalation (12 tecniche)
```
Valid Accounts (T1078, 4 sotto-tecniche) · Exploitation for Privilege Escalation (T1068)
```
- **T1078** → credential harvester + IoT default creds (APT28). Mitigazioni: no hardcoded creds, cambiare default, audit permessi
- **T1068** → kernel exploit → SYSTEM/ROOT. **CVE-2017-0263 (APT28)**, **CVE-2016-7255 (APT32)** — entrambe kernel-mode driver Windows. Mitigazioni: patching, TI su CVE sfruttate, **Exploit Guard**

### TA0005 — Defense Evasion (⭐ 38 tecniche — la più ampia)
```
Impair Defenses (T1562, 6 sotto-tecniche) · Indicator Removal on Host (T1070)
```
- **T1562**: Disable/Modify Tools · Disable Windows Event Logging · **HISTCONTROL** (no log bash history) · Disable/Modify Firewall (system/cloud) · Indicator Blocking
- **T1070**: cancella bash history/file/log raw (serve SYSTEM/SUDO) · **Timestomping**. Malware: **Goopy** (C2 via email, poi cancella) · **PoetRAT** (self-delete in sandbox). Mitigazione: nascondere log, forward rapido a SIEM

### TA0006 — Credential Access (14 tecniche)
```
OS Credential Dumping (T1003, 8 sotto-tecniche) · Brute Force (T1110)
```
- **T1003.1 LSASS Memory** → Mimikatz (APT28, APT39), GetPassword_x64 (APT32)
- **T1003.8 /etc/passwd+/etc/shadow** → John The Ripper (non in esame)
- Mitigazioni: password uniche per sistema, **PAM**, training
- **T1110 Brute Force**: dictionary/exhaustive, o crack hash offline (**Hashcat**). **Ncrack** (APT39, stesso team di Nmap), Chaos (SSH), DarkVishnya
- Mitigazioni: account lockout, MFA, NIST password guidelines, TI su data breach
- Detection: **Event ID 4625** + error code

### TA0007 — Discovery (24 tecniche)
```
Account Discovery (T1087, 4 sotto-tecniche) · Network Service Scanning (T1046)
File and Directory Discovery (T1083)
```
- **T1087**: Local (`net user`, `net localgroup`, `/etc/passwd`) · Domain (`net user /domain`, `ldapsearch`) · Email (**Emotet** scrape) · Cloud (console AWS/Azure cached creds)
- **T1046**: port/service scan → mitigazione: spegnere servizi, NIDS/NIPS, segmentazione
- **T1083**: `cd`, `dir`, `find` — ⚠️ **nessuna mitigazione possibile** (attività normale)

### TA0008 — Lateral Movement (9 tecniche)
```
Remote Services (T1021, 6 sotto-tecniche) · Internal Spearphishing (T1534)
```
- **T1021**: RDP, SMB/Admin Shares, **DCOM**, SSH, VNC, WinRM. Riuso password IT admin = efficace+stealth. Detection: **"Timeline, timeline, timeline"**
- **T1534**: da mailbox compromessa, più efficace del phishing esterno (indirizzo legittimo, reply su thread reali). **Gamaredon Group** (modulo VBA custom)

### TA0009 — Collection (16 tecniche)
```
Email Collection (T1114, 3 sotto-tecniche) · Audio Capture (T1123)
Screen Capture (T1113) · Data From Local System (T1005)
```
- **T1114**: Local (Outlook cache path) · Remote (Exchange/O365) · **Forwarding Rule** (persiste anche senza accesso rete)
- **T1123**: APT37/**SOUNDWAVE**, Bandook, Cobian RAT, Attor, Cadelspy — non mitigabile
- **T1113**: **Agent Tesla**, APT28/39, Aria-body — non mitigabile, serve correlazione
- **T1005**: `find`/`tree`/`dir`. APT28+**Forfiles**, GravityRAT, Inception

### TA0011 — Command and Control (16 tecniche)
```
Application Layer Protocol (T1071) · Web Service (T1102) · Non-Standard Port (T1571)
```
- **T1071**: Cobalt Strike/Dragonfly 2.0 (SMB), Duqu. Detection: Zeek **x509.log** (certificati blacklist)
- **T1102**: FIN6 (Pastebin), Gamaredon (GitHub), Inception (multi-cloud resiliente)
- **T1571**: APT33 (HTTP su 808/880), BADCALL (443/8000 FakeTLS)
- Mitigazione comune: **NIDS/NIPS**, segmentazione, restrizione porte outbound

### TA0010 — Exfiltration (9 tecniche)
```
Exfiltration Over C2 Channel (T1041) · Scheduled Transfer (T1029)
```
- **T1041**: dentro i beacon C2. Detection: magic bytes NIDS, **jitter** analysis sul beaconing
- **T1029**: ADVSTORESHELL (ogni 10 min), Cobalt Strike (random interval + chunking), ComRAT/Dipsind (**solo orario 9-5** — pattern opposto!)

### TA0040 — Impact (13 tecniche)
```
Account Access Removal (T1531) · Defacement (T1491, 2 sotto-tecniche)
Data Encrypted for Impact (T1486)
```
- **T1531**: delete/lock account, change password. **LockerGoga** (ransomware+account removal combinati). Rumorosa → tipicamente ultima azione
- **T1491**: hacktivismo/intimidazione/rivendicazione. Mitigazione: backup (protetto!) · WAF + monitor modifiche file
- **T1486**: Ransomware. **WannaCry** (SMB wormable), Ryuk, Shamoon. Detection: `vssadmin`/`wbadmin`/`bcdedit`

---

## 13. PITFALL E CONFUSIONI COMUNI

| Confusione | Distinzione |
|---|---|
| **NIST (4 fasi) vs PICERL (6 fasi)** | Stesso contenuto, granularità diversa — PICERL più comodo per i report |
| **CERT vs CSIRT** | Nazionale/governativo vs interno aziendale |
| **Criticality level vs Impact level** | Velocità richiesta vs durata dell'impatto |
| **Short-term vs Long-term containment** | Quick fix immediato vs fix strutturale che previene la ricorrenza |
| **HIDS vs HIPS** | Solo alert vs alert+azione |
| **NIDS vs NIPS** | Rileva vs rileva+agisce (inline NIDS = NIPS de facto) |
| **MTTD/MTTA vs MTTR** | Tempo per accorgersi vs tempo per rispondere |
| **Capture filter vs Display filter (Wireshark)** | Cosa catturare (prima) vs cosa mostrare (dopo) |
| **Tattica (TA00xx) vs Tecnica (Txxxx)** | Categoria vs azione specifica dentro la categoria |
| **T1133 in Initial Access vs Persistence** | Stessa tecnica, scopo diverso (ottenere vs mantenere accesso) |
| **T1078 in Initial Access / Persistence / Priv Esc** | Stessa tecnica applicata a 3 fasi diverse dell'attacco |
| **Signature-based vs Anomaly-based detection** | Malware noto (hash) vs deviazione da baseline |
| **SLA vs SLO** | Accordo generale vs metrica specifica misurata dentro l'SLA |
| **Orario anomalo (maggior parte ATT&CK) vs orario "normale" (Scheduled Transfer)** | La maggior parte delle tecniche C2/exfil sono sospette fuori orario; ComRAT/Dipsind fanno l'opposto — si mimetizzano restando IN orario |

---

## 14. APPENDICE

### Numeri chiave
| Valore | Cosa |
|---|---|
| **NIST SP 800-61r2** | Standard IR di riferimento |
| **4 fasi NIST / 6 fasi PICERL** | I due modelli del ciclo IR |
| **6 criteri NIST** | Scelta strategia di containment |
| **99% / 99.9%** | SLA tipici |
| **Trimestrale (3-4 mesi)** | Cadenza phishing simulation |
| **Annuale** | Cadenza security awareness training |
| **38** | Tecniche Defense Evasion (la tattica più ampia) |
| **24** | Tecniche Discovery |
| **18** | Tecniche Persistence |
| **16** | Tecniche Collection / Command and Control |
| **14** | Tecniche Credential Access |
| **13** | Tecniche Impact |
| **12** | Tecniche Privilege Escalation |
| **10** | Tecniche Execution |
| **9** | Tecniche Initial Access / Lateral Movement / Exfiltration |

### Event ID rilevanti in IR (ripasso trasversale)
| ID | Contesto |
|---|---|
| **4625** | Login fallito — brute force, password spray, dictionary attack |
| **4624/4672** | Login riuscito / special logon |
| **1102/104** | Log cancellati — Defense Evasion (T1070) |
| **19/20/21 (Sysmon)** | WMI abuse (T1047) |

### Comandi da ricordare a memoria
```
wmic process get description, executablepath     → trova masquerading
Get-ScheduledTask | Where-Object {...}            → filtra persistenza
Set-ExecutionPolicy Bypass -Scope CurrentUser     → sblocca script PS
./DeepBlue.ps1 -log security                      → triage log live
```

### Workflow generale da portarsi in esame
```
1. Ricevi lo scenario → identifica la fase IR in cui ti trovi
2. Detection & Analysis: Wireshark (PCAP) / CMD-PowerShell (live) / DeepBlueCLI (evtx) / SIEM (§ cheat sheet SIEM)
3. Mappa quello che trovi su ATT&CK: quale tattica? quale tecnica specifica?
4. Se serve un report: PICERL come scheletro, Make a Point > Provide Evidence, screenshot+caption
5. Se serve una risposta su containment/mitigazione: guarda la tabella §12 per quella tecnica specifica
```

---

*Fonti: materiale corso BTL1 (dominio Incident Response completo, incl. le 12 tattiche MITRE ATT&CK) + cheat sheet pubbliche consolidate.*
