# BTL1 — LAB CHEAT SHEET (solo pratica)

> Nessuna teoria. Solo ciò che **digiti, clicchi o consulti** durante un task.
> ⚠️ **Nel lab d'esame non c'è internet, tranne Splunk.** OSINT (VirusTotal, WHOIS, CVE) dal **tuo** browser.

---

## 🧭 ROUTING — "Cosa ho in mano?"

| Ho... | Vai a | Tool |
|---|---|---|
| `.pcap` / `.pcapng` / `.cap` | §2 | Wireshark |
| `.mem` / `.dmp` / `.raw` (memoria) | §3 | Volatility |
| `.E01` / `.img` / `.dd` (disco) | §4 | Autopsy · Scalpel · FTK Imager |
| `.pf` (Prefetch) | §5 | PECmd |
| `$I*` / `$R*` (Recycle Bin) | §5 | RBCmd |
| `.lnk` (shortcut) | §5 | Windows File Analyzer |
| Jump List (`AutomaticDestinations` / `CustomDestinations`) | §5 | JumpList Explorer |
| `SYSTEM` / `SAM` / `SOFTWARE` / `NTUSER.DAT` / `Amcache.hve` (registry hive) | §3, §5 | Volatility `hivelist` · Registry Explorer |
| `.evtx` (event log) | §5 | DeepBlueCLI · Event Viewer |
| Sistema Windows **live** | §6 | CMD / PowerShell |
| Sistema Linux **live** o immagine | §7 | comandi Linux |
| Log dentro Splunk | §1 | SPL |
| `.eml` / email | §8 | CyberChef · tool online |
| Un file qualsiasi (hash/metadati) | §9 | Get-FileHash · exiftool |
| Sospetta steganografia (immagine "pesante"/anomala) | §9 | steghide · StegCracker |
| CSV prodotto da un altro tool (PECmd/RBCmd) | §5 | CSVQuickViewer |
| Un IOC da arricchire | §10 | MISP · OSINT |
| Un **incidente reale** da gestire (phishing, malware, ransomware...) | §13 | Runbook |

---

## 🛠️ TOOL REFERENCE — "A cosa serve ognuno?"

| Tool | A cosa serve | Quando lo usi |
|---|---|---|
| **Splunk (SPL)** | Interrogare log centralizzati (Sysmon, Windows Security, firewall, IDS, web) | Hai accesso a un indice con eventi già ingeriti |
| **Wireshark** | Ispezionare traffico di rete pacchetto per pacchetto | Hai un `.pcap`/`.pcapng` da un dump di rete |
| **Volatility 2/3** | Analisi forense della RAM (processi, connessioni, injection) | Hai un dump di memoria `.mem`/`.raw`/`.dmp` |
| **Autopsy** | Analisi forense completa di un'immagine disco (GUI) | Hai un `.E01`/`.img` e vuoi esplorare filesystem, email, cronologia, ecc. |
| **Scalpel** | File carving: recupera file cancellati/frammentati da un'immagine raw | Devi ricostruire file da un `.img`/`.dd` senza filesystem intatto |
| **FTK Imager** | Acquisizione forense (RAM/disco) e visualizzazione rapida di immagini | Devi creare un `.mem`/`.E01` o aprire/ispezionare un'immagine già fatta |
| **PECmd** | Parsing dei file Prefetch (`.pf`): quante volte un eseguibile è girato, quando, da dove | Devi provare l'esecuzione di un programma su un host Windows |
| **RBCmd** | Parsing del Recycle Bin (`$I`/`$R`): nome originale, path, size, data cancellazione | Devi recuperare metadati di file cancellati |
| **Windows File Analyzer** | Parsing dei file `.lnk` (shortcut) | Devi sapere quale file/percorso apriva uno shortcut e quando |
| **JumpList Explorer** | Parsing delle Jump List (file recenti per applicazione) | Devi ricostruire quali file sono stati aperti con quale programma |
| **CSVQuickViewer** | Visualizzare comodamente output CSV di altri tool (PECmd, RBCmd, ecc.) | Hai generato un CSV e vuoi filtrare/ordinare senza Excel |
| **DeepBlueCLI** | Triage automatico di `.evtx`: rileva pattern sospetti (spraying, Mimikatz, PowerShell offuscato) | Vuoi una prima scrematura veloce di un event log, senza cercare a mano |
| **Event Viewer** | Consultazione manuale/GUI dei log di Windows | Il sistema non è nel SIEM o devi creare una Custom View su Event ID specifici |
| **CMD / PowerShell** | Triage live di un sistema Windows (processi, rete, utenti, servizi) | Hai accesso interattivo a una macchina Windows da analizzare |
| **Sysmon** | Logging avanzato di processi/rete/registro su Windows (sorgente per Splunk/Event Viewer) | Devi installare/configurare la sorgente di log prima di poterla interrogare |
| **Comandi Linux (bash)** | Triage live o su immagine di un sistema Linux (utenti, auth, cron, rete) | Hai accesso a shell Linux o file estratti da un'immagine Linux |
| **CyberChef** | "Coltellino svizzero": decodifica (Base64 ecc.), defanging IOC, trasformazioni dati | Devi decodificare un body email o defangare IOC per un report |
| **WannaBrowser** | Risolve una catena di redirect di un URL abbreviato senza visitarlo | Hai un link sospetto abbreviato (bit.ly ecc.) in una phishing mail |
| **URL2PNG / URLScan.io** | Screenshot di una pagina web senza visitarla direttamente | Devi vedere cosa mostra un URL sospetto senza rischiare il click |
| **VirusTotal** | Reputazione di file (hash), URL, domini, IP | Hai un IOC (hash/URL/IP/dominio) e vuoi sapere se è già noto come malevolo |
| **AbuseIPDB** | Reputazione/segnalazioni storiche di un IP | Vuoi sapere se un IP è già stato segnalato per abuso |
| **Cisco Talos** | Reputazione file e IP/domini (alternativa/conferma a VT) | Vuoi una seconda fonte di reputazione |
| **Hybrid Analysis / Any.run / Joe Sandbox** | Sandbox: esecuzione controllata di un file/URL sospetto | Devi vedere il comportamento reale (processi, rete, IOC generati) di un allegato |
| **WHOIS / MxToolbox** | Info di registrazione dominio (età, registrar, contatti) | Devi valutare se un dominio è appena registrato (sospetto) |
| **Get-FileHash / sha256sum / md5sum** | Calcolo hash di file o stringhe | Devi identificare/confrontare un file per IOC o integrità |
| **exiftool** | Lettura/scrittura metadati di file (immagini, documenti) | Devi estrarre autore, GPS, software, data creazione di un file |
| **steghide / StegCracker** | Nascondere/estrarre/rilevare dati steganografati in immagini | Sospetti dati nascosti in un'immagine (file "pesante" o indicato dal task) |
| **KAPE** | Triage rapido: raccoglie in blocco artefatti forensi mirati (browser, prefetch, ecc.) | Devi acquisire velocemente molti artefatti da un host live senza immagine completa |
| **Procdump** | Dump della memoria di un singolo processo live | Devi analizzare un processo sospetto senza dumpare tutta la RAM |
| **dd** | Acquisizione bit-a-bit di un disco (Linux) | Devi creare un'immagine forense di un disco su sistema Linux |
| **MISP** | Piattaforma di Threat Intelligence: gestione e condivisione IOC | Devi inserire/arricchire/pivotare su IOC in modo strutturato |
| **Autoruns (autorunsc)** 🏢 | Elenca tutti i punti di persistenza (Run keys, servizi, task, driver) con hash e firma | Triage live di un host sospetto |
| **WinPmem / LiME** 🏢 | Dump RAM da riga di comando (Windows / Linux) | Alternativa a FTK Imager, o su Linux |
| **EZ Tools (AmcacheParser, EvtxECmd, MFTECmd)** | Parsing di Amcache, event log e $MFT in CSV | Analisi artefatti in blocco dopo KAPE |
| **Timeline Explorer** | Visualizzare/filtrare i CSV degli EZ Tools | Costruire la timeline dell'incidente |
| **emldump.py** | Elenca ed estrae le parti MIME di un `.eml` (allegati) | Estrarre l'allegato da una phishing mail |
| **oletools (oleid, olevba)** 🏢 | Analisi di documenti Office: macro VBA, IOC embedded | Allegato `.doc/.docm/.xls` sospetto |
| **pdfid.py** 🏢 | Rileva elementi pericolosi in un PDF (`/JavaScript`, `/OpenAction`) | Allegato PDF sospetto |
| **ID Ransomware / No More Ransom** 🏢 | Identifica la famiglia ransomware / trova decryptor gratuiti | Incidente ransomware |

---

## 1. SPLUNK (SPL)

### Avvio + primi 60 secondi
```bash
sudo systemctl start Splunkd
# Firefox → http://127.0.0.1:8000 → app "Search and Reporting"
```
**Checklist obbligatoria** (l'80% dei "0 eventi" viene da qui):
- [ ] Time picker → **All Time** (i dati sono del 2016!)
- [ ] Sampling → **No Event Sampling**
- [ ] La query inizia con `index=`

### Discovery del dataset (fallo SEMPRE prima)
```splunk
index=* | stats count by sourcetype          ← quali log esistono?
index=* sourcetype=<X> | head 5              ← come si chiamano i campi?
| fieldsummary                               ← elenca tutti i campi
```

### Query base
```splunk
index="botsv1" sourcetype=<X> earliest=0
```
| Elemento | Cosa fa |
|---|---|
| `index=` | Quale dataset (**obbligatorio**) |
| `sourcetype=` | Tipo di log — **mettilo sempre**: velocizza e garantisce che i campi esistano |
| `earliest=0` | Dal primo evento disponibile |
| parola nuda | Full-text nel raw event (es. `osk.exe`) |

### Comandi core
```splunk
| stats count by <campo>                     ← conta occorrenze per valore
| stats count by <campo> | sort -count       ← chi è più attivo (pattern più usato)
| stats values(CommandLine) by host          ← elenca valori distinti
| stats dc(<campo>) as unici by <campo2>     ← distinct count
| sort _time asc                             ← cronologico (primo evento = inizio attacco)
| sort -count                                ← decrescente
| table campo1, campo2, campo3               ← mostra solo questi campi
| dedup <campo>                              ← scopri QUALI valori esistono
| head 20                                    ← primi 20 risultati
| spath <campo>                              ← estrai campo da JSON/XML
```

### Operatori
```splunk
EventCode=4624 OR EventCode=4625
NOT (host="monitor")
dst="10.10.10.*"                             ← wildcard
Image="*\\cmd.exe"
pass* AND fail*
```

### Time modifiers
```splunk
earliest=0                    ← tutto
earliest=-24h latest=now
earliest=-7d@d latest=@d      ← ultimi 7 giorni completi (@ = snap to)
```

### Sourcetype comuni (BOTSv1)
| Sourcetype | Contiene |
|---|---|
| `stream:http` | `form_data`, `uri`, `http_method`, `src_ip` |
| `fortigate_utm` | `srcip`, `dstip`, `srccountry`, `attack`, `msg` |
| `fortigate_traffic` / `fgt_traffic` | `srcip`, `dstip`, `action` |
| `suricata` | `event_type=alert`, `alert.signature`, `severity` |
| `xmlwineventlog` | **Sysmon**: `Image`, `CommandLine`, `Hashes`, `DestinationPort` |
| `wineventlog` | Windows Event Log |
| `stream:dns` / `stream:smb` / `stream:ldap` | Traffico per protocollo |

### Query pronte
```splunk
### Brute force su form web
index=* sourcetype=stream:http http_method=POST uri="<path>" earliest=0
| table timestamp, src_ip, form_data | sort timestamp asc

### Login falliti per utente
index=* sourcetype=<WINSEC> EventCode=4625 earliest=0
| stats count by Account_Name, IpAddress | sort -count

### Password spray (1 IP, molti account)
index=* sourcetype=<WINSEC> EventCode=4625 earliest=0
| stats dc(Account_Name) as account, count by IpAddress | sort -account

### Brute force RIUSCITO (timeline account)
index=* sourcetype=<WINSEC> (EventCode=4624 OR EventCode=4625) Account_Name="<user>" earliest=0
| table _time, EventCode, IpAddress, Logon_Type | sort _time asc

### Processo con nome legittimo ma PATH sbagliato (masquerading)
index=* sourcetype=<SYSMON> EventCode=1 earliest=0
Image="*\\<nome>.exe" NOT Image="C:\\Windows\\System32\\*"
| table _time, Computer, User, Image, CommandLine | dedup Image

### Office che genera shell (macro malevola)
index=* sourcetype=<SYSMON> EventCode=1 earliest=0
(ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe")
(Image="*\\powershell.exe" OR Image="*\\cmd.exe")
| table _time, Computer, User, ParentImage, Image, CommandLine

### PowerShell encoded
index=* sourcetype=<SYSMON> EventCode=1 earliest=0
(CommandLine="* -enc *" OR CommandLine="* -EncodedCommand *")
| table _time, Computer, User, CommandLine

### Connessioni di rete di un processo
index=* sourcetype=<SYSMON> EventCode=3 Image="*<nome>.exe" earliest=0
| stats count by DestinationIp, DestinationPort | sort -count

### Quanti IP unici contatta (n. righe in Statistics = risposta)
index=* sourcetype=<SYSMON> Image="<path>" DestinationPort=<porta> earliest=0
| stats count by DestinationIp

### Hash di un file (Sysmon EventID 7)
index=* sourcetype=<SYSMON> EventCode=7 ImageLoaded="*<nome>.exe" earliest=0
| table _time, Computer, ImageLoaded, Hashes

### Alert IDS su coppia IP
index=* sourcetype=suricata event_type=alert src_ip=<IP1> dest_ip=<IP2> earliest=0
| table _time, src_ip, dest_ip, dest_port, alert.signature, severity

### Log cancellati (anti-forensics)
index=* (EventCode=1102 OR EventCode=104) earliest=0
| table _time, ComputerName, Account_Name, EventCode

### Shadow copy eliminate (precursore ransomware)
index=* sourcetype=<SYSMON> EventCode=1 earliest=0
(CommandLine="*vssadmin*delete*shadow*" OR CommandLine="*bcdedit*recoveryenabled*no*")
| table _time, Computer, User, CommandLine
```

### Alert e Dashboard
```
Query → Save As → Alert       (Private/Shared · Scheduled/Real-time · threshold · azioni)
Query → Save As → Report      → apri il report → "Add to Dashboard"
Dashboard → Edit → "Select Visualization" → Pie/Line/Bar
Dashboard → Edit → icona LENTE sul panel → VEDI la query che lo alimenta
Naming convention: <group>_<object>_<description>
```

---

## 2. WIRESHARK (PCAP)

### Display filter — sintassi
```
udp                                  ← solo pacchetti UDP
http.request                         ← solo richieste HTTP
tcp.port == 80                       ← porta sorgente O destinazione
ip.src_host == 192.168.1.7
ip.dst_host == 192.168.1.7 && tcp    ← AND: && o and
ntp or udp.port == 20000             ← OR: || o or
not ftp                              ← NOT: ! o not
ftp                                  ← tutto il traffico FTP
arp                                  ← traffico ARP (scan di rete!)
```
💡 **Non ricordi il nome del campo?** Hover sull'hex dump → il nome compare in basso (es. `tcp.seq`)

### Azioni chiave
| Azione | Come |
|---|---|
| **Follow Stream** | Right-click su pacchetto → Follow → TCP/UDP/SSL/HTTP Stream (rosso=request, blu=response) |
| **Esportare file trasmessi** | `File → Export Objects → HTTP` (o SMB/FTP-DATA) |
| **Aggiungere colonna** | Right-click su campo header → **Apply as Column** |
| **Mostrare data e ora reali** | `View → Time Display Format → Date and Time of Day` |
| **Filtrare da una statistica** | Right-click su riga → **Apply as Filter → Selected** |

### Le 3 finestre statistiche (`Statistics → ...`)
| Finestra | Cosa ti dice | 🚩 Segnale |
|---|---|---|
| **Protocol Hierarchy** | % per protocollo | Protocollo raro/insolito in quella rete = possibile exfil |
| **Conversations** | Chi↔chi, porte, byte/pacchetti | Molto inviato + poco ricevuto = exfil |
| **Endpoints** | Volume per host | Trasmette>>riceve = upload/exfil · Riceve>>trasmette = download |

### Workflow tipico su un PCAP sconosciuto
```
1. Statistics → Protocol Hierarchy      → panoramica, protocolli anomali
2. Statistics → Conversations → TCP     → chi parla con chi, volumi
3. Filtra sul protocollo/host sospetto  (ftp, http, ecc.)
4. Follow TCP Stream                    → leggi la conversazione in chiaro
5. File → Export Objects → HTTP         → estrai file trasmessi
6. View → Time Display Format           → per rispondere a domande sull'orario
```
💡 **FTP e HTTP sono in chiaro** → credenziali e file leggibili con Follow Stream.

---

## 3. VOLATILITY (memoria)

### Volatility 2 — il profilo è obbligatorio
```bash
# STEP 1 sempre per primo
volatility -f memdump.mem imageinfo
# → Suggested Profile: Win7SP1x64 + KDBG + n. processori

# STEP 2 — ogni comando successivo richiede --profile
volatility -f memdump.mem --profile=Win7SP1x64 <plugin>
```
Nota: se il comando sopra non va provare:
```bash
python /volatility/vol.py -f memdump.mem imageinfo
python /volatility/vol.py -f memdump.mem --profile=Win7SP1x64 <plugin>
```
⚠️ Plugin **case sensitive**. Path con spazi → `"..."` o `\ `

| Plugin | Cosa fa |
|---|---|
| `imageinfo` | Profilo, KDBG, n. processori |
| `pslist` | Lista processi |
| `pstree` | Processi ad **albero** (relazioni parent-child) |
| `psscan` | Processi **nascosti** (confronta con pslist!) |
| `psxview` | pslist + psscan combinati |
| `cmdline -p PID` | **Command line** di un processo |
| `procdump -p PID -D <dir>` | Estrae l'eseguibile |
| `memdump -p PID -D <dir>` | Estrae lo spazio di memoria |
| `dlllist -p PID` | DLL caricate |
| `netscan` | Connessioni di rete |
| `filescan` | Tutti i file nel dump |
| `dumpfiles -n --dump-dir=./` | Estrae file |
| `hivelist` | Registry hive |
| `hashdump` | Hash password |
| `malfind` | Code injection / regioni sospette |
| `svcscan` | Servizi |
| `consoles` / `cmdscan` | Comandi digitati in CMD |
| `iehistory` | Cronologia IE |
| `timeliner` | Timeline eventi |

### Combo utili
```bash
# contare occorrenze di un processo
volatility -f mem.mem --profile=Win7SP1x64 pslist | grep "svchost.exe" | wc -l

# estrarre + hashare un processo
volatility -f mem.mem --profile=Win7SP1x64 procdump -p 2940 -D ./
md5sum executable.2940.exe`
```

### Volatility 3 — nessun profilo
```bash
python3 vol.py -f memory.raw windows.info
python3 vol.py -f memory.raw windows.pslist
python3 vol.py -f memory.raw windows.pstree
python3 vol.py -f memory.raw windows.psscan
python3 vol.py -f memory.raw windows.cmdline
python3 vol.py -f memory.raw windows.netscan
python3 vol.py -f memory.raw windows.malfind
python3 vol.py -f memory.raw windows.registry.hivelist
```

### Metodologia
```
1. imageinfo → profilo
2. pslist + pstree → relazioni parent-child ANOMALE
   🚩 svchost.exe→cmd.exe→ping.exe · WINWORD.EXE→powershell.exe
3. psscan vs pslist → la DIFFERENZA = processi nascosti
4. cmdline -p PID → cosa stava eseguendo
5. netscan → 🚩 Foreign Address pubblici da processi che non dovrebbero fare rete
6. procdump -p PID + hash → IOC
```

**GUI alternativa:** **Volatility Workbench** (solo Windows) — Browse Image → Platform → comando → Run

---

## 4. ANALISI DISCO

### Autopsy
```
Create New Case → nome + Base Directory (CARTELLA VUOTA)
→ Add Data Source → "Disk Image or VM File" → seleziona .E01/.img
→ Ingest Modules (Recent Activity, File Type ID, Exif Parser, Email Parser, ...)
→ attendi 10+ min
```

| Cerco... | Dove |
|---|---|
| **OS e versione** | Data Artifacts → Operating System Information → colonna `Program Name` |
| **Hostname** | Stessa sezione → colonna `Name` |
| **File scaricati** | Data Artifacts → **Web Downloads** (match su `Date Accessed`, poi `URL`) |
| **Siti visitati** | Web History |
| **File aperti di recente / path** | **Recent Documents** (basato su LNK) |
| **File cancellati** | Recycle Bin |
| **Software installato** | Installed Programs |
| **Email** | Accounts → Email |
| **Utenti + ultimo accesso** | **OS Accounts** |
| **Navigare il filesystem** | Doppio click su **vol2** (la partizione più grande) |
| **Partizioni/spazio** | Click sul nome immagine → Partition Table |

**Export:** right-click su **qualsiasi** file → Export

### Scalpel (file carving)
```bash
# 1. ATTIVA i tipi file nel config (di default TUTTI commentati con #)
sudo nano /etc/scalpel/scalpel.conf
#    → trova la riga del tipo (jpg, png, pdf...) e RIMUOVI il "#" iniziale
#    → Ctrl+O, Invio, Ctrl+X

# 2. la cartella output deve essere VUOTA o NON esistere
rm -rf ScalpelOutput

# 3. lancia
scalpel -o ScalpelOutput carve1.img

# 4. guarda i risultati
ls -R ScalpelOutput        # sottocartelle per tipo (jpg-0-0/) + audit.txt

# 5. hash del file recuperato
md5sum ScalpelOutput/jpg-0-0/00000000.jpg
```
⚠️ Errore *"didn't specify any file types to carve"* = non hai decommentato nulla nel `.conf`
⚠️ Permessi negati → `sudo chown <user> <file>` oppure prefissa `sudo`

### FTK Imager
```
Se ho un file .img: FTK Imager → File → Add Evidence Item → Image File
Identificare il File System di un'immagine: FTK Imager → File → Add Evidence Item → Image File
```
---

## 5. WINDOWS — ARTEFATTI E EVENT LOG

### Path artefatti
| Artefatto | Percorso |
|---|---|
| **LNK / shortcut** | `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\` |
| **Prefetch** | `C:\Windows\Prefetch\*.pf` |
| **Jump List (auto)** | `...\Windows\Recent\AutomaticDestinations` |
| **Jump List (custom)** | `...\Windows\Recent\CustomDestinations` |
| **Event Logs** | `C:\Windows\System32\winevt\Logs\` (`.evtx`) |
| **Recycle Bin** | `C:\$Recycle.Bin\<SID>\` |
| **SYSTEM/SAM/SOFTWARE hive** | `C:\Windows\System32\config\` |
| **NTUSER.DAT** | `C:\Users\<user>\NTUSER.DAT` |
| **Amcache** | `C:\Windows\AppCompat\Programs\Amcache.hve` |
| **$MFT** | root del volume NTFS |
| **Pagefile / Hibernation** | `C:\pagefile.sys` · `C:\hiberfil.sys` |
| **Chrome** | `C:\Users\<user>\AppData\Local\Google\Chrome\User Data` |
| **Firefox** | `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles` |
| **Outlook** | `...\Documents\Outlook Files` · `...\AppData\Local\Microsoft\Outlook` |

### Tool per artefatto
```powershell
# PREFETCH (quante volte eseguito, path, last run)
.\PECmd.exe -f "C:\path\file.pf"
.\PECmd.exe -d "C:\Windows\Prefetch"                    # intera directory
.\PECmd.exe -d "C:\path\Prefetch" -k "stringa"          # evidenzia in rosso
.\PECmd.exe -d "C:\path\Prefetch" --csv "C:\output"
# ⚠️ NIENTE backslash prima delle virgolette finali: "...\Prefetch" non "...\Prefetch\"

# RECYCLE BIN
cd C:\$Recycle.Bin
dir /a                                    :: /a = mostra cartelle nascoste
wmic useraccount get name,SID             :: mappa SID → username
RBCmd.exe -f $I1UOZ51.xlsx                :: singolo file $I
RBCmd.exe -d . --csv "C:\output"          :: directory + CSV (ricorsivo su tutti i SID)
# ⚠️ SERVE CMD COME AMMINISTRATORE, altrimenti "Found 0 files"
# $R = contenuto reale · $I = metadati (nome originale, path, size, data)

# LNK        → Windows File Analyzer (File → Analyse shortcuts)
# JUMP LIST  → JumpList Explorer
# CSV output → CSVQuickViewer
```

### DeepBlueCLI (triage automatico .evtx)
```powershell
cd Downloads\DeepBlue
Set-ExecutionPolicy Bypass -Scope CurrentUser    # se blocca (script non firmato)

./DeepBlue.ps1 ../Log1.evtx                      # file specifico
./DeepBlue.ps1 -log security                     # log live del sistema
./DeepBlue.ps1 -log system
./DeepBlue.ps1 .\folder\* > output.txt           # tutti gli evtx di una cartella
```
Rileva: creazione utenti/gruppi · password spraying · Bloodhound · comandi obfuscated · PowerShell download · servizi sospetti · **Mimikatz/LSASS dump**

### Custom View in Event Viewer (se il sistema NON è nel SIEM)
```
Event Viewer → Custom Views → Create Custom View
→ Logged (range) · Event Level · By Log · Includes/Excludes Event IDs (4624,4672,4647,4634)
```

---

## 6. WINDOWS — TRIAGE LIVE (CMD / PowerShell)

> ⚠️ Sempre come **Amministratore**

### CMD
```cmd
ipconfig /all                                   :: IP, MAC, hostname, DNS
tasklist                                        :: processi + PID + RAM
wmic process get description, executablepath    :: processo + PATH REALE → trova masquerading
net user                                        :: tutti gli utenti
net localgroup                                  :: lista gruppi
net localgroup administrators                   :: chi è admin
net localgroup "Remote Desktop Users"           :: gruppi con spazi → virgolette
sc query | more                                 :: servizi + dettagli
netstat -ab                                     :: porte aperte + ESEGUIBILE responsabile → backdoor/C2
netstat -ano                                    :: con PID, senza risoluzione nomi
```

### PowerShell
```powershell
Get-NetIPConfiguration                                     # = ipconfig
Get-NetIPAddress

Get-LocalUser                                              # utenti locali
Get-LocalUser -Name <nome> | Select *                      # tutte le proprietà

Get-Service | Where Status -eq "Running" | Out-GridView     # servizi attivi in finestra grafica

Get-Process | Format-Table -View priority
Get-Process -Id <id> | Select *
Get-Process -Name <nome> | Select *

Get-ScheduledTask                                          # persistenza
Get-ScheduledTask -TaskName '<nome>' | Select *
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"}
Get-ScheduledTask | Where-Object {$_.TaskName -like "Pe*"}
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled" -and $_.TaskName -like "Pe*"}

Get-WmiObject Win32_UserAccount | Select-Object Name, SID   # SID di tutti gli utenti
Get-CimInstance Win32_UserAccount | Select-Object Name, SID # versione moderna

Set-ExecutionPolicy Bypass -Scope CurrentUser               # sblocca script

wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:1073741824   # ingrandisci canale log
```
**Operatori `Where-Object`:** `-eq` (uguale) · `-ne` (diverso) · `-like "X*"` (wildcard) · `-and` / `-or`
**Pattern:** `| Select *` dopo un comando specifico = tutte le proprietà invece della vista sintetica

### Sysmon
```cmd
sysmon -i                        :: installa
sysmon -i sysmonconfig.xml       :: installa con config
sysmon -c sysmonconfig.xml       :: aggiorna config
sysmon -u                        :: DISINSTALLA
sysmon -u force                  :: disinstalla forzando
```
Log in Event Viewer → canale `Microsoft-Windows-Sysmon/Operational` (serve Custom View per isolarli)

---

## 7. LINUX — ARTEFATTI E COMANDI

### Path
| Artefatto | Percorso |
|---|---|
| Utenti | `/etc/passwd` (username, UID, GID, shell) |
| Password hash | `/etc/shadow` (**solo root**) |
| Software installato | `/var/lib/dpkg/status` |
| Auth / login | `/var/log/auth.log` · `/var/log/secure` (RHEL) |
| Login **falliti** | `/var/log/btmp` · `/var/log/faillog` |
| Cron (persistenza) | `/var/log/cron` |
| Pacchetti | `/var/log/dpkg.log` |
| Web server | `/var/log/apache2/access.log` |
| Command history | `~/.bash_history` |

### Comandi
```bash
ls -a                              # SEMPRE -a → mostra i file nascosti (che iniziano con ".")
ls -lisap <file>                   # info dettagliate
stat <file>                        # timestamp completi
cat ~/.bash_history                # comandi eseguiti (sopravvive a "history -c")
sudo cat /etc/shadow

cat /var/lib/dpkg/status | grep Package > packages.txt   # lista software installato
sudo unshadow /etc/passwd /etc/shadow > combined.txt     # combina per cracking

# permessi (fondamentale nei lab!)
chown <user> <file>
sudo chown <user> <file>
ls -l <file>                       # verifica

# rete
ip a                               # IP interfacce
ip r list                          # routing table
dig <dominio>                      # record A
dig <dominio> MX
dig -x <IP>                        # reverse DNS
traceroute <host>
ss -tulpn                          # porte in ascolto (netstat moderno)

# swap
free -h
swapon --show
```

### Apache access.log — come si legge
```
52.50.100.106 - SBTUser [27/Jul/2020:15:30:00 -0600] "GET /logo.png HTTP/1.1" 200 379
     IP        -  user          timestamp            metodo+risorsa       code size
```
Status: `200` OK · `404` not found · `403` forbidden · `500` server error

---

## 8. PHISHING (.eml)

### Artefatti da raccogliere
**Email:** mittente · subject · destinatari (anche BCC) · IP invio + reverse DNS · SPF/DKIM/DMARC · **Reply-To** · data/ora · Message-ID
**File:** nome+estensione · **SHA256**
**Web:** URL completo (⚠️ **copia**, non riscrivere) · dominio root

### Lettura header
| Campo | Cosa guardare |
|---|---|
| `Received` | 📍 **Leggi dal BASSO verso l'ALTO** → il più in basso = origine reale |
| `Reply-To` | 🚩 Se ≠ `From` = red flag |
| `X-Originating-IP` / `X-Sender-IP` | IP reale del server di invio |
| `Authentication-Results` | Esito SPF/DKIM/DMARC in un colpo d'occhio |
| `Content-Transfer-Encoding: base64` | Il body è codificato → va decodificato |

### Workflow
```
1. Apri il .eml GREZZO (editor di testo), non solo il rendering
2. Body base64? → CyberChef → "From Base64"
3. Estrai gli URL dai tag <a href="...">  (non dal testo visibile!)
4. URL abbreviato? → WannaBrowser (risolve redirect SENZA cliccare)
5. URL → VirusTotal / URLScan.io / URLhaus / PhishTank
6. Dominio → WHOIS (ETÀ! <30 giorni = sospetto)
7. Allegato → SHA256 → VirusTotal / Talos → sandbox (Hybrid Analysis / Any.run)
8. IOC nel report → DEFANGATI
```

### Tool per compito
| Compito | Tool |
|---|---|
| Decodificare Base64 | **CyberChef** → `From Base64` |
| Defangare IOC | **CyberChef** → `Defang URL` / `Defang IP Addresses` |
| Risolvere URL abbreviato | **WannaBrowser** (redirect chain + status + Location) |
| Screenshot senza visitare | **URL2PNG**, **URLScan.io** |
| Reputazione URL/dominio | VirusTotal, URLhaus, PhishTank, URLScan |
| Reputazione IP | **AbuseIPDB**, VirusTotal |
| Reputazione file | VirusTotal, **Cisco Talos File Reputation** |
| Sandbox | Hybrid Analysis, Any.run, Joe Sandbox |
| Info dominio | **WHOIS**, MxToolbox |

### Defanging (per il report)
```
Punti:      8.8.8.8              →  8[.]8[.]8[.]8
Protocollo: https://evil.com     →  hxxps[://]evil[.]com
Email:      user@dominio.com     →  user[@]dominio[.]com
```

### Blocco — quale livello scegliere
```
Dominio PURAMENTE malevolo (giovane, nessun contenuto legittimo)?
├─ SÌ → blocca INTERO DOMINIO
└─ NO (sito legittimo compromesso)
   ├─ i dipendenti non lo visitano mai → blocca comunque tutto il dominio
   └─ potrebbero doverlo visitare → blocca solo l'URL o la DIRECTORY
```
⚠️ URL dinamico (`?email=nome@dominio`) → blocca la **directory**, non l'URL completo
⚠️ Mai bloccare interi domini `@gmail.com` / `@outlook.com`

---

## 9. HASH, METADATI, STEGANOGRAFIA

### Hash
```powershell
Get-FileHash <file>                        # SHA256 (default)
Get-FileHash -Algorithm MD5 <file>
Get-FileHash -Algorithm SHA1 <file>
```
```bash
sha256sum <file>
md5sum <file>
sha1sum <file>
echo -n "testo" | sha256sum                # hash di una STRINGA (-n = no newline!)
```
**Standard attuale: SHA256.** MD5/SHA1 deprecati (hash collision).

### Metadati
```bash
exiftool <file>                            # tool principale
sudo apt-get install exiftool              # se manca
exiftool -Comment="testo" <file>           # scrivi (crea file_original come backup)
```
Windows: right-click → Proprietà → **Dettagli**

### Steganografia
```bash
# nascondere/estrarre ZIP dentro immagine
cat img.jpg secret.zip > new.jpg
unzip new.jpg

# steghide
steghide embed -cf cover.jpg -ef secret.txt   # -cf = cover, -ef = file da nascondere
steghide extract -sf cover.jpg                # -sf = file sospetto
steghide info cover.jpg                       # verifica presenza dati
# password: Invio 2 volte = nessuna password · bruteforce: StegCracker
```

### Acquisizione forense
```
FTK IMAGER
  Dump RAM:     File → Capture Memory → destinazione → nome.mem
  Disk image:   File → Create Disk Image → Physical Drive → seleziona drive
                → Add → formato .E01 (o Raw/dd) → Image Fragment Size = 0
                → Finish → Start  (al termine confronta gli hash)

Se ho un file .img: FTK Imager → File → Add Evidence Item → Image File
Identificare il File System di un'immagine: FTK Imager → File → Add Evidence Item → Image File

KAPE (triage rapido)
  gkape.exe → toggle "Use Target options"
  → Target source (C:\ o immagine) → Target destination (cartella nuova)
  → Targets (lupa → cerca "browser", "Chrome", ecc.) → Execute

PROCDUMP (dump singolo processo live)
  Get-Process | findstr -I calc      # trova il PID
  .\procdump.exe -ma <PID>           # -ma = full dump

dd (Linux)
  sudo dd if=/dev/sdb of=/mnt/evidence/disk.dd bs=4M status=progress
  sha256sum /mnt/evidence/disk.dd > disk.dd.sha256
```

⚠️ **Ordine sempre:** volatile prima (RAM via KAPE/FTK) → poi disco (write blocker + FTK Imager)

---

## 10. MISP (Threat Intelligence)

```bash
# setup
sudo apt install net-tools
sudo /var/www/MISP/app/console/cake baseurl https://<IP>
# web: https://<IP>  →  admin@admin.test / admin

# ⚠️ job "pending" e nessun evento? → i worker non sono attivi:
sudo -u www-data bash /var/www/misp/app/console/workers/start.sh
```

| Azione | Dove |
|---|---|
| Abilitare/scaricare feed | `Sync Actions → List Feeds` → abilita → **freccia giù** = pull |
| Aprire un evento | `Event List` → icona **occhio** |
| Creare un evento | `Add Event` → nome, Threat Level, Distribution |
| **Inserire IOC in massa** ⭐ | **Freetext Import Tool** → incolla la lista → Submit (MISP assegna categoria/tipo automaticamente) |
| Verificare baseurl | `Administration → Server Settings → MISP settings` |

**4 livelli di Distribution:** Your organisation only → This community → Connected communities → All communities

### Pivoting su un IOC
```
IP      → WHOIS · reverse DNS · AbuseIPDB · VirusTotal (tab Relations) · MISP
Dominio → WHOIS (ETÀ!) · passive DNS · VirusTotal/URLhaus · URLScan (screenshot) · MISP
Hash    → VirusTotal · Talos · sandbox (→ nuovi IOC: IP, domini, file droppati)
URL     → WannaBrowser (se abbreviato) → URLScan → estrai dominio → riparti
```

---

## 11. REFERENCE — EVENT ID, CODICI, PORTE

### Windows Event ID
| ID | Log | Significato |
|---|---|---|
| **4624** | Security | Logon **riuscito** |
| **4625** | Security | Logon **fallito** |
| **4634** | Security | Logoff |
| **4647** | Security | Logoff iniziato dall'utente |
| **4672** | Security | **Special Logon** (admin) |
| 4648 | Security | Logon con credenziali esplicite (runas/lateral) |
| **4688** | Security | **Process creation** (+ command line) |
| 4698 | Security | Scheduled task creato 🚩 persistenza |
| 4720 | Security | Account creato 🚩 persistenza |
| 4728 / 4732 | Security | Utente aggiunto a gruppo global/local 🚩 priv esc |
| 4657 | Security | Valore di registro modificato |
| 5140 | Security | Accesso a network share |
| **1102** | Security | 🚩🚩 **Audit log CANCELLATO** |
| 104 | System | System log cancellato |
| 7045 | System | Nuovo servizio installato 🚩 persistenza |
| 7036 | System | Cambio stato servizio (rileva Sysmon stoppato) |
| 4104 | PowerShell/Op | Script block logging (PowerShell **deobfuscato**) |
| 5379 | Security | Lettura credenziali dal Credential Manager |

⭐ Sequenza reale: **4624 (Logon) → 4672 (Special Logon)** — accoppiati per account admin

### Logon Type (campo in 4624/4625)
| # | Tipo |
|---|---|
| **2** | Interactive (accesso fisico) |
| **3** | Network |
| 4 | Batch |
| 5 | Service |
| 7 | Unlock |
| 8 | NetworkCleartext |
| 9 | NewCredentials (`runas /netonly`) |
| **10** | **RemoteInteractive (RDP)** |

### Codici errore 4625
| Codice | Significato |
|---|---|
| `0xC0000064` | Utente **non esiste** 🚩 |
| `0xC000006A` | **Password errata** |
| `0xC000006C` | Policy password non rispettata |
| `0xC000006D` | Bad username |
| `0xC000006E` | Restrizione account |
| `0xC000006F` | Restrizione oraria |
| `0xC0000070` | Restrizione workstation |
| `0xC0000071` | Password **scaduta** |
| `0xC0000072` | Account **disabilitato** 🚩 |
| `0xC000009A` | Risorse insufficienti |
| `0xC0000193` | Account scaduto |
| `0xC0000224` | Deve cambiare password |
| `0xC0000234` | Account **bloccato** 🚩 |

### Sysmon Event ID
| ID | Evento |
|---|---|
| **1** | Process creation (+ command line + parent) |
| **3** | Network connection |
| **7** | Image/DLL loaded ← contiene gli **HASH** |
| 8 | CreateRemoteThread (injection + persistence) |
| 10 | ProcessAccess (credential dumping su lsass) |
| **11** | File created |
| **13** | Registry value set |
| 19/20/21 | WMI (EventFilter / EventConsumer / ConsumerToFilter) |
| 22 | DNS query |

### Porte
| Porta | Servizio | Nota |
|---|---|---|
| 20/21 | FTP | ❌ in chiaro |
| **22** | SSH | ✅ cifrato (anche SFTP) |
| 23 | Telnet | ❌ 🚩 aperto = red flag |
| 25 | SMTP | Trasporto email |
| **53** | DNS | TCP+UDP · 🔍 DNS tunneling |
| 67/68 | DHCP | UDP |
| **80** | HTTP | ❌ in chiaro |
| 88 | Kerberos | AD |
| 110/995 | POP3 / POP3S | |
| 135/139 | RPC / NetBIOS | Legacy Windows |
| 143/993 | IMAP / IMAPS | |
| 389/636 | LDAP / **LDAPS** | 389 in chiaro |
| **443** | HTTPS | ✅ |
| **445** | **SMB** | 🚩 EternalBlue, lateral movement |
| 514 | Syslog | UDP (TCP 514 affidabile, TCP 6514 sicuro) |
| 587 | SMTP submission | ✅ TLS |
| **3389** | **RDP** | 🚩 brute force, lateral movement |
| 5985/5986 | WinRM | PowerShell remoting |

### Syslog
```
PRI = (Facility Code × 8) + Severity Value
```
**Severity:** 0 Emergency · 1 Alert · 2 Critical · 3 Error · 4 Warning · 5 Notice · 6 Info · 7 Debug
**Facility chiave:** 0 Kernel · 2 Mail · 3 Daemons · **4 e 10 Security/Auth** · 9/15 Clock · 16-23 Local Use

### File system
| FS | Limiti chiave |
|---|---|
| FAT32 | File max **4 GB** · partizione max **8 TB** · no crittografia |
| NTFS | Journaling + ACL · Linux via **NTFS-3G** · macOS solo lettura |
| EXT4 (2008) | Volume max **1 exbibyte** · file max **16 TiB** · usa **extents** |

**Settore:** 512 byte (classico) / **4096 byte (4 KiB)** (moderno) · **Cluster** = gruppo di settori · **Slack space** = residuo del cluster (contiene dati di file cancellati)

### MITRE ATT&CK — lookup tecniche citate
| ID | Tecnica | Tattica |
|---|---|---|
| T1566 | Phishing | Initial Access |
| T1133 | External Remote Services | Initial Access / Persistence |
| T1091 | Replication Through Removable Media | Initial Access |
| T1078 | Valid Accounts | Initial Access / Persistence / Priv Esc |
| T1047 | Windows Management Instrumentation | Execution |
| T1204 | User Execution | Execution |
| T1547 | Boot or Logon Autostart Execution | Persistence |
| T1068 | Exploitation for Privilege Escalation | Priv Esc |
| T1562 | Impair Defenses | Defense Evasion |
| T1070 | Indicator Removal on Host | Defense Evasion |
| T1003 | OS Credential Dumping (.1 LSASS · .8 passwd/shadow) | Credential Access |
| T1110 | Brute Force | Credential Access |
| T1087 | Account Discovery | Discovery |
| T1046 | Network Service Scanning | Discovery |
| T1083 | File and Directory Discovery | Discovery |
| T1021 | Remote Services (RDP/SMB/DCOM/SSH/VNC/WinRM) | Lateral Movement |
| T1534 | Internal Spearphishing | Lateral Movement |
| T1114 | Email Collection | Collection |
| T1113 | Screen Capture | Collection |
| T1005 | Data from Local System | Collection |
| T1071 | Application Layer Protocol | C2 |
| T1102 | Web Service | C2 |
| T1571 | Non-Standard Port | C2 |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1020 | Automated Exfiltration | Exfiltration |
| T1029 | Scheduled Transfer | Exfiltration |
| T1531 | Account Access Removal | Impact |
| T1491 | Defacement | Impact |
| T1486 | Data Encrypted for Impact (ransomware) | Impact |

⚠️ Tattiche = `TA00xx` · Tecniche = `Txxxx` — **non confonderli**

---

## 12. TROUBLESHOOTING

| Sintomo | Fix |
|---|---|
| Splunk: **0 eventi** | Time picker → **All Time** (o `earliest=0`) + **No Event Sampling** |
| Splunk: 0 eventi ma il sourcetype esiste | Nome campo sbagliato → `index=* sourcetype=X \| head 5` e leggi i campi reali |
| Splunk: campo che dovrebbe esserci non c'è | **"Show as raw text"** o espandi il log con `>` |
| Splunk non risponde | `sudo systemctl start Splunkd` |
| Firefox "Restore Session" vuoto | Vai diretto a `http://127.0.0.1:8000` o `http://<IP>:8000` |
| Scalpel: *"didn't specify any file types"* | Decommenta (togli `#`) il tipo file in `/etc/scalpel/scalpel.conf` |
| Scalpel: errore cartella output | `rm -rf <output>` — deve essere vuota o inesistente |
| PECmd: *"Option '-d' parse error"* | Togli il `\` finale prima delle virgolette: `"...\Prefetch"` |
| RBCmd: *"Administrator privileges not found"* | Riapri CMD/PowerShell **come Amministratore** |
| *"filename, directory name... syntax is incorrect"* | Non mettere `.\` davanti a un path assoluto |
| Volatility: non legge il `.mem` | Path con spazi → racchiudi in `"..."` |
| Volatility: plugin non riconosciuto | Case sensitive + manca `--profile=` (solo Vol2) |
| PowerShell: script bloccato | `Set-ExecutionPolicy Bypass -Scope CurrentUser` |
| Linux: file non trovati in una cartella | Usa `ls -a` (file nascosti) |
| Linux: permission denied | `sudo chown <user> <file>` o prefissa `sudo` |
| Windows: cartelle non visibili | `dir /a` |
| MISP: job pending, nessun evento | Avvia i worker (`start.sh`) |

---

## 13. RUNBOOK — INCIDENT RESPONSE (strategia + procedura tecnica)

> Ogni scenario ha due livelli:
> **① Quadro d'insieme**: cosa devi ottenere in ogni fase NIST, con i rimandi agli step · **② Procedura tecnica**: gli step numerati con comandi e tool.
> 🧪 = fattibile nel lab BTL1 · 🏢 = vita reale (M365 / AD / EDR)
> Evidenze sempre su **disco esterno** (`E:\IR\<caso>` / `/mnt/usb/<caso>`), mai sull'host compromesso. Ogni file acquisito → **hash subito**.

### 🗺️ Indice scenari
| Scenario | Trigger tipico | Può portare a |
|---|---|---|
| [A. Phishing](#-a-phishing) | Mail segnalata dall'utente · alert del gateway | B (allegato eseguito) · C (credenziali inserite) |
| [B. PC Windows compromesso](#-b-pc-windows-compromesso) | Alert EDR/AV · processo o traffico anomalo | F (movimento laterale) · E (exfil) |
| [B-bis. Server Linux compromesso](#-b-bis-server-linux-compromesso) | Processo/connessione anomala · alert su server | E · G |
| [C. Account compromesso](#-c-account-compromesso--brute-force--password-spray) | Picco di 4625 · login anomalo · impossible travel | F · A (phishing interno) |
| [D. Ransomware](#-d-ransomware) | File rinominati · ransom note · shadow copy cancellate | E (double extortion) |
| [E. Data exfiltration](#-e-data-exfiltration) | Volumi anomali in uscita · DNS strano · DLP | B |
| [F. Lateral movement / AD](#%EF%B8%8F-f-lateral-movement--attivit%C3%A0-sospetta-in-ad) | Logon tra workstation · PsExec · accesso a LSASS | D |
| [G. Web server / web app](#-g-attacco-a-web-server--web-application) | Picco di 404 · pattern SQLi · alert WAF | B / B-bis (webshell) |

### ⚖️ Principi validi per TUTTI gli scenari
| Regola | Perché |
|---|---|
| **Documenta tutto con timestamp** (chi, cosa, quando, da dove) | La timeline è la base del report e di eventuali azioni legali |
| **Non spegnere** un host compromesso → **isolalo dalla rete** | Spegnendo perdi la RAM (processi, connessioni, chiavi di cifratura) |
| **Ordine di volatilità**: RAM → processi/rete live → disco → log | Il volatile sparisce per primo |
| **Niente scansioni AV prima del dump** | Modificano timestamp e possono cancellare il malware (= prova) |
| **Hash di ogni evidenza acquisita** + chain of custody | Integrità e ammissibilità della prova |
| **Non allertare l'attaccante** (no ping/visite ai suoi IP/domini dalla rete aziendale) | Rischi che cambi infrastruttura o acceleri l'attacco |
| **Scoping prima del contenimento definitivo**: cerca lo stesso IOC su TUTTA la fleet (SIEM/EDR) | Contenere un host solo mentre altri 5 sono infetti = reinfezione |
| **Escalation secondo procedura** (responsabile/CISO) appena la severity è ≥ Alta | Decisioni di business (isolare server critici, notifiche legali) non spettano all'analista |
| **Obblighi di notifica**: GDPR → Garante entro **72h** (data breach) · NIS2 → early warning **24h**, notifica **72h**, report finale **1 mese** | Da valutare con legal/CISO, non in autonomia |

### 🔁 Fasi NIST SP 800-61 (scheletro di ogni scenario)
| # | Fase | Obiettivo |
|---|---|---|
| 1 | Preparation | Tool, accessi, contatti, playbook pronti **prima** (chiavetta IR con FTK Imager, WinPmem, KAPE, EZ Tools, Autoruns) |
| 2 | Detection & Analysis | Confermare che è un incidente, capirne portata e severity |
| 3 | Containment | Fermare la propagazione (short-term: isolamento → long-term: blocchi, reset) |
| 4 | Eradication | Rimuovere la causa (malware, persistenza, account, vulnerabilità) |
| 5 | Recovery | Ripristinare in sicurezza e monitorare |
| 6 | Lessons Learned | Report, root cause, miglioramenti (regole SIEM, awareness, patch) |

---

### 🎣 A. PHISHING

#### ① Quadro d'insieme
| Fase | Cosa devi ottenere | → Step |
|---|---|---|
| **Analisi** | Header (`Received` dal basso, `Reply-To`≠`From`, SPF/DKIM/DMARC) · URL (da `href`) · allegato (SHA256, reputazione, sandbox) | 1 · 2 · 3 · 4 |
| **Scoping** | Quanti l'hanno ricevuta · **chi ha cliccato** · **chi ha inserito credenziali** · chi ha aperto l'allegato | 5 |
| **Containment** | Purge da tutte le mailbox · blocco mittente/URL/hash · reset + revoca sessioni per chi ha inserito credenziali | 6 · 7 |
| **Eradication** | Inbox rules / inoltri dell'attaccante · MFA e app OAuth aggiunte · allegato eseguito → scenario **B** | 7 |
| **Recovery** | Monitoraggio login degli account coinvolti (impossible travel, nuovi device) | 7 |
| **Lessons Learned** | IOC defangati in report e MISP · awareness utenti · tuning gateway | 8 |

#### ② Procedura tecnica

**1. Preserva l'originale** · *Analysis* 🧪
```powershell
Get-FileHash -Algorithm SHA256 .\mail.eml          # hash dell'evidenza
```
🏢 Outlook: *Salva come* `.eml`/`.msg` (non inoltrare: perdi gli header originali)

**2. Estrai gli header chiave** · *Analysis* 🧪
```bash
grep -iE "^(from|to|cc|subject|date|reply-to|return-path|message-id|x-originating-ip|x-sender-ip|authentication-results|received):" mail.eml
```
| Controllo | Come |
|---|---|
| Origine reale | `Received` **più in basso** → IP → `dig -x <IP>` + AbuseIPDB |
| Spoofing | `Authentication-Results`: `spf=fail` / `dkim=fail` / `dmarc=fail` |
| Reply-To ≠ From | 🚩 BEC / raccolta risposte |
| Dominio mittente | WHOIS → età < 30 gg = 🚩 |

**3. Estrai gli URL** · *Analysis* 🧪
```bash
grep -oiE 'https?://[^"<> ]+' mail.eml | sort -u
```
Body in base64 → **CyberChef**: `From Base64` → `Extract URLs`
URL abbreviato → **WannaBrowser** · poi **URLScan.io** (screenshot) + **VirusTotal**

**4. Estrai e analizza l'allegato** · *Analysis* 🧪
```bash
emldump.py mail.eml                       # elenca le parti MIME
emldump.py mail.eml -s <n> -d > allegato  # dump della parte n
# alternativa: CyberChef → From Base64 → icona "Save output to file"
sha256sum allegato                        # → cerca l'HASH su VirusTotal/Talos (non caricare file aziendali!)
```
| Tipo allegato | Tool |
|---|---|
| Office (`.doc/.docm/.xls`) | `oleid file` · `olevba file` → macro, AutoOpen, URL, PowerShell |
| PDF | `pdfid.py file.pdf` → cerca `/JavaScript`, `/OpenAction`, `/Launch` |
| `.exe/.js/.hta/.iso/.lnk` | Hash → VT · sandbox **Any.run / Hybrid Analysis** → annota IP/domini contattati |

**5. Chi l'ha ricevuta / cliccata / eseguita** · *Scoping* 🧪
```splunk
### chi ha contattato il dominio (DNS)
index=* sourcetype=stream:dns query="*<dominio>*" earliest=0 | stats count by src_ip
### stessa cosa via Sysmon (DNS query)
index=* sourcetype=<SYSMON> EventCode=22 QueryName="*<dominio>*" earliest=0 | stats count by Computer, Image
### chi ha aperto l'allegato (processo figlio di Outlook/Office)
index=* sourcetype=<SYSMON> EventCode=1 earliest=0
(ParentImage="*\\outlook.exe" OR ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe")
| table _time, Computer, User, ParentImage, Image, CommandLine
### file droppato dalla cache allegati di Outlook
index=* sourcetype=<SYSMON> EventCode=11 TargetFilename="*\\Content.Outlook\\*" earliest=0
| table _time, Computer, TargetFilename
```

**6. Purge e blocchi** · *Containment* 🏢 (Exchange Online / Security & Compliance PowerShell)
```powershell
# purge da tutte le mailbox
New-ComplianceSearch -Name "phish-<id>" -ExchangeLocation All -ContentMatchQuery 'from:"<mittente>" AND subject:"<oggetto>"'
Start-ComplianceSearch -Identity "phish-<id>"
New-ComplianceSearchAction -SearchName "phish-<id>" -Purge -PurgeType SoftDelete

# blocco mittente / URL / hash
New-TenantAllowBlockListItems -ListType Sender   -Block -Entries "<mittente>" -NoExpiration
New-TenantAllowBlockListItems -ListType Url      -Block -Entries "<dominio>"  -NoExpiration
New-TenantAllowBlockListItems -ListType FileHash -Block -Entries "<sha256>"   -NoExpiration
```
Livello di blocco (dominio vs URL vs directory) → albero decisionale in §8

**7. Utente che ha inserito le credenziali** · *Containment → Eradication → Recovery* 🏢
```powershell
# reset password (portale/AD) + chiudi tutte le sessioni attive
Revoke-MgUserSignInSession -UserId <upn>
# regole inbox create dall'attaccante (inoltro/cancellazione)
Get-InboxRule -Mailbox <upn> | fl Name,Enabled,ForwardTo,RedirectTo,DeleteMessage,MoveToFolder
Get-Mailbox <upn> | fl ForwardingSmtpAddress,DeliverToMailboxAndForward
```
Poi: metodi MFA aggiunti · app OAuth autorizzate · sign-in log (IP/paese anomali) → monitoraggio nei giorni successivi
Allegato eseguito su un PC → vai a **B**

**8. Chiusura** · *Lessons Learned* 🧪
IOC → CyberChef `Defang URL` / `Defang IP Addresses` → MISP **Freetext Import** → report (template in fondo)

---

### 💻 B. PC WINDOWS COMPROMESSO

#### ① Quadro d'insieme
| Fase | Cosa devi ottenere | → Step |
|---|---|---|
| **Containment (short-term)** ⚡ | **Isolamento di rete** subito, senza spegnere | 1 |
| **Raccolta evidenze** | **RAM per prima** → dati volatili → artefatti (KAPE) → immagine disco se serve | 2 · 3 · 4 · 5 |
| **Analisi** | Processo, parent, command line, utente · parent-child anomali (`winword→powershell`, `svchost→cmd`) · connessioni · hash → VT · persistenza | 6 · 7 |
| **Scoping** | Stesso hash / IP C2 / dominio / nome file su **tutta** la fleet · vettore d'ingresso (email → A, USB, download, exploit) | 8 |
| **Containment (long-term)** | Blocco IP/domini C2 (firewall/proxy/DNS) + hash (EDR) · disabilita l'account se usato dal malware | 9 |
| **Eradication** | Persistenza rimossa (Run keys, task, servizi, WMI, account) · preferisci **reimage** alla pulizia | 9 |
| **Recovery** | Reset credenziali usate sull'host (possibile dump LSASS) · rientro in rete sotto monitoraggio | 10 |
| **Lessons Learned** | Root cause (vettore iniziale) · nuova regola SIEM per il pattern osservato | Report |

#### ② Procedura tecnica

**1. Isola (NON spegnere)** · *Containment*
🏢 EDR → *Isolate host* · senza EDR: stacca il cavo / disabilita la porta sullo switch
Annota: ora, utente loggato, cosa si vede a schermo (foto)

**2. Dump della RAM** · *Evidenze* (da USB, output su disco esterno)
```
FTK Imager → File → Capture Memory → Destination: E:\IR\<caso> → ✔ Include pagefile → Capture
```
```cmd
winpmem_mini_x64.exe E:\IR\<caso>\mem.raw       :: alternativa da riga di comando
```
```powershell
Get-FileHash -Algorithm SHA256 E:\IR\<caso>\*.mem
```
Solo un processo sospetto: `procdump.exe -accepteula -ma <PID> E:\IR\<caso>\`

**3. Dati volatili live** · *Evidenze* (CMD admin, output su esterno)
```cmd
set O=E:\IR\<caso>\live
echo %date% %time% > %O%\00_ora.txt
netstat -anob                                    > %O%\netstat.txt
tasklist /v                                      > %O%\tasklist.txt
wmic process get processid,parentprocessid,name,executablepath,commandline /format:csv > %O%\processi.csv
ipconfig /displaydns                             > %O%\dnscache.txt
arp -a                                           > %O%\arp.txt
quser                                            > %O%\sessioni.txt
net user                                         > %O%\utenti.txt
net localgroup administrators                    > %O%\admin.txt
schtasks /query /fo LIST /v                      > %O%\tasks.txt
sc query type= service state= all                > %O%\servizi.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run > %O%\run_hklm.txt
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run > %O%\run_hkcu.txt
autorunsc64.exe -accepteula -a * -c -h -s        > %O%\autoruns.csv
```
```powershell
# persistenza WMI (Sysmon 19-20-21)
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer
```

**4. Triage artefatti con KAPE** · *Evidenze*
```cmd
kape.exe --tsource C: --tdest E:\IR\<caso>\kape_t --target KapeTriage --mdest E:\IR\<caso>\kape_m --module !EZParser
```
GUI: `gkape.exe` → Use Target options → `KapeTriage` → (Module options → `!EZParser`) → Execute

**5. Immagine disco** · *Evidenze* (se serve analisi completa)
```
FTK Imager → File → Create Disk Image → Physical Drive → formato E01 → Fragment Size 0 → ✔ Verify → Start
```
Disco rimosso → sempre dietro **write blocker**

**6. Analisi RAM** · *Analysis* 🧪
```bash
vol -f mem.raw windows.info
vol -f mem.raw windows.pstree          # parent-child anomali (winword→powershell, svchost→cmd)
vol -f mem.raw windows.psscan          # confronta con pslist → processi nascosti
vol -f mem.raw windows.cmdline
vol -f mem.raw windows.netscan         # Foreign Address pubblici
vol -f mem.raw windows.malfind         # injection
vol -f mem.raw windows.pslist --pid <PID> --dump   # estrai l'eseguibile → sha256sum → VT
```
(Vol2: `imageinfo` → `--profile=` → `pstree`, `psscan`, `cmdline`, `netscan`, `malfind`, `procdump` — §3)

**7. Analisi artefatti disco** · *Analysis* 🧪
```powershell
PECmd.exe         -d "C:\Windows\Prefetch"                        --csv E:\IR\<caso>\out   # esecuzioni
AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve"  --csv E:\IR\<caso>\out   # esecuzioni + SHA1
EvtxECmd.exe      -d "C:\Windows\System32\winevt\Logs"            --csv E:\IR\<caso>\out   # tutti gli evtx
MFTECmd.exe       -f "E:\IR\<caso>\kape_t\C\$MFT"                 --csv E:\IR\<caso>\out   # timeline filesystem
RBCmd.exe         -d "C:\$Recycle.Bin"                            --csv E:\IR\<caso>\out   # file cancellati
.\DeepBlue.ps1    E:\IR\<caso>\kape_t\C\Windows\System32\winevt\Logs\Security.evtx
```
CSV → **Timeline Explorer** / CSVQuickViewer · Immagine completa → **Autopsy** (§4)
Persistenza da cercare negli eventi: Run keys (Sysmon 13) · task (4698) · servizi (7045) · WMI (Sysmon 19-21) · account (4720)

**8. Scoping sulla fleet** · *Scoping* 🧪
```splunk
index=* ("<hash>" OR "<IP_C2>" OR "<dominio_C2>" OR "<nome_file>") earliest=0
| stats count, values(sourcetype) by host
```

**9. Blocchi e bonifica** · *Containment long-term → Eradication* 🏢
Blocco IP/domini C2 (firewall/proxy/DNS) + hash (EDR) → rimozione persistenza trovata negli step 3/7 → **reimage** (non "pulire")

**10. Rientro** · *Recovery* 🏢
Reset password di tutti gli account loggati sull'host → rientro in rete sotto monitoraggio (stessi IOC in alert sul SIEM)

---

### 🐧 B-bis. SERVER LINUX COMPROMESSO

#### ① Quadro d'insieme
Stesse fasi di **B**. Cambiano solo i tool: LiME al posto di FTK/WinPmem, `/proc` e cron al posto di Prefetch e Run keys.

| Fase | → Step |
|---|---|
| Containment short-term | Isolamento di rete (come B.1) |
| Raccolta evidenze | 1 · 2 · 4 |
| Analisi persistenza | 3 |
| Scoping · Eradication · Recovery | Come B.8 → B.10 (reinstallazione, rotazione chiavi SSH e credenziali) |

#### ② Procedura tecnica

**1. RAM** · *Evidenze* (modulo LiME compilato per il kernel del target, da USB)
```bash
sudo insmod lime.ko "path=/mnt/usb/<caso>/mem.lime format=lime"
sha256sum /mnt/usb/<caso>/mem.lime
```

**2. Dati volatili** · *Evidenze*
```bash
date -u                                  > /mnt/usb/<caso>/ora.txt
ps auxf                                  > /mnt/usb/<caso>/ps.txt
ss -tunap                                > /mnt/usb/<caso>/ss.txt
{ who; last -i | head -50; }             > /mnt/usb/<caso>/login.txt
ls -la /tmp /var/tmp /dev/shm            # staging tipico di malware
ls -l /proc/<PID>/exe                    # "(deleted)" = binario cancellato ancora in esecuzione
cp /proc/<PID>/exe /mnt/usb/<caso>/pid<PID>.bin   # recuperalo
lsof -p <PID>
```

**3. Persistenza** · *Analysis*
```bash
for u in $(cut -d: -f1 /etc/passwd); do echo "== $u"; crontab -l -u $u 2>/dev/null; done
ls -la /etc/cron* /var/spool/cron
systemctl list-units --type=service --state=running
ls -la /etc/systemd/system/
cat /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys
grep -E ':0:' /etc/passwd                # UID 0 oltre a root = 🚩
cat /home/*/.bash_history /root/.bash_history
```

**4. Disco** · *Evidenze*
```bash
sudo dd if=/dev/sda of=/mnt/usb/<caso>/disk.dd bs=4M status=progress && sha256sum /mnt/usb/<caso>/disk.dd
```

---

### 🔑 C. ACCOUNT COMPROMESSO / BRUTE FORCE / PASSWORD SPRAY

#### ① Quadro d'insieme
| Fase | Cosa devi ottenere | → Step |
|---|---|---|
| **Analisi** | Molti **4625** → poi un **4624** = brute force riuscito · 1 IP → molti account = spray · codici errore 4625 (§11) · **Logon Type** 3/10 · geolocalizzazioni/orari anomali | 1 · 3 |
| **Scoping** | Cosa ha fatto l'account **dopo** il login (4672, 4688/Sysmon 1, 5140, 4648) · altri account attaccati dallo stesso IP | 2 |
| **Containment** | Disabilita o reset password + revoca sessioni · blocco IP sorgente · servizio esposto (RDP/VPN/OWA) dietro MFA/VPN | 4 |
| **Eradication** | Persistenza creata dall'account: 4720, 4728/4732, 4698, 7045 · MFA e metodi di recovery modificati | 5 |
| **Recovery** | Riabilita con MFA · monitoraggio mirato | 5 |
| **Lessons Learned** | Account lockout policy · MFA ovunque · regola SIEM su N×4625 in X minuti | Report |

#### ② Procedura tecnica

**1. Conferma il pattern** · *Analysis* 🧪
```splunk
### brute force (1 account, molti tentativi) → cerca 4624 dopo i 4625
index=* sourcetype=<WINSEC> (EventCode=4625 OR EventCode=4624) Account_Name="<user>" earliest=0
| table _time, EventCode, Logon_Type, IpAddress, Workstation_Name, Status | sort _time asc
### spray (1 IP, molti account)
index=* sourcetype=<WINSEC> EventCode=4625 earliest=0
| stats dc(Account_Name) as account, count by IpAddress | sort -account
```
`Status/Sub_Status`: `0xC0000064` utente inesistente (enumerazione) · `0xC000006A` password errata (utente valido!)
⚠️ Nome campo IP varia: `IpAddress` / `Source_Network_Address` / `src_ip` → controlla con `| head 5`

**2. Cosa ha fatto dopo il login riuscito** · *Scoping* 🧪
```splunk
index=* (Account_Name="<user>" OR User="*<user>") earliest=<ora_login>
(EventCode=4672 OR EventCode=4688 OR EventCode=4648 OR EventCode=5140 OR EventCode=4720 OR EventCode=4728 OR EventCode=4732 OR EventCode=4698 OR EventCode=7045 OR EventCode=1)
| table _time, host, EventCode, Image, CommandLine, ShareName, TargetUserName | sort _time asc
```

**3. SSH su Linux** · *Analysis* 🧪
```bash
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head   # IP attaccanti
grep "Accepted" /var/log/auth.log                                                                     # login riusciti 🚩
sudo lastb | head -30          # login falliti
last -i | head -30             # login riusciti con IP
```

**4. Blocca account e sorgente** · *Containment* 🏢
```powershell
Disable-ADAccount -Identity <user>
Set-ADAccountPassword -Identity <user> -Reset -NewPassword (Read-Host -AsSecureString "Nuova pwd")
Get-ADUser <user> -Properties LastLogonDate,PasswordLastSet,MemberOf,Enabled
Revoke-MgUserSignInSession -UserId <upn>                      # se account cloud/ibrido
New-NetFirewallRule -DisplayName "IR block <IP>" -Direction Inbound -RemoteAddress <IP> -Action Block
```
```bash
sudo iptables -A INPUT -s <IP> -j DROP                        # Linux
sudo passwd -l <user>                                         # blocca account Linux
```

**5. Rimuovi ciò che ha creato e riabilita** · *Eradication → Recovery* 🏢
```powershell
Get-ADGroupMember "Domain Admins"            # membri aggiunti di recente?
Get-ADUser -Filter * -Properties whenCreated | ? whenCreated -gt (Get-Date).AddDays(-7) | select Name,whenCreated
```
Rimuovi account/gruppi/task/servizi creati (4720/4728/4732/4698/7045) · verifica metodi MFA registrati · riabilita l'account con MFA

---

### 🔒 D. RANSOMWARE

#### ① Quadro d'insieme
| Fase | Cosa devi ottenere | → Step |
|---|---|---|
| **Containment** ⚡ (PRIMA dell'analisi) | Isolamento immediato degli host colpiti (senza spegnere: la chiave può essere in RAM) · backup scollegati · share protette · account di propagazione disabilitati · segmentazione se diffuso | 1 |
| **Analisi** | Famiglia (ransom note, estensione, hash) · segnali di preparazione (`vssadmin`, `bcdedit`, `wbadmin`) · processo che cifra | 2 · 3 |
| **Scoping** | **Patient zero** e vettore iniziale (phishing, RDP esposto, VPN) · esfiltrazione prima della cifratura (double extortion)? | 3 · 4 |
| **Eradication** | Reset di **tutte** le credenziali privilegiate (domain admin, service account, krbtgt ×2) · persistenza rimossa · patch del vettore | 5 |
| **Recovery** | Backup **integri e non infetti** verificati prima del restore · ripristino per priorità di business · reimage | 5 |
| **Lessons Learned** | Notifiche GDPR/NIS2 con CISO/legal · il pagamento è decisione del management, mai dell'analista · backup offline/immutabili | Report |

#### ② Procedura tecnica

**1. Contenimento immediato** · *Containment* 🏢
- EDR → isola **tutti** gli host che mostrano cifratura · NON spegnere → dump RAM come in B.2
- Scollega/stoppa il **backup** raggiungibile dalla rete
- Sul file server: individua chi sta cifrando le share e taglialo fuori
```powershell
Get-SmbSession | sort NumOpens -Descending | select ClientComputerName, ClientUserName, NumOpens
Get-SmbOpenFile | group ClientComputerName | sort Count -Descending
Close-SmbSession -ClientComputerName <IP_host> -Force
Disable-ADAccount -Identity <account_che_cifra>
```

**2. Identifica la famiglia** · *Analysis* 🏢
Ransom note + un file cifrato → **ID Ransomware** · decryptor esistente? → **No More Ransom**

**3. Patient zero e timeline** · *Analysis → Scoping* 🧪
```splunk
### primo host a creare file con la nuova estensione
index=* sourcetype=<SYSMON> EventCode=11 TargetFilename="*.<estensione>" earliest=0
| stats earliest(_time) as primo, count by Computer | sort primo | convert ctime(primo)
### preparazione: shadow copy / recovery disabilitati
index=* sourcetype=<SYSMON> EventCode=1 earliest=0
(CommandLine="*vssadmin*delete*" OR CommandLine="*wmic*shadowcopy*delete*" OR CommandLine="*bcdedit*recoveryenabled*no*" OR CommandLine="*wbadmin*delete*")
| table _time, Computer, User, ParentImage, CommandLine | sort _time asc
### processo che cifra (chi scrive più file)
index=* sourcetype=<SYSMON> EventCode=11 earliest=0 | stats count by Computer, Image | sort -count | head 10
```
Dal patient zero risali al vettore: mail (→ A) · RDP esposto (4624 Logon Type 10 da IP pubblico → C) · VPN

**4. Esfiltrazione prima della cifratura?** · *Scoping*
Double extortion → vai a **E**, cerca `rclone`, `megasync`, `winscp`, archivi `7z/rar`

**5. Bonifica e ripristino** · *Eradication → Recovery* 🏢
Reset account privilegiati + service account + **krbtgt due volte** (script Microsoft `New-KrbtgtKeys.ps1`, attendendo la replica tra i due reset) → reimage → verifica backup **integri e non cifrati** → restore per priorità

---

### 📤 E. DATA EXFILTRATION

#### ① Quadro d'insieme
| Fase | Cosa devi ottenere | → Step |
|---|---|---|
| **Analisi** | Host interno che invia **molto e riceve poco** · protocolli insoliti · **DNS tunneling** (sottodomini lunghi/random, molte query TXT) · cloud storage / porte non standard (T1571) · trasferimenti a orari regolari (T1029) | 1 · 2 |
| **Scoping** | Quali host/utenti · **quali dati** (dimensione, share/cartelle: 5140, Sysmon 11) · destinazione · durata | 2 |
| **Containment** | Blocco destinazione · isolamento host sorgente · account disabilitato | 3 |
| **Eradication** | Tool/canale di exfil e malware associato rimossi (→ **B**) | 3 |
| **Recovery** | Monitoraggio egress (DLP, proxy) | 3 |
| **Lessons Learned** | **Classificazione dei dati usciti** → obblighi di notifica · regole su volumi anomali in uscita | 4 |

#### ② Procedura tecnica

**1. PCAP** · *Analysis* 🧪 (Wireshark)
```
Statistics → Conversations → IPv4 → ordina per "Bytes A → B"  (host interno che invia tanto)
Statistics → Protocol Hierarchy                              (protocolli fuori posto)
dns && len(dns.qry.name) > 50                                ← DNS tunneling (sottodomini lunghi)
dns.qry.type == 16                                           ← query TXT (tunneling/C2)
http.request.method == "POST" && ip.src == <interno>         ← upload HTTP
ftp || ftp-data                                              ← FTP in chiaro → Follow TCP Stream
tcp.port == 4444 || tcp.port == 8080                         ← porte non standard (adatta)
File → Export Objects → HTTP / FTP-DATA / SMB                ← recupera ciò che è uscito
```

**2. SIEM** · *Analysis → Scoping* 🧪
```splunk
### volume in uscita per coppia (FortiGate)
index=* sourcetype=fortigate_traffic earliest=0
| stats sum(sentbyte) as out by srcip, dstip, dstport | sort -out | head 20
### DNS tunneling
index=* sourcetype=stream:dns earliest=0 | eval l=len(query) | where l>50
| stats count by src_ip, query | sort -count
### tool di exfil / archiviazione
index=* sourcetype=<SYSMON> EventCode=1 earliest=0
(CommandLine="*rclone*" OR CommandLine="*megasync*" OR CommandLine="*Compress-Archive*" OR CommandLine="*7z* a *" OR CommandLine="*rar* a *" OR CommandLine="*curl* -T *")
| table _time, Computer, User, CommandLine
### quale processo parla con la destinazione
index=* sourcetype=<SYSMON> EventCode=3 DestinationIp="<IP_dest>" earliest=0 | stats count by Computer, Image, DestinationPort
```

**3. Chiudi il canale** · *Containment → Eradication* 🏢
Blocco destinazione (firewall/proxy/DNS sinkhole) → isola l'host → disabilita l'account → processo trovato = malware → **B**

**4. Quantifica** · *Lessons Learned*
Cosa è uscito (file, dimensione, classificazione) → decide gli obblighi di notifica

---

### ↔️ F. LATERAL MOVEMENT / ATTIVITÀ SOSPETTA IN AD

#### ① Quadro d'insieme
| Fase | Cosa devi ottenere | → Step |
|---|---|---|
| **Analisi** | Logon Type 3/10 **tra workstation** · 4648 · 5140 su `ADMIN$`/`C$` · 7045 `PSEXESVC` · WinRM · RDP interno · Sysmon 10 su `lsass.exe` | 1 · 2 |
| **Scoping** | **Percorso** host→host in ordine cronologico · account usati/rubati · arrivo a DC o server critici? | 3 |
| **Containment** | Host del percorso isolati · account disabilitati/resettati · SMB/RDP/WinRM tra workstation bloccati | 4 |
| **Eradication** | Reset di tutti gli account esposti (DC toccato → **krbtgt ×2**) · persistenza rimossa su ogni host del percorso | 4 |
| **Recovery** | Monitoraggio intensivo AD (4728/4732, 4720) | 4 |
| **Lessons Learned** | Tiering admin · LAPS · restrizione admin locale · segmentazione | Report |

#### ② Procedura tecnica

**1. Chi si è autenticato dove** · *Analysis* 🧪
```splunk
index=* sourcetype=<WINSEC> EventCode=4624 (Logon_Type=3 OR Logon_Type=10) earliest=0
NOT Account_Name="*$"
| stats count, values(host) as destinazioni by Account_Name, IpAddress | sort -count
```

**2. Tecniche specifiche** · *Analysis* 🧪
| Tecnica | Query / indicatore |
|---|---|
| **PsExec** | `EventCode=7045 Service_Name="PSEXESVC"` · Sysmon 1 `ParentImage="*\\PSEXESVC.exe"` |
| **WMI exec** | Sysmon 1 `ParentImage="*\\WmiPrvSE.exe" (Image="*\\cmd.exe" OR Image="*\\powershell.exe")` |
| **WinRM / PS Remoting** | Sysmon 1 `ParentImage="*\\wsmprovhost.exe"` · porte 5985/5986 |
| **Admin share** | `EventCode=5140 (Share_Name="*ADMIN$" OR Share_Name="*C$")` |
| **RDP interno** | `EventCode=4624 Logon_Type=10` tra workstation |
| **Credenziali esplicite** | `EventCode=4648` (runas, strumenti di lateral) |
| **Dump LSASS** | Sysmon 10 `TargetImage="*\\lsass.exe"` (GrantedAccess `0x1010`/`0x1410`) · DeepBlueCLI → Mimikatz |

**3. Ricostruisci il percorso** · *Scoping* 🧪
Host A → B → C in ordine cronologico (`sort _time asc`) → ogni host del percorso = scenario **B**

**4. Contieni e bonifica** · *Containment → Eradication → Recovery* 🏢
Isola gli host del percorso · disabilita/reset account usati · DC toccato → reset **krbtgt ×2** · blocca SMB/RDP/WinRM tra workstation · alert su 4720/4728/4732

---

### 🌐 G. ATTACCO A WEB SERVER / WEB APPLICATION

#### ① Quadro d'insieme
| Fase | Cosa devi ottenere | → Step |
|---|---|---|
| **Analisi** | Picco di **404** (enumerazione) · SQLi · path traversal · XSS · molti **POST** sul login · user-agent di scanner | 1 |
| **Compromissione?** | Richiesta malevola seguita da **200** · **webshell** nella web root · web server che genera `cmd.exe`/`sh` | 1 · 2 |
| **Containment** | Blocco IP (WAF/firewall) · regola WAF sul pattern · server compromesso → offline o isolato | 3 |
| **Eradication** | Webshell e file aggiunti rimossi · **patch** della vulnerabilità · rotazione credenziali DB/app | 3 |
| **Recovery** | Restore da versione pulita · monitoraggio log web | 3 |
| **Lessons Learned** | WAF · hardening · vulnerability management sull'applicazione | Report |

#### ② Procedura tecnica

**1. Analisi log** · *Analysis* 🧪 (Apache `/var/log/apache2/access.log` · IIS `C:\inetpub\logs\LogFiles\W3SVC1\`)
```bash
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head          # IP più attivi
awk '{print $9}' access.log | sort | uniq -c | sort -rn                 # distribuzione status code
awk '$9==404 {print $1}' access.log | sort | uniq -c | sort -rn | head   # enumerazione (dirbusting)
grep -iE "union.*select|%27|' or|or%201=1|sleep\(|information_schema" access.log   # SQLi
grep -iE "\.\./|%2e%2e|/etc/passwd" access.log                            # path traversal / LFI
grep -iE "<script|%3cscript" access.log                                   # XSS
grep -iE "sqlmap|nikto|nmap|gobuster|dirbuster|wpscan|hydra" access.log   # scanner (user-agent)
grep "<IP_attaccante>" access.log | awk '$9==200'                          # cosa ha avuto SUCCESSO
grep "POST" access.log | awk '{print $1, $7}' | sort | uniq -c | sort -rn | head   # brute force form
```
Splunk: query *brute force su form web* (§1) su `stream:http`

**2. Cerca webshell** · *Analysis* 🧪
```bash
find /var/www -type f \( -name "*.php" -o -name "*.jsp" \) -mtime -7 -ls
grep -rlE "eval\(|base64_decode\(|system\(|shell_exec\(|passthru\(|assert\(" /var/www
ps -ef --forest | grep -A3 www-data       # shell figlie del web server 🚩
```
```powershell
Get-ChildItem C:\inetpub\wwwroot -Recurse -Include *.aspx,*.ashx,*.asp | ? LastWriteTime -gt (Get-Date).AddDays(-7)
```
```splunk
index=* sourcetype=<SYSMON> EventCode=1 earliest=0
(ParentImage="*\\w3wp.exe" OR ParentImage="*\\httpd.exe" OR ParentImage="*\\tomcat*.exe")
(Image="*\\cmd.exe" OR Image="*\\powershell.exe") | table _time, Computer, ParentImage, CommandLine
```

**3. Blocca, bonifica, ripristina** · *Containment → Eradication → Recovery* 🏢
Blocco IP (WAF/firewall, `iptables -A INPUT -s <IP> -j DROP`) → se compromesso: server offline + trattalo come **B/B-bis** → rimuovi webshell → **patch** della vulnerabilità → rotazione credenziali DB/app → restore da versione pulita

---

### 📝 Template minimo di incident report
| Campo | Contenuto |
|---|---|
| Sommario | Cosa è successo in 3 righe (per il management) |
| Severity e stato | Critica/Alta/Media/Bassa · Aperto/Contenuto/Chiuso |
| Timeline | Evento per evento, `YYYY-MM-DD HH:MM:SS` + timezone |
| Asset e account coinvolti | Host, IP, utenti |
| Evidenze | File acquisiti + SHA256 + chi/quando (chain of custody) |
| IOC | Hash (SHA256), IP, domini, URL — **defangati** |
| MITRE ATT&CK | Tecniche osservate (§11) |
| Azioni svolte | Contenimento, eradicazione, recovery con orari |
| Root cause | Vettore iniziale e vulnerabilità/debolezza sfruttata |
| Raccomandazioni | Cosa cambiare per non ripeterlo |

---

## ✅ CHECKLIST FINALE PER OGNI RISPOSTA

- [ ] Il **formato** richiesto è rispettato? (`X.X.X.X` · `nome.ext, nome.ext` · `YYYY-MM-DD HH:MM:SS` · primi N caratteri)
- [ ] Hash: MD5 o SHA256? Maiuscolo o minuscolo?
- [ ] IOC: defangato o no?
- [ ] Timestamp: dal **campo del log** o dalla colonna del tool? (possono differire per timezone)
- [ ] Ho **copiato** il valore invece di riscriverlo a mano?
