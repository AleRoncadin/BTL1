# BTL1 — LAB CHEAT SHEET (solo pratica)

> Nessuna teoria. Solo ciò che **digiti, clicchi o consulti** durante un task.
> ⚠️ **Nel lab d'esame non c'è internet, tranne Splunk.** OSINT (VirusTotal, WHOIS, CVE) dal **tuo** browser.

---

## 🧭 ROUTING — "Cosa ho in mano?"

| Ho... | Vai a | Tool |
|---|---|---|
| `.pcap` / `.pcapng` / `.cap` | §2 | Wireshark |
| `.mem` / `.dmp` / `.raw` (memoria) | §3 | Volatility |
| `.E01` / `.img` / `.dd` (disco) | §4 | Autopsy · Scalpel |
| `.evtx` (event log) | §5 | DeepBlueCLI · Event Viewer |
| Sistema Windows **live** | §6 | CMD / PowerShell |
| Sistema Linux **live** o immagine | §7 | comandi Linux |
| Log dentro Splunk | §1 | SPL |
| `.eml` / email | §8 | CyberChef · tool online |
| Un file qualsiasi (hash/metadati) | §9 | Get-FileHash · exiftool |
| Un IOC da arricchire | §10 | MISP · OSINT |

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
md5sum executable.2940.exe
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
| 8 | CreateRemoteThread (injection) |
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

## ✅ CHECKLIST FINALE PER OGNI RISPOSTA

- [ ] Il **formato** richiesto è rispettato? (`X.X.X.X` · `nome.ext, nome.ext` · `YYYY-MM-DD HH:MM:SS` · primi N caratteri)
- [ ] Hash: MD5 o SHA256? Maiuscolo o minuscolo?
- [ ] IOC: defangato o no?
- [ ] Timestamp: dal **campo del log** o dalla colonna del tool? (possono differire per timezone)
- [ ] Ho **copiato** il valore invece di riscriverlo a mano?
