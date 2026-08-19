# Digital Forensics Cheat Sheet

> Esame: 24h, 20 task pratici, open-book, soglia 70%.
> Questa cheat sheet è pensata per la *ricerca rapida* (Ctrl+F) durante i task.

---

## 0\. INDICE RAPIDO — "cosa uso per cosa"

|Devo fare...|Tool / Comando|
|-|-|
|Immagine disco / dump RAM|**FTK Imager** (`Create Disk Image` / `Capture Memory`), `dd`|
|Dump di un singolo processo (live)|**ProcDump** (`procdump.exe -ma PID`)|
|Triage rapido artefatti (live/remoto)|**KAPE** (`gkape.exe`)|
|Analisi memoria|**Volatility 2/3**, **Volatility Workbench** (GUI, solo Windows)|
|Analisi disco completa (case management)|**Autopsy** (motore: The Sleuth Kit)|
|Recuperare file cancellati da un `.img`|**Scalpel** (file carving)|
|Metadati file|**exiftool** (Linux), Proprietà→Dettagli (Win)|
|Prefetch|**PECmd.exe**|
|LNK / shortcut|**Windows File Analyzer**|
|Jump List|**JumpList Explorer**|
|Recycle Bin|**RBCmd** + **CSVQuickViewer**|
|Cronologia browser|**BHC + BHV** (Foxton), o KAPE|
|Hash|`Get-FileHash` (Win) / `sha256sum` `md5sum` `sha1sum` (Linux)|
|Decodifica/encoding|**CyberChef**|
|Steganografia|**steghide**, `cat`, **exiftool**, **StegCracker**|
|Crack hash password Linux|**unshadow** + **John The Ripper** / **hashcat**|

---

## 1\. FONDAMENTI (teoria minima da sapere)

### HDD

* **Platter** = disco rigido magnetico; più piatti sullo stesso **spindle**; 2 testine per piatto (un lato ciascuna)
* **Sector** = unità minima di storage. **512 byte** (tradizionale) / **4096 byte = 4 KiB** (moderno)

  * Struttura: *Header/ID area* + *Data area* (sync bytes + dati + **ECC**)
* **Cluster** = gruppo di settori, unità con cui il FS organizza i file. Ogni cluster ha un ID univoco
* **Slack Space** = spazio residuo in un cluster non riempito dal file corrente → **può contenere resti di file cancellati** = evidenza recuperabile

### SSD (rischi forensi)

|Meccanismo|Cosa fa|Impatto forense|
|-|-|-|
|**Garbage Collection**|Il controller sposta pagine valide e cancella blocchi non usati (background)|Può **distruggere evidenza** automaticamente|
|**TRIM**|Cancella **attivamente** i dati marcati come eliminati|Elimina ogni possibilità di recupero, anche parziale|
|**Wear Leveling**|Distribuisce scritture uniformemente|*Dynamic*: solo blocchi riscritti (usura non uniforme) · *Static*: sposta anche dati statici (più lento, più longevo)|

⚠️ **Azione su SSD sospetto**: **hard shutdown** (tenere premuto il tasto power) o **staccare la spina**.
❌ **MAI** spegnere via sistema operativo (possibili script anti-forensi).
⚠️ Ma prima valuta l'**evidenza volatile** (RAM) → vedi Order of Volatility.

### File System

|FS|Note chiave|
|-|-|
|**FAT16**|DOS/Win3.x, partizioni piccole; se la FAT si corrompe → dati inaccessibili|
|**FAT32**|32 bit per cluster. **File max 4 GB**, **partizione max 8 TB**. No crittografia/compressione/protezione blackout. Compatibilità universale|
|**NTFS**|Microsoft, **journaling**, **ACL**. Default da Win NT 3.1. Linux: driver **NTFS-3G** (R/W); macOS: **solo lettura** di default|
|**EXT3**|Linux, journaling (journal = log circolare → recovery veloce dopo crash)|
|**EXT4** (2008)|Max volume **1 exbibyte**, max file **16 tebibyte**, usa **extents** (meno frammentazione)|

Identificare il FS di un'immagine: FTK Imager → `File → Add Evidence Item → Image File`

---

## 2\. PRINCIPI LEGALI E PROCEDURALI

### Order of Volatility — RFC 3227 (IETF)

Raccogli **dal più volatile al meno volatile**:

1. **Registri e cache CPU** (cambiano costantemente)
2. **Memoria / RAM** (processi, connessioni, credenziali, chiavi crypto)
3. **Stato di rete** (ARP cache, routing table)
4. **Processi in esecuzione**
5. **Disco** (HDD/SSD) — se il sistema è offline **non è più volatile**
6. **Log remoti / centralizzati**
7. **Configurazione fisica / topologia / media offline** (meno volatile)

### ACPO — 4 Principi

1. **Non alterare** i dati originali che potrebbero essere prova
2. Se serve accedere all'originale → persona **competente**, capace di **spiegare in tribunale** azioni e implicazioni
3. **Traccia documentata** di tutte le azioni → un terzo indipendente deve poter **ripetere** e ottenere lo stesso risultato
4. Il **lead investigator** è responsabile del rispetto dei principi

### Chain of Custody

**2 componenti:**

1. **Integrità** → hash **prima** e **dopo** ogni manipolazione; almeno 2 algoritmi (MD5+SHA1) o **SHA256** da solo; **write blocker hardware** su prove fisiche
2. **Documentazione** → chi, quando, come, dove, per ogni passaggio

**Modulo CoC deve contenere:** descrizione prova, quando/dove acquisita o trasferita, da chi, contatti esaminatori, come è stata consultata/raccolta/archiviata.

**Archiviazione:** sacchetti antistatici (ESD) + sigilli anti-manomissione, **gabbia di Faraday** (blocco wireless), contenitore chiuso a chiave, sorveglianza in transito.

### Equipment (scena del crimine)

Workstation forense (**CAINE**, **DEFT**) · borse ESD sigillate · etichette · fotografie · braccialetti di messa a terra · **write blocker hardware** · dischi vuoti (**capacità > originale**) · Faraday box / phone jammer · write blocker specializzati (mobile, GPS, IoT) · flash drive con **EnCase / FTK / CSI Linux / mAcquisition**

**Write blocker: software** = a livello OS, specifico per quell'OS · **hardware** = a livello elettrico, indipendente dall'OS (**più efficace**)

### Evidence Destruction

|Metodo|Note|
|-|-|
|**Degaussing**|Campo magnetico → standard garantito. ⚠️ Solo media **magnetici** (non SSD)|
|**File Shredding**|Serve sovrascrittura reale. **DoD 5220.22-M** = 3 pass: ① zero+verify ② uno+verify ③ random+verify|
|**Physical Shredding**|Triturazione industriale|
|**Hydraulic Crusher**|Pressa \~**3.400 kg** perfora il disco|
|**Overwriting**|**Unico non distruttivo** → riuso hardware. Windows: **Diskpart**|

---

## 3\. ACQUISIZIONE

### FTK Imager

**Dump RAM:**

```
File → Capture Memory → destinazione → nome (es. memdump.mem) → Capture Memory
```

* Opzione *include pagefile* → prove aggiuntive
* Opzione *AD1* → formato proprietario FTK/AccessData

**Immagine disco:**

```
File → Create Disk Image
→ Source Evidence Type: Physical Drive   (Logical Drive / Image File / Contents of a Folder)
→ seleziona il drive corretto (controlla la dimensione!)
→ Evidence Item Information (compilare per CoC/ACPO)
→ Add → formato: .E01 (per EnCase/Autopsy) oppure Raw/dd (.img)
→ Image Fragment Size = 0 → file unico non segmentato
→ Finish → Start
```

Al termine FTK mostra **hash MD5/SHA1** originale vs copia → verifica integrità.

**Formati:** `.E01` (EnCase, con metadati) · `.img`/`.dd` (raw bit-per-bit) · `.mem`/`.dmp` (memoria) · `.AD1` (FTK custom)

**Setup fisico corretto (sempre):**

```
Disco sospetto → \\\[HARDWARE WRITE BLOCKER] → Workstation forense (FTK) → .img / disco vuoto
```

### dd (Linux)

```bash
sudo dd if=/dev/sdb of=/mnt/evidence/disk.dd bs=4M status=progress
sha256sum /mnt/evidence/disk.dd > disk.dd.sha256
```

`if` = input file (sorgente) · `of` = output file (destinazione) · **attenzione a non invertirli**

### ProcDump (dump di un singolo processo, live)

```powershell
Get-Process | findstr -I calc     # trova il PID
.\procdump.exe -ma 1688           # -ma = full memory dump del PID
```

Output: file `.dmp` analizzabile con Volatility.

### KAPE (triage rapido)

GUI = `gkape.exe` · CLI = `kape.exe` · deployabile via PowerShell su larga scala

**3 sezioni GUI:** *Targets* (cosa raccogliere) · *Modules* (cosa analizzare) · *Command line* (query generata)

**Workflow:**

```
1. Toggle "Use Target options"
2. Target source → drive/immagine (es. C:\)
3. Target destination → cartella output (creane una nuova, es. "output")
4. Targets → lupa/ricerca → seleziona (es. "browser" → Chrome, Chrome Extensions)
5. Execute
```

**Raccoglie:** Windows Event Log, log AV, metadati FS, registry, file cancellati, email, dati browser, RAM...

**Perché è utile:** gira **in parallelo** all'imaging completo → prove utilizzabili in minuti invece di ore/giorni.

**KAPE remoto (pattern del lab):** RDP → copia cartella KAPE via clipboard RDP → esegui gkape sull'host remoto → output in cartella locale → copia la cartella output indietro via clipboard.

### Live Forensics — perché

* RAM abbondante su OS 64-bit → **prove critiche spesso solo in RAM**
* Contrasta anti-forensics: **full disk encryption** (chiave estraibile dalla RAM), **Live CD** (nessuna traccia su disco), **cloud storage** (accessibile solo mentre online)
* Permette a un team centralizzato di operare **da remoto** su sedi senza personale forense

---

## 4\. HASHING E INTEGRITÀ

**Windows (PowerShell)**

```powershell
Get-FileHash <file>                      # default SHA256
Get-FileHash -Algorithm MD5 <file>
Get-FileHash -Algorithm SHA1 <file>
```

**Linux**

```bash
sha256sum <file>
md5sum <file>
sha1sum <file>
echo -n "testo" | sha256sum              # hash di una stringa (-n = no newline!)
```

**Standard attuale: SHA256.** MD5 e SHA1 deprecati per **hash collision** (due input diversi → stesso hash).

**Workflow integrità:** hash originale → copia bit-per-bit → hash copia → confronto → se coincidono, copia forensicamente valida → **lavora sulla copia, mai sull'originale**.

**Data representation** (utile per identificare/decodificare): Base64, Hexadecimal, Octal, ASCII, Binary → **CyberChef**.

---

## 5\. FILE CARVING, METADATI, STEGANOGRAFIA

### Cosa è un `.img`

Copia **bit-per-bit** dell'intero disco: stream grezzo di **tutti** i byte, incluse le zone marcate "libere" dal file system. Un file cancellato non è distrutto — il SO segna solo lo spazio come riutilizzabile → i byte restano fino a sovrascrittura.

### File carving = come funziona

Scansione byte-per-byte alla ricerca di **header** e **footer** noti di un tipo di file, poi "ritaglio" di ciò che sta in mezzo.
Esempio JPEG: header `\xff\xd8\xff\xe0` → footer `\xff\xd9`

### Scalpel

```bash
scalpel -o <output\\\_dir> <disk\\\_image.img>
```

* `-o` → cartella output. **Deve essere vuota o non esistente** (Scalpel la crea)
* `-b` → (opzionale) carve anche senza footer trovato entro la dimensione massima (compat mode Foremost)

**Workflow obbligatorio:**

```bash
sudo nano /etc/scalpel/scalpel.conf   # 1. apri il config
                                      # 2. trova la riga del tipo file (es. jpg, png, pdf)
                                      # 3. RIMUOVI IL "#" iniziale (righe con # sono ignorate)
                                      # 4. Ctrl+O, Invio, Ctrl+X
rm -rf ScalpelOutput                  # 5. se la cartella output esiste già
scalpel -o ScalpelOutput carve1.img   # 6. lancia
ls -R ScalpelOutput                   # 7. guarda i risultati
md5sum ScalpelOutput/jpg-0-0/\\\*.jpg    # 8. hash del file recuperato
```

Output: sottocartelle per tipo (`jpg-0-0/`, `png-0-0/`...) + **`audit.txt`** (log dell'attività).

Profili **custom**: si creano nel `.conf` definendo estensione + header + footer (istruzioni in cima al file).

### chown (permessi — spesso necessario nei lab)

```bash
chown <nuovo\\\_owner> <file>           # es. chown ubuntu q3.conf
chown <owner>:<gruppo> <file>
ls -l <file>                         # verifica
sudo chown ubuntu q3.conf            # se non hai permessi
```

### Metadati

```bash
exiftool <file>                      # Linux/Kali — tool principale
sudo apt-get install exiftool        # se non installato
ls -lisap <file>                     # info base
stat <file>                          # timestamp dettagliati
```

Windows: click destro → Proprietà → **Dettagli**

### Steganografia

**Metodo 1 — concatenazione:**

```bash
cat Dog.jpg secret.zip > Dog2.jpg    # nascondi
unzip Dog2.jpg                       # estrai
```

**Metodo 2 — steghide:**

```bash
steghide embed -cf Dog.jpg -ef secret.txt    # -cf = cover file, -ef = embed file
steghide extract -sf Dog.jpg                 # -sf = steganography file
steghide info Dog.jpg                        # verifica presenza dati nascosti
```

Password: Invio 2 volte = nessuna password. Se protetto → **StegCracker** per bruteforce.

**Metodo 3 — metadati:**

```bash
exiftool -Comment="Super Sneaky!" Dog.jpg    # scrivi (crea Dog.jpg\\\_original come backup)
exiftool Dog.jpg                             # leggi
```

⚠️ La stringa nascosta può essere ulteriormente codificata in **Base64/Hex** → passala a CyberChef.

---

## 6\. WINDOWS INVESTIGATIONS

### Tabella path artefatti (la più importante da avere sotto mano)

|Artefatto|Percorso|
|-|-|
|**LNK / shortcut**|`C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\`|
|**Prefetch**|`C:\Windows\Prefetch\\\\*.pf`|
|**Jump List (automatic)**|`C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`|
|**Jump List (custom)**|`C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations`|
|**Event Logs**|`C:\Windows\System32\winevt\Logs\` (Security, System, Application...)|
|**Recycle Bin**|`C:\$Recycle.Bin\<SID>\`|
|**Registry SYSTEM hive**|`C:\Windows\System32\config\SYSTEM`|
|**Registry SAM / SOFTWARE / SECURITY**|`C:\Windows\System32\config\`|
|**NTUSER.DAT** (registry utente)|`C:\Users\<user>\NTUSER.DAT`|
|**Amcache** (exec evidence)|`C:\Windows\AppCompat\Programs\Amcache.hve`|
|**$MFT** (Master File Table)|root del volume NTFS|
|**Pagefile**|`C:\pagefile.sys`|
|**Hibernation file**|`C:\hiberfil.sys`|
|**Chrome**|`C:\Users\<user>\AppData\Local\Google\Chrome\User Data`|
|**Firefox**|`C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles`|

### Artefatti di esecuzione programmi

|Artefatto|Cosa dice|Tool|
|-|-|-|
|**LNK**|Path del file collegato, created/modified/accessed, dimensione|**Windows File Analyzer** (`File → Analyse shortcuts`)|
|**Prefetch**|Nome app, path exe, **quante volte eseguito**, last run, created|**PECmd.exe**|
|**Jump List**|App pinnate in taskbar, file aperti (nome specifico), timestamp, **AppID**|**JumpList Explorer**|

**PECmd.exe:**

```powershell
.\PECmd.exe -f "C:\path\file.pf"                       # singolo file
.\PECmd.exe -d "C:\Windows\Prefetch"                   # intera directory (ricorsivo)
.\PECmd.exe -d "C:\path\Prefetch" -k "stringa"         # -k evidenzia in rosso le righe con la stringa
.\PECmd.exe -d "C:\path\Prefetch" --csv "C:\output"    # export CSV
```

⚠️ **Non mettere `\` prima delle virgolette di chiusura** → `"...\Prefetch\"` rompe il parsing. Usa `"...\Prefetch"`.

### Logon Events (Security log)

|Event ID|Significato|
|-|-|
|**4624**|Logon **riuscito**|
|**4625**|Logon **fallito**|
|**4634**|**Logoff**|
|**4672**|**Special Logon** (privilegi amministrativi)|
|**4688**|Process creation|
|**4698**|Scheduled task creato (**persistenza**)|
|**4720**|Account utente creato (**persistenza**)|
|**7045**|Nuovo servizio installato *(System log)* — **persistenza**|
|**1102**|**Audit log cancellato** (anti-forensics!)|
|**4104**|PowerShell **script block logging** *(log PowerShell/Operational)*|

**Logon Type (campo in 4624):**

|#|Tipo|
|-|-|
|2|**Interactive** (logon fisico alla macchina)|
|3|**Network** (accesso via rete)|
|4|Batch (job automatico)|
|5|Service (avviato dal service controller)|
|6|Proxy (non usato in NT/2000)|
|7|**Unlock** (sblocco workstation, sessione preesistente)|
|8|NetworkCleartext (credenziali in chiaro)|
|9|NewCredentials (`RunAs /netonly`)|

**Campi chiave 4624/4672:** *Subject* (account) · *Security ID* (computer\\username) · **Logon ID** (traccia la sessione — stesso valore nel 4634 corrispondente → **durata sessione**) · *Logged timestamp*

**Codici errore 4625 (Failed Logon):**

|Codice|Significato|
|-|-|
|`0xC0000064`|Utente **non esiste**|
|`0xC000006A`|Password **errata**|
|`0xC000006C`|Password policy non rispettata|
|`0xC000006D`|Bad username|
|`0xC000006E`|Restrizione account|
|`0xC000006F`|Restrizione **oraria**|
|`0xC0000070`|Restrizione **workstation di origine**|
|`0xC0000071`|Password **scaduta**|
|`0xC0000072`|Account **disabilitato**|
|`0xC000009A`|Risorse di sistema insufficienti|
|`0xC0000193`|Account **scaduto**|
|`0xC0000224`|Deve cambiare password al primo accesso|
|`0xC0000234`|Account **bloccato** automaticamente|

🚩 **Pattern sospetti:** volume alto di tentativi su account **disabilitato** (`0xC0000072`) o su **username inesistente** (`0xC000006D`) → bruteforce / user enumeration.

### Recycle Bin

Da Windows Vista, ogni file cancellato genera **2 file**:

* **`$R` + stringa** → **contenuto reale** del file
* **`$I` + stessa stringa** → **metadati** (nome originale, path, dimensione, timestamp cancellazione)

```cmd
cd C:\$Recycle.Bin
dir /a                                          :: /a mostra cartelle nascoste
wmic useraccount get name,SID                   :: mappa SID → username
```

PowerShell alternativo se `wmic` è deprecato:

```powershell
Get-CimInstance Win32\\\_UserAccount | Select-Object Name, SID
```

**RBCmd:**

```cmd
RBCmd.exe -f $I1UOZ51.xlsx                                  :: singolo file $I
RBCmd.exe -d . --csv "C:\Users\<user>\Desktop\RBCmdOutput"  :: directory + export CSV
```

* Da `C:\$Recycle.Bin` con `-d .` → scansione **ricorsiva di tutti i SID** (tutti gli utenti)
* ⚠️ **Serve CMD/PowerShell come Amministratore**, altrimenti "Administrator privileges not found! / Found 0 files"
* ⚠️ Se l'exe è in un'altra cartella, usa il **path assoluto senza `.\` davanti**
* Leggi il CSV con **CSVQuickViewer**

⚠️ Se il Recycle Bin è stato **svuotato** l'artefatto è perso → si passa al **file carving** sui dati non allocati.

### Browser

**Metodo 1 — KAPE:** Target `C:\` → abilita Chrome, Firefox, Edge → Execute

**Metodo 2 — BHC + BHV (Foxton Forensics):**

```
1. Browser History Capturer → seleziona User Profile → Capture (output: cartella "Capture")
2. Browser History Viewer → File → Load History
   → "Load history captured using the Browser History Capturer tool" → seleziona "Capture" → Load
```

⚠️ **BHV da solo fallisce su Edge** anche da admin → serve **BHC** prima.

**BHV — 3 pannelli:** ① *Website History* / *Cached Images* / *Cached Web Pages* — ② visite per mese — ③ filtri (keyword, data, browser)
*Cached Web Pages* → **rendering visivo** della pagina come l'ha vista l'utente.

### Memoria su disco

|File|Note|
|-|-|
|**pagefile.sys**|Windows, file **contiguo** in root, dati RAM meno usati. Nascosto, non cancellare, spostabile su altro disco|
|**hiberfil.sys**|Windows (da Win2000), **copia completa della RAM** al momento dell'ibernazione → il più ricco, senza tool di dumping|
|**swap**|Linux, tradizionalmente **partizione** (non file)|

Linux swap:

```bash
free -h                              # spazio swap totale/usato/libero
swapon --show                        # è file o partizione?
sudo fallocate -l 2G /swapfile       # crea swap file (swap va prima disabilitato)
```

**Swappiness**: 0–100, default **60** (0 = server, 100 = desktop)

---

## 7\. LINUX INVESTIGATIONS

### Account

|File|Contenuto|Permessi|
|-|-|-|
|`/etc/passwd`|username, UID, GID, home dir, login shell. Password = solo `x`|Lettura: **tutti** · Scrittura: solo root|
|`/etc/shadow`|**password hashate** + scadenze account/password|**Solo root**|

```bash
cat /etc/passwd
sudo cat /etc/shadow
sudo unshadow /etc/passwd /etc/shadow > combined.txt   # combina i due file
john combined.txt                                       # crack con John The Ripper
```

🚩 **Cosa cercare:** account "extra" mascherato da service account (**backdoor/persistenza**), UID 0 duplicati, shell valida su account di servizio.

### Log

|File|Contenuto|
|-|-|
|`/var/log/auth.log`|Autenticazione, login utenti|
|`/var/log/secure`|Auth/authz (**sshd**, inclusi fallimenti) — RHEL-based|
|`/var/log/btmp`|Tentativi di login **falliti**|
|`/var/log/faillog`|Login falliti (per utente)|
|`/var/log/cron`|Job cron eseguiti → 🚩 **abusabili per persistenza**|
|`/var/log/dpkg.log`|Installazione/rimozione pacchetti|
|`/var/log/apache2/access.log`|Richieste al web server|

### Software installato (Debian-based)

```bash
cat /var/lib/dpkg/status | grep Package > packages.txt
```

🚩 Cerca tool offensivi/sospetti: `nmap`, `nikto`, `steghide`, `hashcat`, `netcat`...

### Apache access.log — parsing

```
52.50.100.106 - SBTUser \\\[27/Jul/2020:15:30:00 -0600] "GET /logo.png HTTP/1.1" 200 379
     IP        -  userID          timestamp          metodo+risorsa        code size
```

Status code: `200` OK · `404` not found · `403` forbidden · `500` server error
🚩 Cerca: user-agent anomali (scanner), sequenze di 404 (**vulnerability scanning**), path traversal, richieste a `/admin`, `.php` sospetti

### File utente

```bash
ls -a                    # SEMPRE -a → mostra i file nascosti (che iniziano con ".")
cat \\\~/.bash\\\_history      # comandi eseguiti dall'utente
history                  # history della sessione corrente
```

⚠️ Due limiti di `.bash\\\_history`:

* `history -c` cancella la history **di sessione**, ma il file su disco può conservare i comandi precedenti
* I comandi vengono scritti nel file **solo alla chiusura del terminale** → una sessione aperta può non comparire

**Clear files da controllare:** Desktop, Downloads, Documents, Music, Pictures, Public, Templates, Videos, **Trash**

---

## 8\. MEMORY ANALYSIS — VOLATILITY

### Volatility 2 (profilo obbligatorio)

```bash
# STEP 1 — sempre per primo: identifica il profilo
volatility -f memdump.mem imageinfo
# output: Suggested Profile(s): Win7SP1x64 ... + KDBG address + n. processori

# STEP 2 — ogni comando successivo richiede --profile
volatility -f memdump.mem --profile=Win7SP1x64 <plugin>
```

⚠️ Plugin **case sensitive**. Path con spazi → usa le virgolette: `-f "/path/con spazi/memdump1.mem"` (o `\ ` per lo spazio)

|Plugin|Funzione|
|-|-|
|`imageinfo`|Profilo suggerito, KDBG, n. processori, service pack|
|`pslist`|Lista processi|
|`pstree`|Processi ad **albero** (relazioni parent-child)|
|`psscan`|Processi **nascosti** (scansione pool)|
|`psxview`|pslist + psscan combinati (attesi + nascosti)|
|`cmdline -p PID`|**Argomenti da riga di comando** del processo|
|`procdump -p PID -D <dir>`|Estrae l'eseguibile del processo|
|`memdump -p PID -D <dir>`|Estrae lo spazio di memoria del processo|
|`dlllist -p PID`|DLL caricate dal processo|
|`netscan`|Connessioni di rete attive/chiuse|
|`connections` / `sockets`|Connessioni (profili XP/2003)|
|`filescan`|Tutti i file citati nel dump|
|`dumpfiles -n --dump-dir=./`|Estrae file dal dump|
|`hivelist`|Registry hive in memoria|
|`hashdump`|Hash password|
|`iehistory`|Cronologia Internet Explorer|
|`timeliner`|Timeline cronologica degli eventi|
|`malfind`|Regioni di memoria sospette / **code injection**|
|`svcscan`|Servizi|
|`clipboard`|Contenuto clipboard|
|`screenshot`|Screenshot pseudo-grafici|
|`consoles` / `cmdscan`|Comandi digitati in CMD|
|`yarascan`|Scan con regole **YARA**|

**Combo utili:**

```bash
# contare occorrenze di un processo
volatility -f mem.mem --profile=Win7SP1x64 pslist | grep "svchost.exe" | wc -l

# estrarre e hashare un processo
volatility -f mem.mem --profile=Win7SP1x64 procdump -p 2940 -D ./
md5sum executable.2940.exe
```

### Volatility 3 (nessun profilo)

```bash
python3 vol.py -f memory.raw windows.info           # info OS (sostituisce imageinfo)
python3 vol.py -f memory.raw windows.pslist
python3 vol.py -f memory.raw windows.pstree
python3 vol.py -f memory.raw windows.psscan
python3 vol.py -f memory.raw windows.cmdline
python3 vol.py -f memory.raw windows.netscan
python3 vol.py -f memory.raw windows.malfind
python3 vol.py -f memory.raw windows.svcscan
python3 vol.py -f memory.raw windows.registry.hivelist
python3 vol.py -f memory.raw windows.filescan
python3 vol.py -f memory.raw windows.dumpfiles
```

Funziona anche la forma lunga: `windows.pslist.PsList`, `windows.info.Info`, `windows.netscan.NetScan`, `windows.malfind.Malfind`

**Differenze chiave Vol2 → Vol3:**

* ❌ **Niente `--profile`** → symbol tables automatiche
* Plugin **prefissati per OS**: `pstree` → `windows.pstree` / `linux.pstree` / `mac.pstree`
* Vol2: 2011, EOL agosto 2021 · Vol3: 2020, rewrite completo

### Volatility Workbench

GUI per Volatility 3 — gratuita, **solo Windows**. Niente Python, dropdown comandi con descrizioni, salva config in `.CFG`, copy/save output, timestamp comandi.

```
Browse Image → seleziona .mem → scegli Platform → scegli comando → Run → Copy / Save to file
```

### 🔍 Metodologia di indagine su memoria (il "come pensare")

1. `imageinfo` / `windows.info` → profilo e contesto
2. `pslist` + `pstree` → **relazioni parent-child anomale**
🚩 Esempi: `svchost.exe` → `cmd.exe` → `ping.exe` · `WINWORD.EXE` → `powershell.exe` · processo con parent inesistente
3. `psscan` vs `pslist` → **la differenza rivela processi nascosti** (rootkit/malware)
4. `cmdline -p PID` → cosa stava effettivamente eseguendo
5. `netscan` → 🚩 **Foreign Address pubblici da processi che non dovrebbero fare rete** (Word, Excel, Notepad su porta 80/443 = macro malevola che scarica payload)
6. `malfind` → code injection
7. `procdump -p PID` + hash → estrai l'artefatto come IOC
8. `filescan` / `dumpfiles` → recupera file di interesse
9. `timeliner` → ricostruisci la sequenza

> *Regola d'oro:* cerca il *comportamento anomalo*, non il nome sospetto. Un `svchost.exe` che fa `ping` o un Word che apre una connessione HTTP verso un IP pubblico sono i veri red flag.

---

## 9\. DISK ANALYSIS — AUTOPSY

Motore: **The Sleuth Kit**. Registry parsing: **RegRipper**. Preinstallato su Kali, gratis su Windows.
FS supportati: NTFS, FAT12/16/32/ExFAT, HFS+, ISO9660, Ext2/3/4, Yaffs2, UFS

### Setup caso

```
Create New Case → nome + Base Directory (CARTELLA VUOTA) → (opz. metadata) → Next
Add Data Source → host default → "Disk Image or VM File" → Browse (.E01 / .img / .dd) → Next
Ingest Modules → target "All Files, Directories, and Unallocated Space"
```

**Moduli utili:** Recent Activity · File Type Identification · Embedded File Extractor · Exif Parser · Email Parser · Encryption Detection · Keyword Search · Interesting Files
⚠️ I nomi dei moduli variano tra versioni. L'ingest può richiedere **10+ minuti** — i contatori nel pannello sinistro crescono mentre lavora.

### Dove trovare cosa (mappa risposte → sezione)

|Cerco...|Sezione|
|-|-|
|**OS e versione**|Data Artifacts → **Operating System Information** → colonna `Program Name`|
|**Hostname**|Data Artifacts → Operating System Information → colonna `Name`|
|**Siti visitati**|Web History (data, titolo, URL, browser)|
|**File scaricati**|Web Downloads (match su `Date Accessed`, poi colonna `URL`)|
|**File aperti di recente / path completo**|**Recent Documents** (basato su **LNK**: `Pier.lnk` → path di `Pier.jpg`)|
|**File cancellati**|Recycle Bin (path, utente, data cancellazione)|
|**Software installato**|Installed Programs (nome + data installazione)|
|**Email**|Accounts → Email (formato **MBOX**)|
|**Utenti locali e last access**|**OS Accounts**|
|**Struttura file / dimensione cartelle**|Doppio click su **vol2** (la partizione più grande) → filesystem read-only navigabile|
|**Partizioni, spazio allocato/non allocato**|Click sul nome immagine → **Partition Table** nel pannello destro|

**Export:** right-click su **qualsiasi** file → Export (non solo Recycle Bin). Email → aprire con Thunderbird/Outlook o **editor di testo**.

**Feature extra:** Keyword Search (testo + regex) · Timeline Analysis · Tags (`suspicious`, `bookmark`) · Unicode Strings Extraction (spazio non allocato) · **File Type Detection con extension mismatch** · Android support (SMS, chiamate, contatti)

> 💡 Pattern ricorrente nei lab Autopsy: la domanda è quasi sempre un *match su timestamp* → trova la riga con la data/ora indicata, poi leggi la colonna richiesta *sulla stessa riga*.

---

## 10\. ERRORI COMUNI NEI LAB (troubleshooting)

|Errore / sintomo|Causa|Fix|
|-|-|-|
|Scalpel: *"configuration file didn't specify any file types to carve"*|Tutte le righe del `.conf` sono commentate|`sudo nano /etc/scalpel/scalpel.conf` → rimuovi `#` dal tipo file|
|Scalpel: errore su cartella output|La cartella esiste e non è vuota|`rm -rf <output\\\_dir>` oppure usa un nome nuovo|
|PECmd: *"Option '-d' parse error"*|Backslash prima delle virgolette: `"...\Prefetch\"`|Togli il `\` finale: `"...\Prefetch"`|
|RBCmd: *"Administrator privileges not found! Found 0 files"*|CMD non elevato|Riapri CMD/PowerShell **come Amministratore**|
|*"The filename, directory name, or volume label syntax is incorrect"*|`.\` combinato con un path assoluto|Path assoluto **senza** `.\`, oppure `.\exe` solo se sei nella cartella dell'exe|
|Volatility non legge il `.mem`|Spazi nel path|Racchiudi il path in `"..."` o usa `\ ` per lo spazio|
|Volatility: plugin non riconosciuto|Case sensitive / manca `--profile`|Minuscolo esatto + `--profile=X` in ogni comando (solo Vol2)|
|Non trovo file in una cartella Linux|File nascosti|`ls -a` invece di `ls`|
|Permission denied su file/cartella|Ownership|`sudo chown <user> <file>` o prefissa `sudo`|
|Cartelle non visibili in `C:\$Recycle.Bin`|Cartelle di sistema nascoste|`dir /a`|
|BHV non estrae dati Edge|Limite noto di BHV|Usa **BHC** prima, poi importa in BHV|

---

## 11\. WINDOWS vs LINUX — colpo d'occhio

|Aspetto|Windows|Linux|
|-|-|-|
|**Logging**|Event Logs (4624/4625/4634/4672/4688/7045/1102)|`auth.log`, `secure`, `btmp`, `faillog`, syslog/journal|
|**Artefatti utente**|Registry, Prefetch, Jump List, LNK, Recycle Bin|`.bash\\\_history`, `/etc/passwd`, file nascosti (`.`)|
|**Browser**|BHC/BHV, path standard|Estrazione manuale, path variabili|
|**Pacchetti**|Programs and Features, MSI log, Amcache|`/var/lib/dpkg/status`, `/var/log/dpkg.log`|
|**Memoria su disco**|`hiberfil.sys`, `pagefile.sys`|swap partition/file, **LiME** per acquisizione|
|**Tool tipici**|RBCmd, PECmd, JumpList Explorer, Windows File Analyzer, KAPE|exiftool, scalpel, steghide, dd|

---

## 12\. CHECKLIST PRE-TASK (30 secondi prima di iniziare)

* \[ ] Che tipo di evidenza ho? (`.mem` / `.img` / `.E01` / filesystem live / log)
* \[ ] Il tool giusto è nella tabella §0?
* \[ ] Se è memoria → `imageinfo` **prima di tutto** (Vol2) o `windows.info` (Vol3)
* \[ ] Se è disco → Autopsy con ingest, oppure Scalpel se devo carvare file cancellati
* \[ ] Se è live Windows → serve **CMD/PowerShell come Amministratore**?
* \[ ] Il path ha **spazi**? → virgolette
* \[ ] La cartella output esiste già? → cancellala o cambiala
* \[ ] La risposta richiede un **hash**? → `Get-FileHash` / `md5sum` (attento al **formato richiesto**: MD5 vs SHA256, maiuscolo/minuscolo, primi N caratteri)
* \[ ] Il formato della risposta è specificato? (es. `YYYY-MM-DD HH:MM:SS`, `nome.ext, nome.ext`) → **rispettalo esattamente**

---

*Fonti: materiale corso BTL1 (Digital Forensics domain) + cheat sheet pubbliche consolidate.*

