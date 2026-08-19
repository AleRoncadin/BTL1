# Phishing Analysis

> Esame: 24h, 20 task pratici, open-book, soglia 70%.
> Pensata per la **ricerca rapida** (Ctrl+F) durante i task.
> ⚠️ **Regola d'oro:** analizza le email di phishing **solo in VM o su un sistema dedicato "sporco"** — mai sulla macchina di produzione.

---

## 0. INDICE RAPIDO — "cosa uso per cosa"

| Devo fare... | Tool |
|---|---|
| Decodificare body Base64 | **CyberChef** → `From Base64` |
| Defangare IOC per il report | **CyberChef** → `Defang URL` / `Defang IP Addresses` |
| Risolvere URL abbreviato **senza cliccare** | **WannaBrowser** (redirect chain + status code + Location) |
| Screenshot pagina senza visitarla | **URL2PNG**, **URLScan.io** |
| Reputazione URL / dominio | **VirusTotal**, **URLScan.io**, **URLhaus**, **PhishTank** |
| Reputazione IP | **AbuseIPDB**, VirusTotal |
| Reputazione file / hash | **VirusTotal**, **Cisco Talos File Reputation** |
| Sandbox malware (dinamica) | **Hybrid Analysis**, **Any.run**, **Joe Sandbox**, VirusTotal |
| Info registrazione dominio | **WHOIS** (età dominio!), MxToolbox |
| Reverse DNS lookup | `nslookup <IP>` (Win) / `dig -x <IP>` (Linux), **MxToolbox** |
| Hash di un file | `Get-FileHash` (Win) / `sha256sum` (Linux) |
| Automazione completa artefatti | **PhishTool** (a pagamento / community) |
| Simulazioni phishing (training) | **GoPhish** (OSS), Sophos Phish Threat, Phish Insight, PhishingBox |

---

## 1. FONDAMENTI EMAIL

### Protocolli
| Protocollo | Ruolo | Porte |
|---|---|---|
| **SMTP** | **Trasporto** email tra server (invio). Non serve per leggere | **25** (default), **587** (submission + TLS, standard moderno), 465 (SMTPS legacy) |
| **POP3** | **Scarica** le email sul dispositivo locale e le **cancella dal server** | 110, 995 (SSL) |
| **IMAP** | Le email **restano sul server**, lette da lì | 143, 993 (SSL) |

| | POP3 | IMAP |
|---|---|---|
| Email salvate su | Dispositivo locale | **Server** |
| Accesso multi-device | ❌ | ✅ |
| Offline | ✅ | Solo se scaricate |
| Stato | Quasi obsoleto | Standard moderno |

### Flow completo di una email
```
1. Mittente scrive nel client
2. Client → SMTP server del mittente
3. SMTP server interroga il DNS: "dov'è dominio-destinatario.com?"  (record MX)
4. DNS risponde con l'IP del mail server di destinazione
5. Email viaggia in internet (possibili più SMTP relay = più hop "Received")
6. Arriva all'SMTP server del destinatario
7. Trasferita via SMTP al server POP3/IMAP
8. Destinatario legge dal proprio client via POP3 o IMAP
```
**Webmail** = accesso via browser (Gmail, Outlook, Yahoo). Pro: nessun client, accesso da ovunque. Contro: richiede connessione.

**MTA (Mail Transfer Agent)** = ogni server intermedio che inoltra l'email; **ogni MTA aggiunge un header `Received`**.

---

## 2. ANATOMIA DI UNA EMAIL

### Header — campi obbligatori
| Campo | Contenuto |
|---|---|
| `From` | Indirizzo mittente |
| `To` | Indirizzo destinatario |
| `Date` | Data di invio |

### Header — campi chiave per l'analisi
| Campo | Significato / uso investigativo |
|---|---|
| `Received` | Info sui server intermedi + timestamp di ogni hop. 📍 **Leggere dal BASSO verso l'ALTO** → il più in basso è l'**origine reale** |
| `Reply-To` | Dove finiscono le risposte. 🚩 **Se ≠ From = red flag classico** |
| `Subject` | Oggetto — usabile per bloccare/cercare l'intera campagna |
| `Message-ID` | Identificatore univoco — cercalo nei log per correlare la campagna |
| `X-Sender-IP` / `X-Originating-IP` | **IP reale del server di invio** → reputazione + geolocalizzazione |
| `Authentication-Results` | Esito **SPF / DKIM / DMARC** in un colpo d'occhio |
| `X-Spam-Status` | Verdetto dell'antispam (es. `YES`/`NO`) |
| `Content-Transfer-Encoding` | Se `base64` → il body è codificato, va decodificato |

**X-Headers** = header custom con prefisso `X-`, aggiunti da software specifici (antispam, gateway, client).

### ⚠️ Gli header NON sono affidabili
I valori possono essere **modificati liberamente**. Un attaccante può scrivere `contact@amazon.co.uk` nel `From` senza avere nulla a che fare con Amazon. È esattamente il motivo per cui esistono **SPF, DKIM, DMARC**.

### Body
Testo puro oppure **HTML** (styling, immagini, hyperlink).
Se `Content-Transfer-Encoding: base64` → il contenuto è codificato (compatibilità di trasporto, ma anche **ostacolo deliberato all'analisi**).

**Workflow decodifica:**
```
1. Apri il .eml grezzo in un editor di testo
2. Trova "Content-Transfer-Encoding: base64"
3. Copia il blocco codificato
4. CyberChef → "From Base64"
5. Ottieni l'HTML in chiaro → ispeziona i veri link, tag nascosti, markup
```

### Mappa visiva
```
─────────────────────────────────────
HEADER
From: contact@amazon.co.uk        ← può essere falso
To: victim@company.com
Date: 03 Jul 2026
Reply-To: attacker@evil.com       ← 🚩 RED FLAG
Received: [hop3] ← [hop2] ← [hop1]  ← leggi dal basso = origine reale
Authentication-Results: spf=fail  ← 🚩
X-Spam-Status: NO
─────────────────────────────────────
BODY
Content-Transfer-Encoding: base64 ← da decodificare
[contenuto...]
─────────────────────────────────────
```

### Tag HTML utili da riconoscere
| Tag | Funzione |
|---|---|
| `<a href="...">testo</a>` | **Anchor/link** — `href` = destinazione reale, il testo visibile può dire qualsiasi cosa |
| `<table>` | Layout/struttura dell'email |
| `<b>` `<i>` `<u>` | Grassetto / corsivo / sottolineato |
| `<img src="...">` | Immagine — se remota, potenziale **tracking pixel** |

---

## 3. AUTENTICAZIONE EMAIL — SPF / DKIM / DMARC

| | Domanda a cui risponde | Come funziona | Dove sta |
|---|---|---|---|
| **SPF** | *"Chi può spedire per il mio dominio?"* | Lista di server autorizzati. Server non in lista → **SPF fail** = probabile spoofing | Record **DNS TXT** |
| **DKIM** | *"Il contenuto è stato manomesso?"* | **Firma crittografica** applicata dal server mittente; il destinatario verifica con la **chiave pubblica** nel DNS | Firma nell'header + chiave pubblica nel DNS |
| **DMARC** | *"Cosa faccio se SPF/DKIM falliscono?"* | **Policy di decisione** + reporting | Record DNS TXT (`_dmarc.dominio`) |

**Esempio SPF:**
```
v=spf1 a: include:mailgun.org include:protection.outlook.com -all
```
→ solo Mailgun e Outlook autorizzati. `-all` = **tutto il resto è falso** (hard fail).
*(`~all` = soft fail, `?all` = neutral)*

**Esempio DMARC:**
```
v=DMARC1; p=quarantine; rua=mailto:contact@securityblue.team
```
| Policy | Effetto |
|---|---|
| `p=none` | Solo **monitoring**, nessuna azione |
| `p=quarantine` | Manda in **spam** |
| `p=reject` | **Blocca** completamente l'email |

`rua=` → indirizzo a cui arrivano i report aggregati (quante volte qualcuno ha provato a spoofare il dominio).

**Flusso di verifica:**
```
Email ricevuta
 ├─ SPF check   → il server mittente è autorizzato?
 ├─ DKIM check  → la firma è valida e il contenuto integro?
 └─ DMARC       → se uno o entrambi falliscono → none / quarantine / reject
```

⚠️ **SMTP per design non verifica il mittente** → è la debolezza strutturale che SPF/DKIM/DMARC coprono.

⚠️ **SPF/DKIM/DMARC tutti PASS ≠ email legittima.** Significa solo che il mittente è *davvero* quel dominio. Un attaccante che usa un dominio **typosquat proprio** passa tutti i controlli.

---

## 4. GLOSSARIO E TIPI DI PHISHING

### Concetti base
- **IOC (Indicator of Compromise)** = intelligence da attività malevola (hash, IP C2, domini) → condivisibile per blocklist e threat exposure check
- **Artifact** = pezzo di informazione rilevante estratto da email/sito/file
- **File Hash** = stringa univoca da algoritmo di hashing. **Standard: SHA256** (MD5/SHA1 soffrono di **hash collision**)

### Tipi di attacco
| Termine | Descrizione |
|---|---|
| **Recon Phishing** | Verifica se la mailbox è attiva / ottiene una risposta — ricognizione per attacchi futuri |
| **Credential Harvester** | Link → pagina di login falsa che imita un brand noto |
| **Vishing** | **Voice** phishing — social engineering via **telefonata** |
| **Smishing** | **SMS** phishing |
| **Whaling** | Phishing mirato al **C-level** (CEO/CFO/COO) |
| **Spear Phishing** | Mirato a **un individuo specifico**, personalizzato via OSINT |
| **BEC (Business Email Compromise)** | Mailbox aziendale **legittima compromessa** usata per phishing/esfiltrazione |

### Recon Emails — 3 tipi
| Tipo | Come funziona | Red flag |
|---|---|---|
| **Spam Recon** | Corpo casuale (`adjdfkaweasda`). Se non arriva un bounce → mailbox esiste. Nessuna interazione umana richiesta | Oggetto/corpo insensato |
| **Social Engineering Recon** | Costruita per ottenere una **risposta umana**: fingersi un conosciuto, urgenza, impersonare autorità (info da LinkedIn). = **BEC / impersonation** | Mittente sconosciuto, tono urgente, riferimenti a persone interne |
| **Tracking Pixel Recon** | Pixel invisibile **1x1** nel body HTML → all'apertura il client carica il pixel e notifica il server dell'attaccante | Email HTML con immagini esterne caricate automaticamente |

**Cosa raccoglie un tracking pixel:** OS, tipo di client (webmail vs client, mobile vs desktop), risoluzione schermo, **data/ora di apertura** (= quanto è monitorata la mailbox), **indirizzo IP** (geo + ISP).

⚠️ **Perché le recon email passano i filtri:** non contengono indicatori malevoli classici (no link, no allegati, no malware) → bypassano quasi sempre i gateway. Sono il **primo step della kill chain**.

💡 **Difesa principale contro i tracking pixel:** disabilitare il **caricamento automatico delle immagini** nel client (molti client moderni lo fanno già di default).

**Dopo la conferma:** gli indirizzi attivi vengono **venduti** ad altri threat actor o usati per campagne mirate (cred harvester, malware delivery).

### Credential Harvester
```
1. Email che imita un brand noto (Amazon, Microsoft, DHL, HMRC...)
2. Spinge a cliccare un link/bottone
3. Pagina di login falsa visivamente identica
4. Credenziali → salvate sul server malevolo OPPURE inviate a un account gratuito (Gmail/Hotmail)
```
**Conseguenze a catena:** **credential stuffing** (riuso password su altri servizi) → **BEC** → frodi, social engineering, ricatti.

**Esempi dal corso:**
| URL | Tecnica / red flag |
|---|---|
| `hxxps://amazonupdates.sytes[.]net/ap/signin` | **Subdomain impersonation** — il dominio reale è `sytes.net`, non `amazon.com` |
| `hxxps://12.158.186[.]80/owa/auth/logon.aspx` | 🚩 **IP raw nell'URL** — nessun servizio Microsoft legittimo lo fa |

**Artefatti principali da raccogliere:** URL del link (**defangato**) + IP/dominio della pagina di destinazione.

### Smishing vs Vishing
| | **Smishing** | **Vishing** |
|---|---|---|
| Vettore | SMS | Chiamata vocale |
| Target | **Generico, massivo** | **Specifico**: personale 1–2 livelli sotto il C-level con accesso a info sensibili |
| Obiettivo | **PII**, dati bancari/carta (**PCI**) | Credenziali di rete, info finanziarie aziendali |
| Leva | Link malevolo | **Social engineering vocale** (più difficile resistere) |

**Esempio smishing:** `paypal.verification-procedure[.]com` → dominio reale = `verification-procedure.com` (subdomain impersonation).

**Difese smishing:** awareness training, non cliccare link da numeri sconosciuti/impossibili (es. `4291`), liste anti-spam SMS.
**Difese vishing:** awareness training (mai condividere password senza verifica), blocco chiamate automatizzate, **codici di autorizzazione interni** (un esterno non li conosce), **segregation of duties** (riduce chi può completare da solo azioni critiche come i pagamenti).

### Whaling
**Target:** CEO, CFO, COO. Logica: ruolo più alto = più accessi critici, e stereotipicamente **minore cultura di cybersecurity**.

**Costruzione:** email altamente personalizzate via **OSINT**. Obiettivi: far scaricare malware, redirect a cred harvester, estrarre info riservate.

**Perché è difficile da rilevare:** volumi **bassissimi** (i filtri basati su volume non scattano), altamente personalizzate (nessun errore grossolano), spesso **non generano alert**.

**Difese specifiche:**
| Misura | Nota |
|---|---|
| Awareness training per il **C-level** | Spesso trascurato |
| Formazione degli **assistenti personali** | Gestiscono la mailbox del dirigente = primo filtro umano |
| **Marcatura email esterne** | Banner "questa email viene dall'esterno" |
| **DLP** (Data Loss Prevention) | Previene l'esfiltrazione anche se il dirigente risponde |

### Malicious File — 2 vettori
**Vettore 1 — Allegati dannosi**
Un `.exe` diretto viene bloccato → gli attaccanti usano formati **comuni e fidati** (Word, Excel).

**Office Macro Malware:** le macro sono disabilitate di default nelle versioni recenti → l'attaccante deve convincere l'utente ad **abilitarle manualmente**.
```
Documento aperto → falso avviso ("SOMETHING WENT WRONG - abilita il contenuto")
→ utente clicca "Abilita contenuto" → macro eseguita
→ connessione a dominio esterno → download malware (trojan, ransomware, rootkit)
```
**Difese:** macro disabilitate via **GPO**, **ASR Rules** (Attack Surface Reduction) in Microsoft Defender → bloccano l'esecuzione di contenuto eseguibile da macro, awareness training, non aprire allegati da mittenti sconosciuti.

**Vettore 2 — Malware hostato**
Link nell'email → sito che ospita il malware; l'utente deve scaricare ed eseguire (uno step in più, ma efficace).
| Variante | Nota |
|---|---|
| **Domini malevoli** | Registrare un dominio costa pochi euro e minuti. Dato dal corso: **200.000 nuovi domini/giorno**, **~70% malevoli o sospetti** → **~140.000/giorno** |
| **Domini compromessi** | Siti legittimi violati. Il sito resta intatto per non insospettire; solo un URL nascosto punta al payload. **Più difficile da bloccare** perché il dominio ha reputazione pulita |

---

## 5. TATTICHE E TECNICHE

### Spear Phishing
| | Phishing standard | **Spear phishing** |
|---|---|---|
| Target | Generico, massivo | **Singolo individuo** |
| Personalizzazione | Nessuna | **Alta**, basata su OSINT |
| Effort pre-attacco | Minimo | Significativo |
| Efficacia sul singolo | Bassa | **Alta** |

**Catena OSINT tipica (esempio dal corso):**
```
LinkedIn (ruolo, colleghi, azienda)
 → reverse image search della foto profilo
 → Facebook (interessi, hobby, amici)
 → email personalizzata + typosquatting/sender spoofing
 → allegato con backdoor → accesso remoto
```
**Fonti OSINT:** LinkedIn (ruolo, colleghi, responsabilità) · Facebook/Instagram (interessi, relazioni, posizione) · sito aziendale (struttura, nomi, formato email) · Google.

**Perché funziona:** il cervello **abbassa le difese** quando riconosce contesto familiare (nome del manager, progetto reale, collega noto).

### Typosquatting
Dominio quasi identico con errore tipografico intenzionale.
Esempi per `securityblue.team`: `securltyblue.team` (i→l), `securityblue.team` con doppia L, `securtyblue.team` (manca la i).

**Difese:** typosquat **monitoring** proattivo + **registrazione preventiva** dei domini a rischio.

**Esempio multi-stadio dal corso:**
```
Dominio reale:  DicksonUnited.co.uk
Dominio squat:  Dicksonunted.co.uk        ← manca la "i"

1. OSINT → identificano John Doe (target FINALE, service desk IT) e Samantha Moore (HR, nuova assunta)
2. Registrano il dominio squat + webmail Office365 sullo stesso dominio
3. Creano Chloe.wood@dicksonunted.co.uk (impersonando la responsabile HR reale)
4. Email a Samantha → non nota il typo → invia info personali su John Doe
5. Usano quelle info per RICATTARE John Doe → accesso ai server
```
🧠 Nota: il typosquatting colpisce prima una **vittima secondaria** per raccogliere munizioni contro il vero target.

### Homoglyphs (omografi)
Caratteri **Unicode diversi visivamente identici** (es. "o" latina vs "о" cirillica) → dominio completamente diverso. Domini con caratteri non latini = **IDN** (Internationalized Domain Names).

| | **Typosquatting** | **Homoglyph** |
|---|---|---|
| Meccanismo | Errore di battitura reale | Caratteri Unicode diversi, aspetto identico |
| Rilevabile a occhio | A volte, con attenzione | **Praticamente impossibile** |
| Awareness training | Parzialmente utile | ❌ **Inefficace** |
| Difesa principale | Training + monitoraggio domini | **Tecnologica** (URL scanning automatico, decodifica Unicode) |

🧠 **Punto esplicito del corso:** per gli omografi il training **non funziona** — l'utente non può fisicamente distinguere i caratteri. Serve tecnologia.

### Sender Spoofing
**Caso 1 — From spoofato con dominio interno:**
```
From: ServiceDesk@DicksonUnited.co.uk   ← spoofato, sembra INTERNO
To:   James.Smith@DicksonUnited.co.uk
```
Il training ha reso James sospettoso verso i domini **esterni**, ma non verso il proprio → abbassa la guardia.

**Come si rileva:** IP del server di invio (`X-Originating-IP`) → **WHOIS / IP lookup** per verificare se appartiene davvero all'organizzazione → **SPF/DKIM/DMARC**.

**Caso 2 — From spoofato + Reply-To diverso:**
```
From:     contact@amazon.com          ← quello che vede la vittima
Reply-To: hacktheplanet@gmail.com     ← dove arrivano davvero le risposte
```
Problema dell'attaccante: se spoofa `contact@amazon.com` e la vittima risponde, la risposta va ad Amazon. Soluzione: `Reply-To` diverso.

**Come si rileva:** confronta **From vs Reply-To**. Se diversi **e** il Reply-To è un servizio email gratuito o non correlato al brand → 🚩 red flag enorme. Blocca il Reply-To sul gateway.

### HTML Styling
Replicare fedelmente template, loghi, colori e pulsanti di un brand rende il cred harvester **indistinguibile a colpo d'occhio** dall'originale. Confronta la struttura HTML dell'email sospetta con quella di una email legittima nota dello stesso brand.

### Attachments — 3 categorie
| Categoria | Come funziona | Nota |
|---|---|---|
| **1. File non dannoso per social engineering** | Allegato innocuo (modulo HR); il pericolo è nel **testo** che chiede informazioni | Spesso combinato con sender spoofing. Es: "compila per aggiornare il sistema paghe, altrimenti niente stipendio" |
| **2. File non dannoso con link dannoso ("lure document")** | PDF/Word senza malware, ma con **hyperlink** verso sito malevolo | ⚡ **Bypassa l'URL sandboxing** del gateway: i tool analizzano i link nel *corpo* dell'email, non necessariamente quelli *dentro un allegato* |
| **3. File intrinsecamente dannoso** | Il file contiene codice malevolo — tipicamente **Office con macro** | Flow: apri → "abilita contenuto" → macro → download payload |

### Hyperlinks
**Perché funzionano:** quasi ogni email legittima contiene link → non destano sospetto (gli allegati sì). Un click porta subito al browser, **zero frizione percepita**.

**Verificare un link SENZA cliccarlo:**
- **Hover** con il mouse sul testo/bottone → molti client mostrano l'URL reale in basso
- Aprire l'email come **`.eml` grezzo** / editor di testo → cercare i tag `<a href="...">` → rivelano la destinazione **reale** indipendentemente dal testo visibile

```html
<p>Devi accedere a Google? <a href="https://www.google.com">Basta cliccare qui!</a></p>
                                    ↑ QUESTO conta        ↑ questo può dire qualsiasi cosa
```

### URL Shortening
`https://securityblue.team/courses/introduction-to-OSINT` → `bit.ly/2vYvczq`

Opzioni Bitly: **Title** (visibile solo nella dashboard del creatore) · **Custom back-half** (es. `bit.ly/paypal-verify` → rende il link più credibile).

**Perché è efficace:** l'URL breve non rivela nulla sulla destinazione → bypassa controlli visivi e talvolta scansioni basate su reputazione di dominio.

**Analizzare SENZA visitare — WannaBrowser** (simula un browser reale, es. Safari):
| Output | Significato |
|---|---|
| Request URL | Quale URL è stato interrogato |
| User-Agent | Browser simulato |
| **Final resolved URL** | **Destinazione reale** dopo tutti i redirect |
| Numero di redirect | Quanti rimbalzi |
| Status code | Es. **`301 Moved Permanently`** (tipico di Bitly) |
| **Location header** | L'URL verso cui punta il redirect |

**Workflow sicuro:**
```
1. Ricevi URL abbreviato sospetto (bit.ly/xxxxx)
2. ❌ NON cliccarlo
3. WannaBrowser → URL finale + status code + redirect chain
4. (Opz.) URL2PNG / URLScan → screenshot della destinazione
5. URL finale → VirusTotal / URLScan / URLhaus / PhishTank
```

### Use of Legitimate Services
I team di sicurezza **non bloccano** servizi ampiamente legittimi (troppi falsi positivi) → gli attaccanti sfruttano esattamente questa fiducia strutturale.

| Vettore | Servizi | Perché non vengono bloccati |
|---|---|---|
| **Delivery email** | Gmail, Outlook, Hotmail | Dipendenti li usano legittimamente (HR fuori orario, stipendi, clienti esterni) |
| **Delivery email** | **MailGun**, **MailChimp** | Le aziende ricevono newsletter/notifiche legittime → gli IP di invio sono fidati. L'attaccante **eredita la reputazione IP pulita** |
| **File hosting** | Dropbox, OneDrive, **Google Drive** | Dominio riconosciuto e fidato: `drive.google.com` è molto più credibile di un dominio sconosciuto |

**Limite per l'attaccante:** questi servizi bloccano l'upload di eseguibili palesemente malevoli.
**Bypass:** caricare **Office con macro** invece di `.exe`; su Google Docs creare un documento che contiene **solo un hyperlink** verso una pagina malevola esterna (invece di metterlo nel corpo dell'email, dove i controlli lo intercetterebbero).

### Business Email Compromise (BEC)
Sfrutta **relazioni di fiducia già esistenti**. Combina compromissione reale o spoofing con social engineering di alto livello.
⚠️ Spesso **nessun malware e nessun link palesemente malevolo** → bypassa i controlli tecnici; **il fattore umano è l'unico vero livello di difesa**.

**I 5 scenari:**
| # | Scenario | Meccanica |
|---|---|---|
| 1 | **Compromissione + attacco al fornitore** | Account di chi gestisce i pagamenti compromesso (credential stuffing, keylogger) → **fattura falsa** basata su una reale → inviata a tutti i fornitori in rubrica |
| 2 | **Spoofing + metodo di pagamento alternativo** | Email al fornitore che comunica un **nuovo IBAN** per i pagamenti futuri |
| 3 | **Spoofing + CEO Fraud** | Finge un dirigente, contatta il team finance con **urgenza estrema** → bonifico immediato |
| 4 | **Spoofing + furto dati** | Finge un dipendente e chiede info **su se stesso** (indirizzo, dati di pagamento) → alimenta spear phishing futuro o rivendita |
| 5 | **Compromissione + "Phishing Zombie"** | 🚩 Risponde a **thread email esistenti e legittimi** inserendo un URL malevolo. Devastante: mittente noto + conversazione in corso + fiducia già stabilita |

---

## 6. INVESTIGARE UNA EMAIL — ARTEFATTI DA RACCOGLIERE

### Artefatti EMAIL
| Artefatto | Perché serve |
|---|---|
| **Indirizzo mittente** | Ricerca sul gateway per trovare altre email dallo stesso mittente (anche se spoofato, va registrato) |
| **Subject line** | Ricerca/blocco di tutta la campagna con lo stesso oggetto |
| **Indirizzi destinatari** | Identificare chi altro l'ha ricevuta → notificarli. Spesso in **BCC** → si trovano cercando sul gateway per mittente+subject |
| **IP server di invio + Reverse DNS** | Verificare se il mittente dichiarato è legittimo (**WHOIS**); reverse DNS (**MxToolbox**) rivela l'hostname reale |
| **SPF / DKIM / DMARC** | Capire se hanno spoofato o manipolato l'email |
| **Reply-To** | Se ≠ From, rivela dove l'attaccante vuole davvero le risposte |
| **Data e ora** | Cercare altre email della campagna in una finestra temporale vicina; metrica su quando arrivano più attacchi |
| **Message-ID** | Correlazione campagna nei log |

### Artefatti FILE
| Artefatto | Perché serve |
|---|---|
| **Nome allegato + estensione** | Usabile come IOC per bloccare su EDR |
| **Hash SHA256** | Identifica univocamente il file → reputation check (VirusTotal). MD5/SHA1 come secondari |
| File type e size | Verifica mismatch estensione/contenuto reale |

### Artefatti WEB
| Artefatto | Perché serve |
|---|---|
| **URL completo** | ⚠️ **Copiare, mai riscrivere a mano** (rischio errori): right-click → "Copia indirizzo link", oppure estrarre dall'HTML raw (`<a href>`) |
| **Dominio root** | Capire se il sito è nato ad-hoc per l'attacco o è un sito legittimo compromesso |
| Sottodomini, parametri, path | Utili per scegliere la granularità del blocco |

### Comandi

**Hash del file**
```powershell
Get-FileHash .\malware.pdf                          # SHA256 (default)
Get-FileHash -Algorithm MD5 .\malware.exe
Get-FileHash -Algorithm SHA1 .\malware.docx
# tutti e tre in una riga:
Get-FileHash .\m.exe; Get-FileHash -Algorithm MD5 .\m.exe; Get-FileHash -Algorithm SHA1 .\m.exe
```
```bash
sha256sum malware.pdf
sha1sum malware.exe
md5sum malware.exe
```

**Reverse DNS lookup**
```powershell
nslookup 54.240.5.4          # Windows
```
```bash
dig -x 54.240.5.4            # Linux
```

---

## 7. ANALISI DEGLI ARTEFATTI

### Tool per categoria
| Scopo | Tool |
|---|---|
| **Visualizzazione URL** (senza visitare) | URL2PNG, URLScan.io, WannaBrowser |
| **Reputazione URL/dominio** | VirusTotal, URLScan.io, URLhaus, PhishTank |
| **Reputazione IP** | AbuseIPDB, VirusTotal |
| **Reputazione file/hash** | VirusTotal, Cisco Talos File Reputation |
| **Sandbox (dinamica)** | Hybrid Analysis, Any.run, Joe Sandbox, VirusTotal |
| **Info dominio** | WHOIS (**età di registrazione!**), MxToolbox |
| **Automazione end-to-end** | PhishTool |

### Confronto approcci di analisi
| Tipo | Velocità | Profondità | Sicurezza | Quando usarlo |
|---|---|---|---|---|
| **Reputation check** | ⚡ Istantaneo | Storica | ✅ Sicuro | Verdetto rapido, intelligence di community |
| **Analisi statica** | ⚡ Veloce | Superficiale | ✅ Molto sicuro | Triage iniziale, indicatori noti |
| **Sandbox** | ⏱️ Moderato | Comportamentale | ✅ Isolato | Zero-day, estrazione **TTP** (mappabili su **MITRE ATT&CK**) |
| **Analisi dinamica** | 🐌 Lenta | Profonda | ⚠️ Controllata | File sconosciuti, analisi comportamentale completa |

💡 **Età del dominio** (WHOIS) è uno dei segnali più affidabili: dominio registrato **< 30 giorni** = altamente sospetto. Serve anche a decidere il **tipo di blocco** (vedi §8).

---

## 8. AZIONI DIFENSIVE

### PREVENTIVE

**1. Email Security Technology** → SPF / DKIM / DMARC (vedi §3)

**2. Spam Filter — 3 livelli di deployment**
| Tipo | Dove | Esempio | Nota |
|---|---|---|---|
| **Gateway** | Dietro il firewall aziendale | Barracuda Email Security Gateway | Tipico di grandi organizzazioni |
| **Hosted** | Cloud | SpamTitan | Aggiornamenti più rapidi del gateway locale |
| **Desktop** | Installato dall'utente | Freeware vari | ⚠️ Rischioso, poco trasparente |

**3 meccanismi di rilevamento:**
| Meccanismo | Come funziona |
|---|---|
| **Content Filter** | Analizza header (incrocio con **blacklist** / reti di spam note) e body (contenuti specifici) |
| **Rule-Based Filter** | Regole predefinite/manuali. Es. Exchange Mail Flow Rules: `SE (subject O body contiene "OFFERTA GRATUITA") E (mittente esterno) ALLORA aumenta spam score`. Trasparente ma richiede manutenzione |
| **Bayesian Filter** | **Machine learning** sul comportamento dell'utente: marchi un'email come spam → impara le caratteristiche. Limite: serve molto volume prima di essere efficace |

⚠️ **Rischio sottovalutato:** un filtro **mal configurato fa più danno che bene**. Se un utente marca ripetutamente email legittime come spam (per errore o frustrazione), il filtro Bayesiano impara il pattern sbagliato e inizia a **bloccare email legittime**. Va spiegato agli utenti cosa è *spam* vs *email legittima ma indesiderata*.

**3. Security Awareness Training** → piattaforme di simulazione: **GoPhish** (open source), Sophos Phish Threat, Phish Insight (Trend Micro), PhishingBox

### Spam vs Email legittima indesiderata
| | **Spam** | **Legittima ma indesiderata** |
|---|---|---|
| Mittente | Sconosciuto, nessuna relazione | **Reale e verificabile** |
| Volume | Massivo, liste raccolte/comprate | Cold outreach commerciale |
| Autenticazione | Spesso fallisce | **SPF/DKIM/DMARC pass** |
| Contenuto | Ripetitivo, bassa qualità (pillole, offerte miracolose) | Coerente con quanto dichiara |
| Opt-out | Assente/finto | Presente e funzionante |

→ Non è spam nel senso classico, ma è comunque **indesiderata** dal punto di vista del destinatario.

### REATTIVE — Processo di risposta immediata (6 step)
```
1. RECUPERO EMAIL ORIGINALE
   → dal gateway email security (Defender, log gateway)
   → estrazione diretta da Exchange
   → richiesta al dipendente di inoltrarla a una mailbox dedicata alla sicurezza

2. RACCOLTA ARTEFATTI  (§6)

3. NOTIFICA AI DESTINATARI   ← passo spesso sottovalutato
   → cerca sul gateway chi altro l'ha ricevuta (mittente + subject)
   → invia template standard con destinatari in BCC
   → il template deve contenere: data/ora, subject, istruzioni chiare,
     contatto del team security

4. ANALISI APPROFONDITA  (§7 — sandbox, VirusTotal, IPVoid, URL2PNG, WannaBrowser, VM)

5. MISURE DIFENSIVE — blocco degli IOC (email / web / file)

6. REPORT DI INVESTIGAZIONE — audit trail
```

### Blocco ARTEFATTI EMAIL — 4 livelli (dal più mirato al più aggressivo)
| # | Livello | Quando | Rischio |
|---|---|---|---|
| 1 | **Mittente** (`mailbox@dominio`) | Default, volume alto dallo stesso indirizzo. Il blocco può essere **bidirezionale** (impedisce anche ai dipendenti di rispondere) | ✅ Basso |
| 2 | **Dominio mittente** | Solo se il dominio è **interamente malevolo** o usa **molte mailbox** diverse | ⚠️ Medio — ❌ **mai** su `@gmail.com`/`@outlook.com` (bloccherebbe email legittime da account personali verso HR/Payroll) |
| 3 | **IP server di invio** | Il più drastico: blocca **tutte** le email da quell'IP. Ha senso solo su IP chiaramente non autorizzato/compromesso/dedicato al phishing | 🚩 Alto — un dominio usa **più server di invio** (O365, Google Workspace, email marketing) → inefficace o eccessivo |
| 4 | **Subject line** | Gli attaccanti **riusano lo stesso oggetto** per tutta la campagna (cambiarlo costa tempo/denaro). Efficiente se la campagna usa **più mittenti** ma stesso subject | ⚠️ Medio |

### Blocco ARTEFATTI WEB
**Web Proxy — 2 granularità:**
| | Blocco URL | Blocco Dominio |
|---|---|---|
| Efficace se | URL **statico** (uguale per tutti) → copre l'intera campagna | Dominio **puramente malevolo** o compromesso senza necessità legittime |
| Inefficace se | URL **generato dinamicamente** per destinatario (es. `?email=john.smith@domain.com`) → protegge solo quel destinatario | Rischia di bloccare risorse legittime |

**Tecnica intermedia — bloccare per DIRECTORY:**
```
URL completo: hxxp://elephantsanctuary[.]com/index/2019/hgasdf/11/outlook/owa.php?...
Blocco su:    elephantsanctuary[.]com/index/2019/hgasdf
```
→ copre tutte le variazioni dopo quella directory senza bloccare l'intero dominio.

**Blackhole DNS — blocco "educativo":**
```
Dipendente clicca link malevolo
 → DNS interno reindirizza a una landing page interna sicura
 → messaggio: "Hai cliccato un link malevolo"
 → (opz.) alert SIEM/EDR per identificare CHI ha cliccato
```
**Vantaggio doppio:** blocca la minaccia **e identifica chi ha cliccato** → training aggiuntivo mirato. Particolarmente utile su campagne larghe.

**Firewall — blocco IP (raro nel phishing):**
Solo se l'IP ospita più siti malevoli e nessuna risorsa legittima.
⚠️ Perché è raro: secondo la **Pyramid of Pain**, l'IP è tra gli indicatori **più facili da cambiare** → il blocco ha vita breve. Più utile contro IP che scansionano/attaccano attivamente.

**🌳 Albero decisionale — quale blocco scegliere:**
```
Il dominio è PURAMENTE MALEVOLO? (giovane, nessun contenuto legittimo)
│
├─ SÌ → blocca l'INTERO DOMINIO
│        (nessun motivo legittimo per visitarlo)
│
└─ NO, è un dominio COMPROMESSO (sito legittimo violato)
   │
   ├─ I dipendenti NON hanno mai bisogno di visitarlo per lavoro?
   │  → blocca l'INTERO DOMINIO comunque
   │
   └─ I dipendenti POTREBBERO doverlo visitare?
      → blocca SOLO l'URL specifico (o la DIRECTORY malevola)
```
**Come determinare malevolo vs compromesso:** **WHOIS** (età di registrazione — domini nuovi = sospetti), **URL2PNG** (esiste un sito legittimo dietro?), ricerche Google in background.

### Blocco ARTEFATTI FILE
**1. Blocco hash (metodo principale)**
Blocca l'hash (**SHA256** preferito) nell'**EDR** → ogni volta che quel file tocca un endpoint protetto viene eliminato prima dell'esecuzione.
💡 **Bonus community:** se l'AV non lo rileva, invia l'hash al vendor → viene aggiunto al detection database, proteggendo tutti i clienti.
⚠️ **Limite — malware polimorfico:** si auto-modifica o scrive dati "spazzatura" nel codice → **hash diverso ad ogni esecuzione/campagna** → il blocco hash diventa inefficace su varianti future.
⚠️ **SHA256, non MD5/SHA1** → hash collision note.

**2. Blocco nome file (raramente usato)**
| Esempio | Verdetto |
|---|---|
| `Budget FINAL March 2019.xls` | ❌ Nome plausibile → rischio enorme di falsi positivi |
| `INVOICE #8491 READ NOW URGENT` | ✅ Numerazione specifica + urgenza artificiale → improbabile che sia legittimo |

**Uso reale più comune:** non blocco diretto ma **watchlist** → genera alert per l'analista invece di eliminare automaticamente.

---

## 9. REPORT WRITING E DEFANGING

### Artifact Sanitization (Defanging) — perché
Un IOC scritto in forma **cliccabile** in un report è un rischio: un collega, un cliente, o tu stesso mesi dopo potreste cliccarci per errore → esecuzione del payload → compromissione **causata dal report stesso**.

Il defanging rende l'IOC **leggibile e riconoscibile** ma **non cliccabile né risolvibile** da browser/client/parser.

### Le regole
| Regola | Trasformazione |
|---|---|
| **1. Punti** | Ogni `.` → `[.]` |
| **2. Protocollo** | `tt` → `xx` (`http`→`hxxp`, `https`→`hxxps`) |
| 3. (Opz.) `://` | → `[://]` |
| 4. (Opz.) `@` nelle email | → `[@]` |

### Esempi
| Originale | Defanged |
|---|---|
| `8.8.8.8` | `8[.]8[.]8[.]8` |
| `https://hello.example.com` | `hxxps[://]hello[.]example[.]com` |
| `http://malicious-site.com/payload.exe` | `hxxp[://]malicious-site[.]com/payload[.]exe` |
| `user@domain.com` | `user[@]domain[.]com` |

### Automatizzare
**CyberChef:**
- `Defang URL` → applica entrambe le regole a un URL
- `Defang IP Addresses` → defanga i punti di un IP
→ incolla la lista di IOC, applica l'operazione, ottieni tutto sanificato pronto per il report.

### Struttura del report
```
1. EXECUTIVE SUMMARY
   └── descrizione della minaccia in una frase (leggibile da non-tecnici)

2. EMAIL ARTIFACTS
   ├── analisi header (mittente, IP invio, autenticazione)
   ├── subject e analisi contenuto
   └── impatto sui destinatari (chi l'ha ricevuta, chi ha interagito)

3. TECHNICAL ANALYSIS
   ├── analisi URL + verdetto
   ├── analisi file/allegati (se presenti)
   └── reputation check degli IOC

4. DEFENSIVE ACTIONS TAKEN
   ├── blocchi immediati applicati (e a quale livello)
   ├── notifiche inviate agli utenti
   └── controlli preventivi aggiornati

5. RECOMMENDATIONS
   ├── misure di sicurezza aggiuntive
   ├── necessità di training
   └── miglioramenti di processo
```
⚠️ **Tutti gli IOC nel report vanno defangati.** Il report è la tua **audit trail**: dimostra che l'email è stata identificata, investigata e che sono state prese misure concrete.

---

## 10. RED FLAGS — RIFERIMENTO RAPIDO

### Header / tecnici
- 🚩 **`Reply-To` ≠ `From`** (specialmente se il Reply-To è un servizio gratuito)
- 🚩 **SPF / DKIM / DMARC fail**
- 🚩 **IP raw nell'URL** invece di un dominio (nessun servizio legittimo lo fa)
- 🚩 Dominio registrato **< 30 giorni** (WHOIS)
- 🚩 Routing `Received` incoerente, X-headers sospetti
- 🚩 IP residenziale per email "aziendale"
- 🚩 Display text del link ≠ `href` reale

### Contenuto / social engineering
- 🚩 **Urgenza artificiale**: "Act now", "24 ore", "il tuo account sarà sospeso"
- 🚩 **Saluto generico**: "Caro cliente" invece del nome reale
- 🚩 Errori di grammatica/ortografia (i brand veri raramente ne hanno)
- 🚩 Allegati **inaspettati**, doppie estensioni
- 🚩 Richiesta di **abilitare le macro**
- 🚩 Richiesta di cambiare **IBAN / metodo di pagamento**
- 🚩 Email inviata a mailbox di gruppo (`contact@`) = recon generica
- 🚩 Immagini esterne caricate automaticamente = possibile **tracking pixel**

### Per tipo di attacco
| Segnale | Tipo probabile |
|---|---|
| Oggetto/corpo casuale o insensato | **Spam recon** |
| Mittente sconosciuto + urgenza + riferimenti a persone interne | **Social engineering recon / BEC** |
| Pixel 1x1 / immagini remote | **Tracking pixel recon** |
| Login page che imita un brand | **Credential harvester** |
| Email a CEO/CFO, volume bassissimo, molto personalizzata | **Whaling** |
| Risposta dentro un thread esistente con URL nuovo | **BEC "phishing zombie"** |

---

## 11. CHECKLIST OPERATIVA PER TASK

- [ ] Sto lavorando in **VM / sistema dedicato**? (non sulla macchina di produzione)
- [ ] Ho aperto il `.eml` **grezzo** (editor di testo), non solo il rendering?
- [ ] Il body è **base64**? → CyberChef `From Base64`
- [ ] Ho estratto **tutti** gli artefatti email? (mittente, subject, destinatari, IP+rDNS, Reply-To, data/ora, Message-ID)
- [ ] Ho confrontato **From vs Reply-To**?
- [ ] Ho letto i `Received` **dal basso verso l'alto** per trovare l'origine reale?
- [ ] Ho controllato **SPF / DKIM / DMARC** (`Authentication-Results`)?
- [ ] Ho estratto gli URL dai tag **`<a href>`** (non dal testo visibile)?
- [ ] Ho **copiato** l'URL invece di riscriverlo a mano?
- [ ] URL abbreviato? → **WannaBrowser** prima di qualsiasi altra cosa
- [ ] Allegato? → **SHA256** + VirusTotal + sandbox
- [ ] Ho fatto **WHOIS** per l'età del dominio? (decide il tipo di blocco)
- [ ] Gli IOC nella risposta/report sono **defangati**?
- [ ] Il **formato della risposta** richiesto è rispettato esattamente? (hash maiuscolo/minuscolo, `nome.ext, nome.ext`, primi N caratteri, defanged o no)

---

## 12. PITFALL COMUNI

| Errore | Conseguenza | Fix |
|---|---|---|
| Fidarsi del campo `From` | Verdetto sbagliato | Verifica sempre con IP di invio + SPF/DKIM/DMARC |
| Leggere i `Received` dall'alto | Identifichi l'ultimo hop, non l'origine | **Dal basso verso l'alto** |
| Riscrivere un URL a mano | Typo → analisi del dominio sbagliato | Copia con right-click o dall'HTML raw |
| Cliccare un URL abbreviato "per vedere" | Esecuzione payload / conferma della mailbox all'attaccante | WannaBrowser / URL2PNG |
| Usare MD5 come hash primario | Hash collision, non è lo standard | **SHA256** |
| Bloccare `@gmail.com` / `@outlook.com` interi | Blocchi email legittime dei dipendenti | Blocca il **mittente singolo** |
| Bloccare l'intero dominio di un sito **compromesso** | Blocchi un sito legittimo usato per lavoro | Blocca solo l'**URL/directory** |
| Bloccare l'URL quando è **dinamico** (`?email=...`) | Proteggi solo un destinatario | Blocca la **directory** |
| Affidarsi solo al blocco hash | Malware polimorfico cambia hash | Blocca anche URL/dominio + watchlist |
| Scrivere IOC cliccabili nel report | Click accidentale → compromissione | **Defanging** (CyberChef) |
| Assumere che SPF/DKIM/DMARC pass = sicuro | Un dominio typosquat passa tutti i controlli | Controlla anche il **dominio stesso** (WHOIS, somiglianza) |
| Fare training contro gli **homoglyph** | Inefficace — l'utente non li distingue | Difesa **tecnologica** (URL scanning) |
| Dimenticare lo step 3 (notifica destinatari) | Altri utenti interagiscono durante la tua analisi | Cerca mittente+subject sul gateway, avvisa in **BCC** |

---

*Fonti: materiale corso BTL1 (Phishing Analysis domain) + cheat sheet pubbliche consolidate.*
