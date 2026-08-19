# BTL1 — Threat Intelligence Cheat Sheet

> Esame: 24h, 20 task pratici, open-book, soglia 70%.
> **Tool pratico del dominio: MISP** (confermato). La teoria serve come *contesto* per capire cosa stai guardando, non come nozionismo.
> Il lavoro reale in TI = **dare contesto a un indicatore**: un IP malevolo da solo dice poco; sapere a quale infrastruttura appartiene, quale malware family e quali TTP usa l'attore ti dice cosa cercare dopo.

---

## 0. INDICE RAPIDO — "cosa uso per cosa"

| Devo fare... | Tool |
|---|---|
| Gestire/correlare IOC, creare eventi | **MISP** |
| Reputazione IP / dominio / URL | **VirusTotal**, **URLhaus**, **URLScan.io**, **AbuseIPDB**, **PhishTank** |
| Reputazione file / hash | **VirusTotal**, **Cisco Talos File Reputation** |
| Info registrazione dominio (età!) | **WHOIS**, **DomainTools** |
| Passive DNS / storico risoluzioni | VirusTotal (tab Relations), SecurityTrails |
| Mappare TTP / esplorare tecniche | **MITRE ATT&CK** (attack.mitre.org), **ATT&CK Navigator** |
| TTP per gruppo specifico | attack.mitre.org/groups/ |
| Ricerca dispositivi esposti su Internet | **Shodan**, **Censys** |
| Link analysis / grafi di relazioni | **Maltego** |
| Monitoraggio OSINT | **TweetDeck** (free), **Recorded Future** (paid) |
| Sandbox malware | Hybrid Analysis, Any.run, Joe Sandbox |
| Feed IOC gratuiti | AlienVault OTX, Spamhaus, URLhaus, CISA AIS, SANS ISC, Talos (free) |
| CVE lookup | **NVD** (NIST), **CVEDetails.com** |

---

## 1. FONDAMENTI

### Cos'è la Threat Intelligence
Informazioni che un'organizzazione usa per capire le minacce che la stanno colpendo **ora** o potrebbero colpirla **in futuro**. A differenza del SOC quotidiano (reattivo su alert), la TI si concentra su minacce più sofisticate: **APT**, **zero-day**, **campagne malware globali**.

**Obiettivo:** capire **chi** ti attacca, **perché**, e **come** (tattiche) → alimenta red team/pentest e difese mirate.

### Threat Intelligence Lifecycle — 6 fasi
| # | Fase | Cosa avviene |
|---|---|---|
| 1 | **Planning & Direction** | **La più critica** — definisce obiettivi e stakeholder. Senza scope chiaro si spreca tempo |
| 2 | **Collection** | Raccolta dati: forum, OSINT, feed. Aggregazione in piattaforme centralizzate (**MISP**) |
| 3 | **Processing** | Dati grezzi → formato leggibile/analizzabile (es. traduzione di post in lingua straniera) |
| 4 | **Analysis** | **Fase umana** — info elaborate → intelligence **azionabile**. Il livello di dettaglio dipende dal **pubblico** |
| 5 | **Dissemination** | Distribuzione ai destinatari giusti (SOC, analisti TI, board) |
| 6 | **Feedback** | Chiude il ciclo — le esigenze sono state soddisfatte? Adatta le fasi precedenti |

**Domande chiave nella Dissemination:** che info serve a questo pubblico? come presentarle? con che frequenza? su che canale? come rispondo alle domande?

### Types of Intelligence (discipline generali, non solo cyber)
| Sigla | Nome | Fonte |
|---|---|---|
| **SIGINT** | Signals Intelligence | Intercettazione segnali radio/comunicazioni. Origine: **1ª Guerra Mondiale**. Contesti: droni, UAV, radar |
| ↳ **COMINT** | Communications Intelligence | Comunicazioni **tra persone** (messaggi, voce) — sottodisciplina di SIGINT |
| ↳ **ELINT** | Electronic Intelligence | Sistemi **non** di comunicazione (guida missilistica, radar) |
| **OSINT** | Open Source Intelligence | **Fonti pubbliche**. ⚠️ Arma a doppio taglio: gli attaccanti la usano identicamente |
| **HUMINT** | Human Intelligence | **Da altri esseri umani**: incontri, debriefing, osservazione, spionaggio, canali diplomatici |
| **GEOINT** | Geospatial Intelligence | Dati geografici/spaziali, **immagini satellitari**. Guerra, disastri naturali, instabilità politica |

🧠 Il più rilevante per un analista SOC/TI è di gran lunga **OSINT**.

### Il profilo dell'analista TI
Forte consapevolezza dei **bias cognitivi** · approccio **scettico** (mette tutto in discussione, cerca prove) · analisi tecnica intensa · spesso proveniente da **forze dell'ordine o background militare** (competenze investigative trasferibili).

---

## 2. I 3 LIVELLI DI THREAT INTELLIGENCE

```
        ┌──────────────────────┐
        │     STRATEGICA       │ ← C-Suite / Board
        │  rischi, trend, geo  │   mesi/anni
        └──────────────────────┘
        ┌──────────────────────┐
        │     OPERATIVA        │ ← Security manager / IR / TI team
        │  TTP, campagne, attr.│   settimane/mesi
        └──────────────────────┘
        ┌──────────────────────┐
        │     TATTICA          │ ← Analisti SOC
        │  IOC, firme, regole  │   ore/giorni
        └──────────────────────┘
```

| Livello | Tecnicità | Pubblico | Formato | Orizzonte | Azionabilità |
|---|---|---|---|---|---|
| **Strategica** | Bassa | Dirigenza/board | Report, presentazioni | Lungo termine | Decisioni di policy, budget |
| **Operativa** | Alta | Analisti TI, IR, red team | Profili attori, **TTP** | Medio termine | Procedure di risposta, hunting |
| **Tattica** | Alta | Analisti SOC | **IOC** | Immediato | Blocco, detection rule |

**Esempi Strategica:** collegare eventi globali ad attività cyber (COVID → phishing a tema OMS) · report su pattern nel tempo ("il lunedì aumentano i DDoS") · monitorare attori che colpiscono **il proprio settore** (una banca monitora attacchi ad altre banche). Gli analisti strategici sono spesso specializzati **geograficamente** e seguono le **tensioni geopolitiche**.

**Operativa:** studio di identità, motivazioni, **TTP** degli attori. Tecnica, **non automatizzabile** → richiede analisti umani.

**Esempi Tattica:** lista di email IOC legate a **Emotet** → check manuale sul gateway · feed di IP malevoli → alimenta **IPS** in autonomia · report pubblico con IOC su uno zero-day.

### Perché la TI è utile — 4 aree
1. **Contesto delle minacce** → ricerche approfondite su chi potrebbe colpirti realmente; dà contesto al **vulnerability management** per prioritizzare il patching
2. **Prioritizzazione degli incidenti** → con 2 incidenti simultanei e risorse limitate, il contesto TI dice quale ha impatto potenziale maggiore
3. **Arricchimento delle indagini** → un IP che scansiona il perimetro è **normale**; ma se la TI lo collega a un **APT** diventa indagine urgente. *(TI tattica = l'IOC; TI operativa = l'attribuzione)*
4. **Condivisione informazioni** → segnali di allarme precoci da altre org → azioni **proattive**

---

## 3. THREAT ACTORS

### Minaccia vs vulnerabilità vs attore
```
Vulnerabilità: mancanza di input validation
Minaccia:      sfruttarla per una SQL Injection
Risultato:     esfiltrazione tabelle username/password
Attore:        chi la sfrutta
```
⚠️ **Non serve intenzione malevola** per essere un threat actor: un dipendente non formato che cancella per errore una tabella DB **è** un threat actor (minaccia **involontaria/accidentale**).

### Le 4 categorie
| Categoria | Motivazione | Sofisticazione | Tecniche tipiche | Esempi |
|---|---|---|---|---|
| **Cybercriminals** | Guadagno economico | Bassa→Alta (dall'esperto allo **script kiddie**) | Ransomware, phishing | Gruppi ransomware, sindacati di frode |
| **Nation-States (APT)** | Spionaggio, sabotaggio | **Molto alta** | Operazioni prolungate e furtive, 0-day | APT28, APT29 |
| **Hacktivists** | Politica/sociale | Bassa→Media | **DDoS**, **defacement** | Anonymous, Syrian Electronic Army |
| **Insider Threat** | Varia (vendetta, denaro, errore) | Varia | Abuso di accesso legittimo | Dipendente scontento, account compromesso |

**Script kiddie** = individuo poco esperto che dipende da tool/script già pronti, basse competenze tecniche.

### Le 4 motivazioni
| Motivazione | Sotto-tipi ed esempi |
|---|---|
| **Finanziaria** | **Individuale**: corporate espionage (rubare e vendere info ai concorrenti) · **Criminale**: ransomware ($1mld 2016 → **$8mld 2018**, +800%; costo medio attacco 2019 **~$133.000**), cryptomining, trojan bancari → **mule accounts** · **Governativa**: **Lazarus Group** (Corea del Nord) = **BlueNoroff** (banche, finanzia il resto) + **AndAriel** (spionaggio governativo); fondi convertiti in **Monero** per aggirare le sanzioni USA |
| **Politica** | State-sponsored contro nazioni ostili. **Stuxnet** (USA/Israele → programma nucleare iraniano, **4 exploit zero-day**). Cyberwarfare: nessun personale sul campo, nessuna barriera geografica (basta Internet o superare un **air gap**). **Campagne di disinformazione** (bot, account fake, ads a pagamento — tipiche durante le **elezioni**) — tecnicamente non attacchi informatici |
| **Sociale** | Fare una dichiarazione **o** migliorare reputazione/status. Script kiddies con **"stressers"/"booters"** = DDoS-as-a-Service. **Lizard Squad**: DDoS a League of Legends, Destiny, PSN (ago/nov 2014); Xbox Live + PSN a **Natale 2014** |
| **Sconosciuta** | Il motivo non è chiaro → **attribuzione più difficile** (non si possono collegare pattern noti). Può emergere più tardi con nuove prove |

### Naming Conventions — chi chiama chi come

**CrowdStrike** — animali. Stati-nazione = **paese**; non statali = **intento**.
| Animale | Paese | Esempio |
|---|---|---|
| **Bear** | Russia | Fancy Bear, Cozy Bear |
| Buffalo | Vietnam | — |
| **Chollima** | Corea del Nord | Stardust Chollima |
| Crane | Corea del Sud | — |
| **Kitten** | Iran | Refined Kitten |
| Leopard | Pakistan | Mythic Leopard |
| **Panda** | Cina | Goblin Panda |
| Tiger | India | Viceroy Tiger |
| **Jackal** | *(non statale)* hacktivisti | Syrian Electronic Army |
| **Spider** | *(non statale)* criminali | **Mummy Spider** → **Emotet** |

**Mandiant / FireEye** — numerico. `APTxx` (stati-nazione, numeri da codici nazionali interni) · `FINxx` (**Fin**ancial) · `UNCxx` (**Unc**lassified, in analisi).
| Paese | APT |
|---|---|
| Cina | APT1, 2, 3, 10, 19, 20, 30, 40, 41 |
| Iran | APT33, 34, 35, 39 |
| Corea del Nord | APT37, 38 |
| **Russia** | **APT28, APT29** |
| Vietnam | APT32 |

`FIN7` = retail/ristorazione/hospitality USA dalla metà 2015, malware **POS** (Point of Sale). Altri: FIN4, 5, 6, 8, 10.

**Altri vendor:**
| Vendor | Convenzione |
|---|---|
| **Microsoft** | ⚠️ **Meteo** (dal 2023) — `Typhoon`=Cina, `Blizzard`=Russia, `Sandstorm`=Iran, `Sleet`=Corea del Nord, `Tempest`=motivati finanziariamente, `Tsunami`=private sector offensive actors, `Flood`=influence ops, `Storm-####`=cluster in sviluppo |
| **Kaspersky** | Termini geografici/culturali (Lazarus, Equation Group) |

> ⚠️ **CORREZIONE a molte cheat sheet in circolazione:** l'elemento chimico (Nobelium, Hafnium) è la convenzione Microsoft **vecchia**, ritirata nell'**aprile 2023**. Mapping: `Nobelium → Midnight Blizzard` (APT29/Cozy Bear), `Hafnium → Silk Typhoon`, `Phosphorus → Mint Sandstorm`. Se una fonte usa ancora gli elementi chimici, è materiale datato.
> 💡 Dal 2025 Microsoft e CrowdStrike (con Mandiant e Unit 42) pubblicano un **mapping congiunto** dei nomi per ridurre la confusione.

### Perché l'attribuzione via nomi è un casino
- Gli attori **condividono strumenti** → stessi indicatori in gruppi diversi
- Usano **infrastrutture di altri paesi** e **copiano TTP** altrui → **false flag**
- Lo stesso gruppo ha nomi diversi per vendor (Cozy Bear = APT29 = Midnight Blizzard = The Dukes = UNC2452 = Nobelium...)

---

## 4. APT (Advanced Persistent Threat)

Gruppi altamente qualificati, spesso **state-sponsored**, con accesso quasi illimitato a risorse. Danni **massimi e duraturi**, target specifici, uso tipico di **exploit 0-day** e framework **custom**.

### 3 differenze chiave rispetto a un threat actor "normale"
1. **Risorse** — enormemente superiori (tipicamente da stati-nazione)
2. **Obiettivi** — finanziari, politici o militari (non curiosità o hacktivismo)
3. **Persistenza** — cercano accesso e controllo **continui** (spionaggio, sorveglianza); gli hacker convenzionali fanno attacchi brevi e si fermano a obiettivo raggiunto

### APT del corso (da sapere)
| Gruppo | Alias | Origine | Motivazione | Note |
|---|---|---|---|---|
| **APT28** | Fancy Bear, Sofacy, Pawn Storm | Russia | Politica | Militari, sicurezza, governi — **Georgia**, Europa dell'Est. Campagna **Hillary Clinton**, interferenza elezioni USA |
| **APT29** | Cozy Bear | Russia | Politica | Intelligence russa, attivo dal **~2010**. **Spear-phishing al Pentagono nel 2015** (chiusura email/Internet non classificati). Ritenuto chiuso nel 2017, in realtà solo evoluto |
| **APT32** | — | **Vietnam** | Spionaggio | Attivo dal **2014**. Settore privato, governi, **dissidenti e giornalisti**. Sud-est asiatico. Tecnica: **strategic web compromise** |
| **Cobalt Group** | Gold Kingswood | — | **Finanziaria** | Bancomat, sistemi di pagamento, banche (Europa dell'Est/Russia). Malware **SpicyOmelette**. Leader arrestato in Spagna, gruppo continua. **>1 mld €** in **>40 paesi** |
| **Lazarus** | — | Corea del Nord | Mista | Sotto-team: **BlueNoroff** (finanziario) + **AndAriel** (spionaggio) |

### Case study — Cobalt Group exploit chain
```
Fase 0: spear-phishing con PDF/Word/RTF allegato o linkato
Fase 1: link → documento Word con VBA malevolo
Fase 2: exploit kit THREADKIT → vulnerabilità Office/IE → file batch
Fase 3: bypass APPLOCKER via binari Microsoft legittimi (CMSTP → file INF /
        scriptlet XML) → dropper DLL su disco
Fase 4: PowerShell → payload offuscato a strati → shellcode in memoria →
        beacon COBALT STRIKE (o downloader JScript → backdoor)
Fase 5: C2 remoto cifrato, invio info sistema (antimalware, IP) →
        compromissione completa, lateral movement, persistenza
```
🧠 Il punto: **non è un singolo strumento avanzato** — è l'**orchestrazione dei TTP**, ogni fase innesca la successiva.

---

## 5. FRAMEWORK

### MITRE ATT&CK
**A**dversarial **T**actics, **T**echniques, and **C**ommon **K**nowledge. Introdotto nel **2013**. Base di conoscenza del **comportamento avversario**. Caso d'uso principale: identificare comportamento **APT**.

**Le 12 tattiche del corso** (in ordine di fase d'attacco):
| # | Tattica | Tecnica esempio |
|---|---|---|
| 1 | **Initial Access** | T1566 Phishing |
| 2 | **Execution** | T1059 Command and Scripting Interpreter |
| 3 | **Persistence** | T1547 Boot or Logon Autostart Execution |
| 4 | **Privilege Escalation** | T1068 Exploitation for Priv Esc |
| 5 | **Defense Evasion** | T1055 Process Injection |
| 6 | **Credential Access** | T1003 OS Credential Dumping |
| 7 | **Discovery** | T1083 File and Directory Discovery |
| 8 | **Lateral Movement** | T1021 Remote Services |
| 9 | **Collection** | T1005 Data from Local System |
| 10 | **Command & Control** | T1071 Application Layer Protocol |
| 11 | **Exfiltration** | T1041 Exfil Over C2 · **T1020 Automated Exfiltration** |
| 12 | **Impact** | T1486 Data Encrypted for Impact (ransomware) |

> ⚠️ Il corso dice **12 tattiche / 260+ tecniche**. La matrice Enterprise attuale ne ha **14**: davanti alle 12 sopra sono state aggiunte **Reconnaissance** (TA0043) e **Resource Development** (TA0042). Se l'esame chiede "quante categorie", usa il numero del corso; se navighi il sito reale, aspettati 14.
> ⚠️ **Attenzione ai formati ID**: le **tattiche** hanno ID `TA00xx`, le **tecniche** `Txxxx`. Molte cheat sheet li confondono (es. scrivono "Initial Access = T1566" — T1566 è *Phishing*, una tecnica *dentro* Initial Access).

**Ogni tecnica include anche:** consigli di **mitigazione** e di **rilevamento (detection)** — è la parte più utile operativamente.

**Uso pratico — dall'IOC all'attack path:**
```
Trovi uno script che esfiltra dati → mappi su T1020
→ lavori a RITROSO: come è avvenuto l'accesso iniziale? la priv esc? il lateral movement?
→ costruisci l'ATTACK PATH completo
→ confronti con i TTP di APT noti su attack.mitre.org/groups/
→ ATTRIBUZIONE con ragionevole confidenza
→ implementi difese anche contro le ALTRE tattiche di quel gruppo (difesa proattiva)
```

**Difesa proattiva:** invece di aspettare l'attacco, analizza TTP noti in anticipo → verifica se i controlli attuali li rilevano/bloccano → conduci **pentest** su attack path specifici per validare.

### Cyber Kill Chain (Lockheed Martin, 2011)
**7 fasi — tutte devono completarsi** perché l'attacco riesca:
| # | Fase | Attaccante | Difensore |
|---|---|---|---|
| 1 | **Reconnaissance** | Record di dominio, scan porte/vuln, dipendenti sui social | Qui si osservano i **precursori** |
| 2 | **Weaponization** | Crea backdoor custom, la ospita su dominio proprio, scrive la macro | ⚠️ **Molto difficile da rilevare** — avviene **fuori** dalla rete (unica eccezione: la TI). AV, email security, hardening |
| 3 | **Delivery** | Spear-phishing (basato su OSINT) con documento Office + macro | **Sandboxing degli allegati** |
| 4 | **Exploitation** | Sfrutta una vulnerabilità per privilegi più alti | **Hardening** + **vulnerability management** |
| 5 | **Installation** | Backdoor + tecniche di **persistenza** | Agenti **EDR** |
| 6 | **Command & Control** | Apre il canale C2 | **Ultima vera possibilità** di fermare tutto — bloccare l'esecuzione dei comandi è critico |
| 7 | **Actions on Objectives** | "Hands on keyboard", completa l'obiettivo | Rilevare **il prima possibile** per minimizzare il danno |

**Limiti:** gli attacchi evolvono e il modello non li rappresenta sempre; ⚠️ **non funziona per gli insider threat** — le prime 2 fasi presuppongono un attaccante **esterno**, ma un insider parte già dall'interno.

**Unified Kill Chain (UKC):** MITRE ATT&CK **+** Cyber Kill Chain → **18 fasi**, copre attività **sia fuori sia dentro** la rete.

### ATT&CK vs Kill Chain
| | **Cyber Kill Chain** | **MITRE ATT&CK** |
|---|---|---|
| Struttura | **Sequenza lineare** definita | Tecniche **caso per caso** |
| Dettaglio | Più **generico** | Più **specifico** (come è stato eseguito) |
| Uso | Visione d'insieme | Dettaglio tecnico + gruppi APT |

→ Molti usano un approccio **ibrido**: Kill Chain per la vista d'insieme, ATT&CK per il dettaglio.

### Pyramid of Pain
Dal basso (facile per l'attaccante) all'alto (doloroso):
| Livello | Dolore | Difficoltà di cambio | Esempi |
|---|---|---|---|
| **6. TTP** | 😭 **Massimo** | **Ripensare l'intera metodologia** | Uso di PowerShell, tecniche di lateral movement, spear-phishing con PDF |
| **5. Tools** | 😫 Molto alto | Trovare/sviluppare alternative | Cobalt Strike, Mimikatz, malware custom |
| **4. Network/Host Artifacts** | 😖 Alto | Modificare codice/config | Chiavi di registro, user-agent, path di file, directory create |
| **3. Domain Names** | 😒 Medio | Registrare nuovi domini (costo + attesa) | Domini C2, siti di phishing |
| **2. IP Addresses** | 😑 Basso | VPN, TOR, proxy aperti | IP C2, host malevoli |
| **1. Hash Values** | 😄 **Banale** | **Cambio di un solo carattere** | Hash di file, campioni malware |

🧠 **Esempio dal corso — campagna spam Locky (3 mesi):** domini, IP e hash cambiavano continuamente, ma gli **artefatti host** restavano costanti. Cambiare la **logica del malware** costa molto più che cambiare un IP.

🧠 **Perché conta operativamente:** spiega perché bloccare un IP ha vita breve, e perché una detection rule su comportamento (TTP) vale più di una blocklist di hash.

---

## 6. IOC E PRECURSORI

### Precursori vs IOC — la distinzione chiave
| | **Precursore** | **IOC** |
|---|---|---|
| Quando | **PRIMA** che l'attacco inizi (fase di ricognizione) | **DURANTE / DOPO** la compromissione |
| Cosa indica | Qualcuno sta studiando le tue difese | Qualcosa è già avvenuto |
| Problema | ⚠️ **La maggioranza degli attacchi non ha precursori rilevabili** → peggiora il detection time | Abbondanti ma reattivi |

**Le 3 categorie di precursori:**
| Categoria | Attività dell'attaccante | Cosa monitorare |
|---|---|---|
| **Scansione porte / fingerprinting OS e app** | **Nmap**, **Netcat**, **Nessus** | Log **firewall/WAF** con alert su IP che tenta molte porte in poco tempo; log dei sistemi scansionati |
| **Social engineering e ricognizione** | **Dumpster diving** (spazzatura: USB, documenti), **eavesdropping** (ascolto conversazioni) | Segnalazioni dipendenti, **CCTV**: estranei nei cassonetti, persone che si aggirano fuori/in lobby, dipendenti avvicinati da sconosciuti, chiamate da numeri sconosciuti/spoofati, sparizione di documenti/attrezzature |
| **Fonti e bacheche OSINT** | Social, blog, forum, dark web | **TweetDeck** (free), **Recorded Future** (paid): minacce esplicite da un gruppo, **CVE** che riguardano i tuoi sistemi, discussioni su 0-day sfruttati in the wild, report governativi su picchi di exploit |

### I 4 tipi di IOC
| Tipo | Perché è malevolo | Fonte tipica dove lo trovi |
|---|---|---|
| **Indirizzo email** | Ha inviato URL/allegati malevoli, social engineering | Header email (`From`, `Reply-To`, `Return-Path`) |
| **Indirizzo IP** | Scansioni non autorizzate, hosting malevolo, **C2** | Header email, log SIEM, PCAP, memory analysis |
| **Dominio / URL** | Ospita malware, phishing | Body email, log DNS, stringhe nel malware, log proxy, report sandbox |
| **Hash / nome file** | Identifica univocamente il malware (**MD5, SHA1, SHA256**) → blacklist su **EDR** | Allegato, file droppato, carving da memoria |
| *(extra)* **Chiave di registro / mutex** | Artefatto host persistente | Memory analysis, report comportamentale sandbox |

### STIX e TAXII
| | **STIX** | **TAXII** |
|---|---|---|
| Nome | **S**tructured **T**hreat **I**nformation e**X**pression | **T**rusted **A**utomated e**X**change of **I**ntelligence **I**nformation |
| Cos'è | Il **linguaggio/formato** dei dati | Il **protocollo/trasporto** per scambiarli |
| Sviluppato da | **MITRE** + comitato tecnico **OASIS CTI** | — |
| Note | Progettato per lavorare con TAXII ma **usabile anche da solo**. Condivide **più dei soli IOC**: **motivazioni, abilità, capacità, risposta** | Gira su un **server**; condivisione a gruppi chiusi **o** threat feed pubblico ad abbonamento |

🧠 Mnemonica: **STIX = COSA dici** · **TAXII = COME lo consegni**.

---

## 7. ATTRIBUZIONE

### I 3 livelli
| Livello | Domanda | Metodo | Problemi |
|---|---|---|---|
| **1. Macchina** | Quali sistemi sono stati usati? | IP, log di rete, chi ha fatto accesso, punto d'ingresso | L'IP può essere in un altro paese; catena di più macchine (hop). Se confermato → sequestro da parte delle forze dell'ordine |
| **2. Umana** | Chi ha premuto i tasti? | Forense + correlazione con database identità | Le **credenziali non provano la persona** (furto, macchina compromessa). L'affidabilità dipende dalla qualità del database |
| **3. Responsabile ultimo** | **Di chi è la colpa?** | Ha agito da solo o per conto di un'org/stato? | Il **"perché"** è centrale: può essere stato **costretto**. Conseguenze: perseguimento individuale vs **discussione diplomatica** / ritorsione |

### I 5 indicatori chiave di attribuzione
1. **Tradecraft** — comportamenti ricorrenti (tecniche, strumenti, procedure)
2. **Infrastruttura** — macchine/reti usate (spesso già compromesse in precedenza)
3. **Malware** — può essere specifico dell'attore, riutilizzato, o modificato in fretta per sfuggire all'attribuzione
4. **Intento** — motivazione dietro l'attacco
5. **Fonti esterne** — report di società di sicurezza, media, ricercatori indipendenti

### Cosa ostacola l'attribuzione
⚠️ **Tutti i metadati sono falsificabili** (IP sorgente, dati email, domini, username, dati di registrazione).

| Tecnica | Effetto |
|---|---|
| **Proxy** e sistemi terzi compromessi | Trampolino, nasconde l'origine |
| **TOR** | Anonimato + cifratura automatica |
| **Infrastruttura condivisa** tra gruppi | Impossibile isolare un singolo attore |
| Malware **commodity** / **living off the land** | Nessuno strumento unico identificabile |
| **False flag / attacco imitativo** | Copia deliberata dei TTP di un altro gruppo per incolparlo |

🧠 **Esempio classico:** malware con stringhe in **cirillico** in un'azienda USA → *sembra* russo. Ma potrebbe essere **ingegnerizzato apposta** da attori di un altro paese per sviare.

🧠 **Rovescio della medaglia:** alcuni attori **vogliono** essere riconosciuti (reputazione/status) e lasciano deliberatamente fingerprint, nomi di file caratteristici, connessioni da IP/domini già noti, malware custom non condiviso.

---

## 8. WORKFLOW OPERATIVI

### Threat Exposure Check (TEC)
Verifica pratica se determinati IOC sono **già presenti** nel proprio ambiente. Attività **tattica** (richiede competenza tecnica per interpretare output di più tool).

```
TRIGGER: alert da US-CERT → "Vulnerabilità X" ha un picco di sfruttamento
         + lista di IP osservati mentre scansionano Internet
   ↓
1. Recupera la lista di IOC dal report
2. Cercali nel SIEM (dove confluiscono i log dei firewall perimetrali)
3. Query: IP sorgente nei log == IP del report
4. Finestra storica tipica: ULTIMI 7 GIORNI
5. Risultato: quegli IP hanno già scansionato il nostro range pubblico?
   ↓
SE MATCH:
   → valuta blocco IP (dipende dalla natura dell'IP)
   → imposta ALERT per rilevare se riprendono a scansionare
```
**Fonti di IOC che innescano un TEC:** vendor TI, partner di sharing (**ISAC**), **avvisi governativi** (US-CERT, NCCIC, NCSC, CISA), OSINT.

🧠 **Collegamento TI ↔ Vulnerability Management:** una vuln **HIGH/CRITICAL** potrebbe non essere mai sfruttata, mentre una **MEDIUM** può essere sfruttata massicciamente. **Exploitation attiva in the wild → patching immediato**, a prescindere dal punteggio CVSS.

### Watchlist / IOC Monitoring
**Automazione del TEC** — invece di cercare manualmente ogni volta, il SIEM/EDR monitora in continuo.
```
TI Analyst riceve lista IP malevoli (C2, scan, hosting malware)
 → crea WATCHLIST nel SIEM: alert se uno di quegli IP appare come IP sorgente O destinazione
 → dipendente clicca un link di phishing → connessione a IP monitorato
 → alert automatico → Security Analyst investiga e protegge l'utente
```
**Divisione dei ruoli:** il **TI Analyst** crea/configura la watchlist · il **Security Analyst (SOC)** gestisce l'alert quando scatta.

**Retention IOC (buona pratica):**
| Tipo IOC | Retention | Auto-expiry | Review |
|---|---|---|---|
| IOC APT critici | 2+ anni | No | Trimestrale |
| Malware commodity | 6–12 mesi | Sì | Mensile |
| Infrastruttura phishing | 3–6 mesi | Sì | Bisettimanale |
| Sospetto non confermato | 30–90 giorni | Sì | Settimanale |

### Public Exposure Check
Cosa è **pubblicamente visibile** sulla tua organizzazione, e come può essere sfruttato.

⚠️ **Non confondere con Threat Exposure Check**: TEC = IOC **dentro** il tuo ambiente · Public Exposure Check = info **fuori**, esposte al mondo.

**Monitoraggio social media — 4 aree:**
| Area | Rischio |
|---|---|
| **Metadati immagini** | Marca/modello dispositivo, **nome dispositivo** ("iPhone di Josh"), data/ora, a volte **coordinate GPS** → posizione esatta dell'ufficio |
| **Informazioni trapelate** | Nel contenuto visivo: schermi con OS/software aziendali, lavagne con diagrammi riservati, **post-it con credenziali** |
| **Segnali di insider threat** | Dipendente che twitta di odiare il lavoro e che "farà qualcosa" → monitoraggio con tool forensi come **DTEX** |
| **Brand impersonation** | ≠ **account hijacking** (richiede credenziali). L'**imitazione non richiede nulla**: basta creare profilo/sito/app simile → danno reputazionale, phishing verso i tuoi clienti, **perdita di ricavi** |

**Data breach dumps:** il **riutilizzo password** è il vero problema. Esempio: dipendente in viaggio usa la **mail aziendale** per prenotare un hotel (rimborso spese) → hotel violato → credenziali aziendali nel dump → **credential stuffing**. Le società TI si infiltrano nei marketplace dark web e acquistano i dump **per conto dei clienti**, dando accesso solo ai dati rilevanti per la loro org.

---

## 9. MISP — LA PARTE PRATICA ⭐

> Questo è il tool del dominio nell'esame. Le sezioni seguenti sono quelle da avere davvero pronte.

### Cosa fa MISP
Piattaforma **open source**, community-driven (**CIRCL** = organizzazione dietro MISP), usata da **6.000+ organizzazioni**.
- Archivia info **tecniche e non tecniche** su malware/attacchi
- **Correla automaticamente** relazioni tra attributi e indicatori
- Formato **strutturato** → usabile da sistemi di detection/forensi
- Genera **regole NIDS** importabili (IP, domini, hash, pattern in memoria)
- Condivide con **partner fidati**; evita **lavoro duplicato** tra organizzazioni
- Archivia **localmente** i dati da altre istanze (riservatezza sulle query)

**Accesso:** interfaccia **web** (analisti) · **API REST** (sistemi automatizzati push/pull)

### I 4 livelli di distribuzione (Distribution)
```
1. Your organisation only        (privato)
2. This community only
3. Connected communities
4. All communities               (pubblico)
```
+ **Sharing groups** settoriali (es. settore finanziario).

### Correlazione e funzionalità
- **Fuzzy hashing correlation** (es. **ssdeep**) → trova file *simili*, non solo identici
- **CIDR block matching** → correla IP dentro range di rete
- Correlazione abilitabile/disabilitabile **per singolo attributo o evento**
- **Event graph** → visualizza relazioni tra oggetti e attributi
- **MISP warning lists** → ⚠️ riducono i **falsi positivi** (es. IP di Google DNS, range privati) durante la creazione di eventi
- **MISP Galaxy** → collega eventi/IOC a cluster di **threat actor** e tecniche **MITRE ATT&CK**

### Import / Export
| | Formati |
|---|---|
| **Export** | IDS output, **OpenIOC**, plain text, CSV, MISP XML/JSON, **STIX v1 e v2** (XML/JSON), formato cache (tool forensi), **NIDS** (Snort, Suricata, Bro/Zeek), zona **RPZ**, altri via moduli |
| **Import** | Bulk, batch, **OpenIOC**, GFI Sandbox, ThreatConnect CSV, formato MISP standard, **STIX 1.1/2.0**, altri via moduli |

### Setup (dev, NON production-ready)
```bash
# 1. Import appliance .ova in VirtualBox
# 2. Login VM:  misp / Password1234
sudo apt install net-tools                    # per avere ifconfig
# 3. Metti la VM in BRIDGED MODE → riavvia → ottieni IP proprio
ifconfig                                      # es. 192.168.1.248
# 4. Imposta il baseurl (evita problemi con "localhost")
sudo /var/www/MISP/app/console/cake baseurl https://192.168.1.248
# 5. Da browser sull'host: https://192.168.1.248
#    Login web:  admin@admin.test / admin  → richiesto cambio password
```
**Verifica baseurl:** `Administration → Server Settings and Maintenance → tab MISP settings` → controlla `MISP.baseurl`

### Utenti e organizzazioni
```
Administration → List Users → Add User          (username + organizzazione)
Administration → List Organisations → Edit/New  (nome, nazionalità, settore)
```

### Importare intelligence dai feed
```
Sync Actions → List Feeds
 → abilita i feed desiderati (di DEFAULT quasi tutti sono DISABILITATI)
 → icona freccia giù = PULL degli eventi da quel feed
```
⚠️ **Problema classico:** i job restano **pending** e non vedi nulla → i **worker** non sono attivi:
```bash
sudo -u www-data bash /var/www/misp/app/console/workers/start.sh
```
→ torna alla dashboard: i worker diventano **"alive"** e processano gli eventi.

### Dashboard
Widget utili: **MISP workers** (processi backend attivi) · **Trending tags** (si popola quando arriva intelligence).

### Esplorare un evento
```
Event List → icona OCCHIO per aprire
```
Cosa trovi: **publisher** (es. CIRCL) · **tag** assegnati · **IOC** in fondo · **link diretti a VirusTotal** · se l'evento ha **MITRE ATT&CK** mappato → **Attack Matrix** cliccabile con le tattiche associate.

### Creare un evento custom + aggiungere IOC ⭐
```
Add Event
 → Event Info (nome, es. "APT28 NCSC Report")
 → Threat Level (undefined / low / medium / high)
 → Distribution: es. "Your organisation only"
 → Submit

# Poi, per popolarlo di IOC:
Freetext Import Tool
 → incolla la lista grezza di IOC (domini, IP C2, hash... da un report)
 → pulisci/verifica il parsing
 → Submit → MISP assegna AUTOMATICAMENTE categoria e tipo a ogni IOC
 → Submit finale → i worker importano
```
**Tag:** se non esiste un tag specifico (es. "APT28"), usa tag esistenti pertinenti (**APT**, **OSINT**) per classificare l'evento.

🧠 **Il Freetext Import Tool è la skill MISP più probabile in un task**: ti danno una lista di IOC da un report e devi inserirli correttamente in un evento.

---

## 10. TIP E FONTI

### Cosa sono i TIP (Threat Intelligence Platform)
Software (SaaS o on-prem) per gestire grandi volumi di threat intel: attori, campagne, firme, bollettini, TTP.

**3 funzionalità core:**
1. **Aggregazione e normalizzazione** da più fonti
2. **Integrazione** con controlli esistenti (firewall, IPS, EDR)
3. **Analisi e condivisione**

**3 gruppi beneficiari (secondo Anomali):**
| Gruppo | Cosa ottiene |
|---|---|
| **SOC** | **Automazione** dei task di routine: integrazioni, arricchimento, scoring |
| **Team TI** | Una **"libreria"** centralizzata per fare previsioni su associazioni tra attori/campagne |
| **Dirigenza** | **Una singola piattaforma** per report tecnici e di alto livello |

**Fonti supportate:** open source · terze parti a pagamento · governo · **ISAC** · interne
**Formati:** **STIX/TAXII** · JSON/XML · email · CSV, TXT, PDF, Word

### Prodotti TIP — chi fa cosa
| Prodotto | Caratteristica distintiva |
|---|---|
| **MISP** | **Open source**, community-driven, 6.000+ org, semplice, usato nel corso |
| **ThreatConnect** | Ingestione da **qualunque formato** (email, RSS, blog) + **"runbook"** (automazioni decisionali) |
| **Anomali** | Usato da vari **ISAC** (incluso **FS-ISAC**); permette di **creare il proprio ISAC**; ha un **"app store"** per integrazioni e feed |
| **ThreatQ** | Approccio **"threat-centric"**; supporta anche Vulnerability Management, Spear Phishing, IR, **Threat Hunting** |
| **OpenCTI** | *(citato tra i tool BTL1)* alternativa open source a MISP |

### OSINT vs a pagamento
| | **OSINT (gratuito)** | **A pagamento** |
|---|---|---|
| Pro | Ottimo **punto di partenza** per costruire una capacità TI da zero; utile anche a ricercatori indipendenti | Contenuto curato, segmentato per settore |
| Contro | ⚠️ **Le fonti vanno sempre verificate** | Molto costoso; realistico solo per grandi org con team TI dedicato |

**Fonti OSINT (dal corso):** Tweet IOC · **Spamhaus** · **URLhaus** (abuse.ch) · **AlienVault OTX** · VirusShare · threatfeeds.io · Anomali Weekly Threat Briefing · **CISA AIS** (Automated Indicator Sharing) · **SANS Internet Storm Center** · **Talos Intelligence** (free)

**Vendor a pagamento:** **FireEye** (vende pacchetti **per settore**) · **Recorded Future** · **CrowdStrike** · **Flashpoint** · **Intel471**

📌 **Conclusione del corso:** la soluzione ideale è la **combinazione** di OSINT + intelligence a pagamento. In ogni caso: **metti sempre in discussione e verifica** ogni fonte.

### ISAC (Information Sharing and Analysis Center)
Gruppi di organizzazioni dello **stesso settore** che condividono intelligence.
| ISAC | Settore |
|---|---|
| **FS-ISAC** | Financial Services |
| **H-ISAC** | Healthcare |
| **E-ISAC** | Energy / Utilities |
| **Aviation ISAC** | Aviazione |
| **Auto-ISAC** | Automotive |

### IOC/TTP Gathering — il principio chiave
⚠️ **Filtrare, non assimilare tutto.** Raccogliere IOC per **ogni** attacco esistente genera **rumore** e sommerge i difensori di falsi positivi.
→ Criterio corretto: **solo attori con probabilità reale di colpire la TUA organizzazione**.
*Esempio: un attore che colpisce le banche è irrilevante per il team TI di un'azienda aerospaziale.*

**Flusso tipico (chi fa cosa):**
```
Analista STRATEGICO      → riceve/filtra (contatti ISAC, avvisi governativi)
        ↓
Analista TATTICO         → esegue il Threat Exposure Check nel SIEM
        ↓
Team SOC (tutti)         → riceve una email di SITUATIONAL AWARENESS
```

---

## 11. TLP E PAP

### ⚠️ ATTENZIONE — TLP 1.0 vs TLP 2.0
Il corso BTL1 insegna **TLP 1.0** (con `TLP:WHITE`). Lo standard attuale è **TLP 2.0**, pubblicato da **FIRST** nell'**agosto 2022**:
- **`TLP:WHITE` → rinominato `TLP:CLEAR`** (significato identico, `WHITE` è **deprecato**)
- **Aggiunto `TLP:AMBER+STRICT`** = solo la propria organizzazione, **non condivisibile con i clienti**
- CISA è passata ufficialmente a TLP 2.0 il **1 novembre 2022**

👉 **In esame:** se la domanda usa la terminologia del corso, rispondi `WHITE`. Sappi che nel mondo reale (e in eventuali materiali aggiornati) è `CLEAR`. Nota anche: `TLP:BLUE` **non è mai esistito** in nessuna versione dello standard — se lo vedi in una grafica, è sbagliata.

### Le classificazioni TLP
| TLP 1.0 (corso) | TLP 2.0 (attuale) | Chi può vederla |
|---|---|---|
| ⚪ **WHITE** | ⚪ **CLEAR** | **Pubblico**, nessun limite di divulgazione (copyright ancora applicabile) |
| 🟢 **GREEN** | 🟢 **GREEN** | **Community specifica** (es. **ISAC**) — mai pubblicamente su Internet |
| 🟠 **AMBER** | 🟠 **AMBER** | Organizzazione **+ clienti**, su base **need-to-know** |
| — | 🟠 **AMBER+STRICT** | **Solo** la propria organizzazione (no clienti) |
| 🔴 **RED** | 🔴 **RED** | **Solo i destinatari/presenti** — nessuna ulteriore divulgazione |

**Origine:** creato nei primi anni 2000 dal **National Infrastructure Security Coordination Center** (governo UK). Non nato per la cybersecurity, ma adottato dal settore.
**Scopo:** permettere all'**autore originale** di dichiarare **come** vuole che l'informazione sia diffusa.
🧠 **L'intero protocollo si basa sulla fiducia** — non violare mai il livello indicato.

**Esempi tipici:**
| Contenuto | Livello |
|---|---|
| Report di analisi malware CISA con IOC pubblici | **WHITE/CLEAR** |
| IOC condivisi con i membri del proprio ISAC dopo un attacco APT33 (settore aviazione) | **GREEN** — nota: i concorrenti sapranno che sei stato colpito (rischio reputazionale) |
| **Report di penetration test, red team engagement, risultati di vulnerability scan** | **AMBER** — contengono falle sfruttabili |
| Threat hunt che scopre un avversario con **Domain Admin** in rete → riunione con **SIRT** | **RED** — nessuna fuga di info, l'avversario non deve sapere di essere stato scoperto |

### PAP (Permissible Action Protocol)
Concettualizzato nel **2016** sotto la guida di **MISP**.

🧠 **Differenza fondamentale:**
- **TLP** = *"a CHI posso mostrare questa informazione?"*
- **PAP** = *"COSA posso FARE con questa informazione?"*

| Livello | Azioni permesse | Esempi |
|---|---|---|
| ⚪ **PAP:CLEAR** | Azioni **pressoché libere** (rispettando vincoli legali/licenza) | Gestione fluida ma conforme |
| 🟢 **PAP:GREEN** | Azioni **difensive controllate, non intrusive** | Bloccare traffico in ingresso al **firewall**; bloccare traffico in uscita via **proxy** |
| 🟠 **PAP:AMBER** | **Solo gestione passiva** — le azioni non devono essere rilevabili dall'attaccante. ⚠️ **Vietata ogni comunicazione diretta o indiretta con il threat actor** | Usare piattaforme OSINT/repository per capire meglio i dati raccolti |
| 🔴 **PAP:RED** | **Solo detection e investigazione**, need-to-know. Infrastruttura **segregata** dal sistema generale. **Vietato** ogni contatto con servizi/dispositivi esterni. Azioni **invisibili** all'avversario | Ricerca in **ambienti non di produzione** su log storici. Team: **Threat Hunting** e **Incident Response** |

**Esempi pratici per fissarli:**
- Bloccare un IP al firewall → **PAP:GREEN**
- Cercare un hash su VirusTotal senza toccare l'infrastruttura dell'attaccante → **PAP:AMBER**
- Threat hunting su log storici in ambiente isolato → **PAP:RED**

💡 Negli eventi MISP trovi spesso **entrambi** i tag (TLP **e** PAP) — sapere distinguerli a colpo d'occhio serve nel task pratico.

---

## 12. VULNERABILITY INTELLIGENCE

| | **CVE** | **CVSS** | **VPR / EPSS** |
|---|---|---|---|
| Cos'è | **Identificatore univoco** di una vulnerabilità pubblica | **Punteggio di gravità** (0–10) basato sugli attributi | Punteggio **predittivo** di probabilità di sfruttamento |
| Formato | `CVE-ANNO-NUMERO` (es. **CVE-2019-0708** = vuln critica **RDP**) | `8.8 HIGH` | Dinamico |
| Limite | **Nessuna indicazione di priorità** | ⚠️ **Statico e generico** | Richiede threat intelligence |
| Uso | Tracciamento e comunicazione | Valutazione iniziale | **Prioritizzazione del patching** |

**Fonti CVE:** **NVD** (National Vulnerability Database, offerto da **NIST**) · **CVEDetails.com**

### I 2 limiti del CVSS "puro"
1. **Non conosce la tua infrastruttura** → una vuln **10.0 CRITICA** su Solaris non ha impatto su un'azienda 100% Windows
2. **Non conosce lo sfruttamento reale** → una CRITICAL tecnicamente complessa può non essere mai sfruttata, mentre una **HIGH attivamente sfruttata in the wild** è un rischio maggiore

### VPR (Tenable) — il case study del corso
**Prioritizzazione predittiva** = dati di vulnerabilità **+** threat intelligence → **VPR** (Vulnerability Priority Rating).
- Valore **dinamico** (il CVSS è statico)
- Se una vuln "silenziosa" inizia a essere sfruttata **in the wild** → il **VPR sale**
- Obiettivo dichiarato: *"concentrarsi prima sui problemi di sicurezza che contano di più"*

💡 **EPSS** (Exploit Prediction Scoring System) è l'equivalente **aperto e vendor-neutral** dello stesso concetto: stima la probabilità che una CVE venga sfruttata nei prossimi 30 giorni. Non è nel corso ma è lo standard che troverai nel lavoro reale.

🧠 **Il concetto da portarsi via:** distinguere **"critica sulla carta"** da **"critica perché attivamente sfruttata"**. È il cuore del capitolo e il collegamento diretto tra TI e Vulnerability Management.

---

## 13. WORKFLOW DI PIVOTING SU UN IOC

Il task pratico tipico: ti danno **un indicatore** e devi arrivare a un contesto utile.

### Da un IP
```
1. WHOIS → chi lo possiede, ASN, geolocalizzazione, range
2. Reverse DNS → hostname reale
3. AbuseIPDB / VirusTotal → reputazione, segnalazioni, categoria di abuso
4. VirusTotal tab "Relations" → domini che risolvono/hanno risolto su quell'IP,
   file che lo contattano, URL ospitati
5. Cerca l'IP in MISP → è già in un evento noto? di quale attore?
6. Se collegato a un attore → attack.mitre.org/groups/ → quali altri TTP usa?
```

### Da un dominio
```
1. WHOIS → ETÀ DI REGISTRAZIONE (< 30 giorni = molto sospetto), registrar, registrante
2. Passive DNS → su quali IP ha risolto nel tempo (rivela l'infrastruttura)
3. VirusTotal / URLhaus / PhishTank → reputazione
4. URLScan.io / URL2PNG → screenshot SENZA visitarlo
5. Confronta con domini legittimi → typosquatting? homoglyph?
6. MISP → già presente in un evento?
```

### Da un hash
```
1. VirusTotal → detection ratio, nomi delle famiglie malware, prima/ultima analisi
2. Talos File Reputation → secondo parere
3. VirusTotal tab "Behavior" o sandbox (Hybrid Analysis / Any.run)
   → IP/domini contattati, file droppati, chiavi di registro, mutex
   → NUOVI IOC da cui ripartire
4. Mappa il comportamento osservato su MITRE ATT&CK
5. MISP → fuzzy hashing (ssdeep) trova varianti SIMILI, non solo identiche
```

### Da un URL
```
1. Se abbreviato → WannaBrowser (risolvi la redirect chain SENZA cliccare)
2. URLScan.io → screenshot + risorse caricate + IP di hosting
3. VirusTotal / URLhaus / PhishTank
4. Estrai il dominio root → riparti dal workflow "da un dominio"
```

🧠 **Principio del pivoting:** ogni indicatore analizzato **genera nuovi indicatori**. Ti fermi quando hai abbastanza contesto per rispondere alla domanda, non quando hai esaurito i pivot possibili.

---

## 14. CHECKLIST E PITFALL

### Checklist pre-task
- [ ] Che tipo di indicatore ho? (IP / dominio / hash / URL / email)
- [ ] Il task chiede **contesto** (chi/cosa) o un'**azione** (crea evento, blocca, mappa su ATT&CK)?
- [ ] Se è MISP: i **worker** sono attivi? (`start.sh`)
- [ ] Se devo importare IOC: sto usando il **Freetext Import Tool**?
- [ ] Se devo classificare: serve un tag **TLP** e/o **PAP**?
- [ ] Se devo mappare un comportamento: ho l'ID tecnica corretto (`Txxxx`, non `TAxxxx`)?
- [ ] Il **formato della risposta** richiesto è rispettato? (nome esatto del gruppo/tecnica, ID completo, defanged o no)

### Pitfall comuni
| Errore | Conseguenza | Fix |
|---|---|---|
| MISP: job **pending**, nessun evento visibile | Sembra che il pull non funzioni | Avvia i worker: `sudo -u www-data bash /var/www/misp/app/console/workers/start.sh` |
| MISP: feed abilitati ma nessun dato | Di default i feed sono **disabilitati** | `Sync Actions → List Feeds` → abilita **e** fai il pull (freccia giù) |
| MISP: risorse non caricate / redirect a localhost | `baseurl` non impostato | `cake baseurl https://<IP>` + verifica in MISP settings |
| Confondere **tattica** e **tecnica** ATT&CK | ID sbagliato nella risposta | Tattiche = `TA00xx` · Tecniche = `Txxxx` |
| Usare `TLP:WHITE` in contesto moderno | Terminologia deprecata | `TLP:CLEAR` (dal 2022). In esame segui il corso |
| Confondere **TLP** e **PAP** | Risposta invertita | TLP = **a chi lo mostro** · PAP = **cosa posso fare** |
| Confondere **precursore** e **IOC** | Categorizzazione sbagliata | Precursore = **prima** dell'attacco · IOC = **durante/dopo** |
| Confondere **Threat Exposure Check** e **Public Exposure Check** | Risposta sul workflow sbagliato | TEC = IOC **dentro** il tuo ambiente (SIEM) · PEC = info **esposte fuori** |
| Confondere **STIX** e **TAXII** | Risposta invertita | STIX = **formato** · TAXII = **trasporto** |
| Confondere i sotto-team di **Lazarus** | Attribuzione sbagliata | **BlueNoroff** = banche/finanziario · **AndAriel** = spionaggio governativo |
| Attribuire in base a un solo indizio (es. cirillico) | Cadi in un **false flag** | Serve convergenza di più indicatori (tradecraft + infrastruttura + malware + intento) |
| Fidarsi di un singolo hash come IOC duraturo | Pyramid of Pain: banale da cambiare | Sali di livello: artefatti, tool, **TTP** |
| Raccogliere IOC di **tutti** gli attori esistenti | Rumore, falsi positivi, alert fatigue | Filtra per **rilevanza settoriale** |
| Cercare la naming convention Microsoft "elementi chimici" | Informazione **datata** (pre-2023) | Convenzione attuale = **meteo** (Blizzard/Typhoon/Sandstorm/Sleet/Tempest) |

---

*Fonti: materiale corso BTL1 (Threat Intelligence domain) + cheat sheet pubbliche consolidate + verifica online su TLP 2.0 (FIRST, ago 2022) e taxonomy Microsoft (apr 2023).*
