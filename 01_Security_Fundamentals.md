## Security Fundamentals

> Esame: 24h, 20 task pratici, open-book, soglia 70%.
> Questo dominio è **il più teorico** dei sei, ma è la base su cui poggiano tutti gli altri: quando in un task devi capire *dove* sta operando un attacco o *quale controllo* è mancato, la risposta viene da qui.

---

## 0. INDICE RAPIDO

| Cerco... | Sezione |
|---|---|
| Tipi di controllo (preventivo/detective/correttivo) | §1  |
| HIDS vs HIPS, AV, EDR, vuln scan | §2 |
| NIDS vs NIPS vs Firewall vs NAC | §3 |
| Spam filter, DLP, anti-phishing | §4 |
| Authentication / Authorization / Accountability | §5 |
| TCP vs UDP, OSI, IP/MAC, device di rete | §6 |
| Tabella porte | §7 |
| Comandi di rete + Nmap | §8 |
| Risk management (4 strategie) | §9 |
| Policy, SOP, AUP, SLA, MOU | §10 |
| GDPR, ISO 27001, PCI DSS, HIPAA | §11 |
| Change & patch management, WSUS/SCCM | §12 |
| Active Directory (oggetti, OU, SID, GPO, forest) | §13 |
| Kerberos, NTLM, LDAP | §14 |
| Pitfall e confusioni comuni | §15 |

---

## 1.  TIPI E CATEGORIE DI CONTROLLI

### CIA Triad — i 3 obiettivi della sicurezza
| Principio | Significato | Come si rompe | Come si protegge |
|---|---|---|---|
| **Confidentiality** | Solo chi è autorizzato accede | Data breach, sniffing, accesso non autorizzato | Cifratura, access control, MFA |
| **Integrity** | I dati non sono alterati non autorizzatamente | Manomissione, MITM, ransomware | Hashing, firme digitali, checksum |
| **Availability** | I dati/servizi sono accessibili quando servono | DDoS, ransomware, guasto hardware | Ridondanza, backup, load balancing |

💡 Utile come griglia mentale: quando descrivi l'impatto di un incidente, dì **quale** pilastro è stato colpito.

### Per funzione (quando agisce il controllo)
| Categoria | Quando agisce | Esempi |
|---|---|---|
| **Preventive** | **Prima** — impedisce che l'evento accada | Firewall, MFA, patch, NAC, awareness training, badge |
| **Detective** | **Durante/dopo** — rileva e avvisa | **IDS**, SIEM, log monitoring, CCTV, antivirus (scan), audit |
| **Corrective** | **Dopo** — ripristina/limita il danno | Backup restore, **IPS** (blocco), quarantena file, patch post-incidente |
| *(anche)* **Deterrent** | Scoraggia | Cartelli di sorveglianza, warning banner |
| *(anche)* **Compensating** | Alternativa quando il controllo primario non è applicabile | Segmentazione di rete su un sistema EOL non patchabile |

### Per natura (come è implementato)
| Tipo | Esempi |
|---|---|
| **Physical** | Serrature, badge/RFID, tornelli, guardie, CCTV, gabbie server, mantrap |
| **Technical / Logical** | Firewall, AV, EDR, cifratura, ACL, IDS/IPS |
| **Administrative** | Policy, procedure, awareness training, background check, segregation of duties |

🧠 **Domanda tipica:** *"Un firewall che blocca il traffico è che tipo di controllo?"* → **Preventivo** e **tecnico**. Un IDS che genera alert → **detective**. Un IPS che blocca → **preventivo/correttivo**.

---

## 2. ENDPOINT SECURITY

| Controllo | Cosa fa | Agisce da solo? |
|---|---|---|
| **HIDS** (Host IDS) | Software sull'endpoint, analizza l'attività con regole e **genera alert** (o li manda al SIEM) | ❌ **No** — solo avvisa |
| **HIPS** (Host IPS) | Come HIDS **+ risposta automatica**: termina connessioni, cancella file malevoli | ✅ **Sì** |
| **Antivirus** | Vedi sotto | Dipende |
| **EDR** | Agente silenzioso: logging + monitoring + **response**. Permette all'analista di investigare dalla piattaforma (processi attivi, forensics, comportamento utenti → utile anche per **insider threat**) | ✅ Sì |
| **Log Monitoring** | Gli endpoint mandano log a un **SIEM** centralizzato che normalizza e applica regole di detection. Protocollo classico: **Syslog** | ❌ Detective |

### Antivirus — i 2 approcci
| Approccio | Come funziona | Punto debole |
|---|---|---|
| **Signature-based** | Confronta i file con **firme di malware noti** | ❌ Malware **sconosciuto o modificato** passa (basta cambiare un byte → hash diverso — vedi *Pyramid of Pain*) |
| **Behavior-based** | Costruisce una **baseline** di attività normale e flagga le anomalie | ✅ Più efficace su minacce nuove/zero-day; ⚠️ più falsi positivi |

### Vulnerability Scanning
| Dimensione | Opzioni | Differenza |
|---|---|---|
| **Posizione** | **Esterna** vs **Interna** | Esterna = simula la **vista dell'attaccante da fuori**; Interna = più completa ma non riflette un attaccante esterno (a meno che sia già dentro) |
| **Credenziali** | **Credentialed** vs **Non-credentialed** | Con credenziali = **molti più dati** (versioni software, configurazioni); senza = simula meglio uno scan esterno |

**Compliance Scanning** = variante del vuln scan orientata a verificare la conformità a un **framework specifico** (PCI-DSS, ISO 27001...) — non cerca "vulnerabilità" ma **deviazioni dal requisito**.

---

## 3. NETWORK SECURITY

### NIDS — 3 modalità di posizionamento
| Modalità | Come | Nota |
|---|---|---|
| **Inline** | Sta **nel mezzo** del flusso di traffico | ⚠️ Per definizione diventa un **NIPS**, perché può bloccare attivamente |
| **Network Tap** | Si aggancia **fisicamente** a un cavo di rete | Passivo, invisibile |
| **Passive / SPAN port** | Riceve una **copia speculare** del traffico da una porta dedicata sul device | Il metodo più comune per un NIDS puro |

### Confronto controlli di rete
| | **NIDS** | **NIPS** | **Firewall** | **NAC** |
|---|---|---|---|---|
| Deployment | Passivo (SPAN/tap) | **Inline** | Inline | Inline |
| Funzione | **Detection + alert** | **Prevention + blocco** | Filtraggio traffico | Controllo accessi |
| Impatto performance | Minimo | Moderato | Basso | Moderato |
| **Failure mode** | **Fail open** (nessun impatto sul traffico) | **Fail closed** (blocca) | Fail closed | Fail closed |
| Caso d'uso | Monitoraggio, forensics | Prevenzione attiva | Sicurezza perimetrale | Compliance dei device |

🧠 **Esempio NIPS dal corso:** un host interno inizia a fare **port scan** → il NIPS **blocca automaticamente** le sue comunicazioni e genera un alert.

### Firewall — 3 forme
| Forma | Dove | Esempio |
|---|---|---|
| **Standard** | Hardware dedicato in punti chiave della rete | Firewall perimetrale |
| **Local (software)** | Sull'endpoint | Windows Firewall |
| **WAF** (Web Application Firewall) | Davanti ai web server esposti | Protegge da SQLi, XSS |

Funzione base: separa segmenti di rete creando **zone private**, controllando traffico in ingresso e uscita.

### Log Monitoring di rete — 2 fonti d'oro
| Fonte | Cosa ti dà |
|---|---|
| **Web Proxy Logs** | Tutti i siti visitati → combinabile con **blacklist** per alert su siti malevoli |
| **Perimeter Firewall Logs** | Rileva **port scan**, **vulnerability scan**, **DDoS** in ingresso |

### NAC (Network Access Control)
Impedisce a **dispositivi non conformi** di connettersi. Può richiedere: patch aggiornate, AV attivo, versione OS minima.
Usato tipicamente per reti **BYOD** o **guest**. Tecnologie collegate: **802.1X**, certificati.
💡 Esempio quotidiano: il wifi del bar che ti fa registrare prima di navigare.

---

## 4. EMAIL SECURITY

> 🔗 Questo argomento si sovrappone al dominio **Phishing Analysis** — per SPF/DKIM/DMARC in dettaglio, spam filter (gateway/hosted/desktop, content/rule-based/Bayesian) e blocco artefatti, vedi la cheat sheet Phishing §3 e §8.

**Sintesi essenziale:**
| Meccanismo | Domanda a cui risponde |
|---|---|
| **SPF** | Quali server sono autorizzati a spedire per questo dominio? (record DNS TXT) |
| **DKIM** | Il contenuto è stato manomesso? (firma crittografica + chiave pubblica nel DNS) |
| **DMARC** | Cosa faccio se SPF/DKIM falliscono? (`p=none` / `p=quarantine` / `p=reject`) |

**Altri controlli email:**
| Controllo | Funzione |
|---|---|
| **Spam filter** | 3 livelli: **gateway** (on-prem), **hosted** (cloud), **desktop**. 3 meccanismi: **content filter**, **rule-based**, **Bayesian** (ML sul comportamento utente) |
| **Email scanning / sandboxing** | Analizza allegati e URL in ambiente isolato prima della consegna |
| **DLP** (Data Loss Prevention) | Previene l'**esfiltrazione** di dati sensibili via email (anche se l'utente risponde a un attaccante) |
| **Marcatura email esterne** | Banner "questa email viene dall'esterno" |
| **Anti-phishing / awareness training** | Simulazioni: GoPhish, Sophos Phish Threat, PhishingBox |

---

## 5. AAA

```
Authentication  → sei chi dici di essere
      ↓
Authorization   → ecco cosa puoi fare
      ↓
Accountability  → ogni tua azione è registrata
```
🧠 Tre layer complementari: **mancarne uno indebolisce tutto il sistema**.

### Authentication — i 3 fattori
| Fattore | Esempi | Punto debole |
|---|---|---|
| **Something you know** | Password, PIN, security question | Può essere **rubata o indovinata** |
| **Something you have** | Badge RFID, token fisico, chiave, smartphone | Può essere **rubato o clonato** |
| **Something you are** | Impronta, Face ID, retina (biometria) | **Difficilissimo da bypassare** |

**MFA** = almeno **2 fattori di categorie diverse**. Un attaccante che ruba la password non entra senza il tuo telefono.
⚠️ Due password **non** sono MFA (stesso fattore).

### Authorization
Cosa può fare l'utente autenticato. Si basa sul **Principle of Least Privilege**: solo i permessi **strettamente necessari** al ruolo.

Tecnologie: **RBAC** (Role-Based Access Control), **ACL**, security group, policy.

💡 Esempio pratico: un analista **Tier 1** accede all'interfaccia del SIEM per investigare, ma **non** al backend dove si configurano le regole → se il suo account viene compromesso, il danno è limitato.

### Accountability
Capacità di ricostruire **chi ha fatto cosa e quando** tramite log e **audit trail**. Fondamentale per IR **e** insider threat.

**2 scenari dal corso:**
- Dipendente cancella file SharePoint **alle 2 di notte** → log di login + log SharePoint lo inchiodano
- Furto di attrezzatura → log accessi fisici + **CCTV** permettono di capire se era davvero John o qualcuno con la sua **card clonata**

---

## 6. NETWORKING 101

### TCP vs UDP vs ICMP
| | **TCP** | **UDP** |
|---|---|---|
| Connessione | ✅ Sì (**three-way handshake**) | ❌ No (connectionless) |
| Affidabilità | **Alta** (ritrasmette i pacchetti persi, garantisce ordine) | Bassa |
| Velocità | Più lento | **Più veloce** |
| Uso tipico | HTTP/S, SMTP, FTP, SSH | **DNS**, streaming, VoIP, gaming |

**Three-way handshake:**
```
Client → Server:  SYN       (voglio connettermi)
Server → Client:  SYN-ACK   (ok, accetto)
Client → Server:  ACK       (ricevuto, inizio a trasmettere)
```
🧠 Rilevante in security: un **SYN flood** (DoS) invia molti SYN senza mai completare con l'ACK, esaurendo le risorse del server.

**ICMP** — non trasporta dati applicativi, serve a **diagnosticare la rete**. `ping` usa ICMP. Usato principalmente da router e device di rete.

### IP e MAC
**IP privati (non routabili su Internet):**
| Range CIDR | Intervallo | N. indirizzi |
|---|---|---|
| `10.0.0.0/8` | 10.0.0.0 – 10.255.255.255 | 16.777.216 |
| `172.16.0.0/12` | 172.16.0.0 – 172.31.255.255 | 1.048.576 |
| `192.168.0.0/16` | 192.168.0.0 – 192.168.255.255 | 65.536 |

**IP pubblici** → assegnati dall'ISP, visibili su Internet.
**Statici** (configurati manualmente, non cambiano) vs **Dinamici** (assegnati via **DHCP**, possono cambiare).

**MAC Address** — identificatore hardware della scheda di rete, **6 byte esadecimali** (es. `00:0d:83:b1:c0:8e`).
| | MAC | IP |
|---|---|---|
| Layer OSI | **2** (Data Link) | **3** (Network) |
| Ambito | Rete **locale** | LAN **e** Internet |
| Natura | Hardware (hardcoded) | Logico (assegnato) |

⚠️ Il MAC è hardcoded **ma può essere spoofato** → rilevante per **NAC bypass** e forensics di rete.

**Come si combinano:** vuoi raggiungere `www.google.com` → **DNS** traduce il nome in IP → comunichi via **TCP/UDP** → a livello fisico i pacchetti sono instradati tramite **MAC** (risolto dall'IP via **ARP**).

### Modello OSI
| # | Layer | Ruolo | Esempi | Attacchi tipici |
|---|---|---|---|---|
| **7** | **Application** | Interfaccia utente-rete | HTTP, SMTP, DNS, FTP | SQLi, XSS, phishing |
| **6** | **Presentation** | Traduzione, encoding, cifratura | TLS/SSL, compressione, JPEG | Downgrade attack |
| **5** | **Session** | Apertura/gestione/chiusura sessioni | NetBIOS, RPC, session token | Session hijacking |
| **4** | **Transport** | Trasferimento affidabile, frammentazione | **TCP, UDP** | **SYN flood**, port scan |
| **3** | **Network** | Instradamento tra reti, percorso ottimale | **IP, ICMP**, router | **IP spoofing**, routing attack |
| **2** | **Data Link** | Indirizzamento fisico, frame | **MAC**, switch, Ethernet | **ARP spoofing**, MAC flooding |
| **1** | **Physical** | Trasmissione dei bit | Cavi, fibra, Wi-Fi | Physical tampering, **network tap** |

**Mnemonici:**
- 7→1: **A**ll **P**eople **S**eem **T**o **N**eed **D**ata **P**rocessing
- 1→7: **P**lease **D**o **N**ot **T**hrow **S**ausage **P**izza **A**way

### Device di rete
| Device | Layer | Cosa fa |
|---|---|---|
| **Router** | 3 | Instrada tra **reti diverse** basandosi sull'**IP**. È il gateway verso Internet |
| **Hub** | 1 | ❌ "Dumb": riceve su una porta e fa **broadcast a tutti**. ⚠️ Un attaccante collegato **vede tutto il traffico** → praticamente obsoleto |
| **Switch** | 2 | ✅ Usa i **MAC** per inviare i dati **solo al destinatario**. Ricava il MAC dall'IP tramite **ARP** |
| **Bridge** | 2 | Collega reti separate **fondendole in una sola** |
| **Firewall** | 3–7 | Permette/blocca traffico in base a regole; separa rete privata da esterno |

🧠 **Router vs Bridge:** *Router = reti distinte che si parlano* · *Bridge = reti distinte che diventano una*
🧠 **Hub vs Switch:** broadcast a tutti (insicuro) vs solo al destinatario (sicuro)

---

## 7. PORTE E PROTOCOLLI

### I 3 range
| Range | Porte | Uso |
|---|---|---|
| **Well-known** | **0 – 1023** | Servizi standard |
| **Registered** | **1024 – 49151** | Applicazioni specifiche |
| **Private / Ephemeral** | **49152 – 65535** | Porte **sorgente** temporanee lato client |

### Tabella porte
| Porta | Servizio | Note di sicurezza |
|---|---|---|
| **20 / 21** | **FTP** | ❌ **Traffico in chiaro**, credenziali sniffabili |
| **22** | **SSH** | ✅ Cifrato. Sostituto di Telnet. Base anche di **SFTP/SCP** |
| **23** | **Telnet** | ❌ **Nessuna cifratura**, deprecato → 🚩 aperto = red flag immediato |
| **25** | **SMTP** | Trasporto email tra server. Rilevante per phishing/mail flow |
| **53** | **DNS** | **TCP + UDP**. 🔍 **DNS tunneling** = tecnica C2 comune |
| **67 / 68** | **DHCP** | UDP. Assegna IP automaticamente |
| **80** | **HTTP** | ❌ In chiaro |
| **443** | **HTTPS** | ✅ HTTP + TLS/SSL |
| **514** | **Syslog** | UDP. Invio log al **SIEM** — se un host smette di mandare qui, qualcosa non va |
| **3389** | **RDP** | 🚩 Esposto su Internet = **vettore primario**; brute force, lateral movement, ransomware |
|  **445** | **SMB** | 🚩 **Vettore di attacco molto comune** (EternalBlue/WannaCry, lateral movement, share enumeration). Da monitorare sempre |
|  **135 / 139** | RPC / NetBIOS | Legacy Windows, spesso associati a SMB e enumerazione |
|  **88** | **Kerberos** | Autenticazione AD (vedi §14) |
|  **389** | **LDAP** | ⚠️ **In chiaro** — query verso AD |
|  **636** | **LDAPS** | ✅ LDAP over TLS |
|  **110 / 995** | POP3 / POP3S | Scarica email sul client e le rimuove dal server |
|  **143 / 993** | IMAP / IMAPS | Email restano sul server, accesso multi-device |
|  **587** | SMTP submission | ✅ Invio autenticato + TLS (standard moderno per i client) |
|  **5985 / 5986** | WinRM (HTTP/HTTPS) | PowerShell remoting → lateral movement |

### Coppie insicuro → sicuro (domanda classica)
| Insicuro | Sostituto sicuro |
|---|---|
| **Telnet (23)** | **SSH (22)** |
| **HTTP (80)** | **HTTPS (443)** |
| **FTP (20/21)** | **SFTP (22)** / FTPS |
| **LDAP (389)** | **LDAPS (636)** |
| POP3 (110) / IMAP (143) | POP3S (995) / IMAPS (993) |

💡 **Tip di triage:** in un alert con connessioni sospette, la **porta di destinazione** è spesso il primo indizio. Traffico su porte non standard, **o** su porte note usate in modo anomalo (es. DNS/53 con payload enormi = **tunneling**), va sempre approfondito.

---

## 8. NETWORK TOOLS

### Comandi essenziali
```bash
# Configurazione di rete locale (primo comando in diagnostica)
ip a                                # IP delle interfacce (Linux)
ip r list                           # routing table
ip link set dev eth0 up|down        # abilita/disabilita interfaccia
ipconfig /all                       # Windows (IP, gateway, DNS, MAC)

# Percorso dei pacchetti hop-by-hop
traceroute google.com               # Linux
traceroute google.com -p 443        # su porta specifica
tracert google.com                  # Windows

# Query DNS
dig example.com                     # record A (IP)
dig example.com MX                  # mail server del dominio
dig example.com ANY +nocomments +noauthority +noadditional +nostats
dig -x 8.8.8.8                      # reverse DNS
nslookup example.com                # Windows

# Connessioni attive e porte in ascolto
netstat -a                          # tutte le connessioni e porte in ascolto
netstat -a -b                       # + l'ESEGUIBILE responsabile (Windows) ⭐
netstat -s -p tcp -f                # statistiche TCP in formato FQDN
netstat -ano                        # Windows: con PID, senza risoluzione nomi
ss -tulpn                           # equivalente moderno su Linux
```

⭐ **`netstat -a -b` su Windows è il comando chiave in IR**: ti dice **quale processo** ha aperto quella connessione sospetta → collega una connessione C2 a un eseguibile.

### Nmap
```
nmap [Scan Type] [Options] {target}
```
**Capacità:** scoprire host attivi · identificare porte aperte · rilevare **servizi e versioni** (banner grabbing) · identificare l'**OS** · scripting via **NSE** (fuori scope BTL1)

```bash
nmap -v -sT -sV scanme.nmap.org
```
| Flag | Significato |
|---|---|
| `-v` | Verbose |
| `-sT` | **TCP Connect scan** — completa il three-way handshake |
| `-sV` | **Version detection** (banner grabbing) |
|  `-sS` | SYN / "half-open" scan — più furtivo, non completa l'handshake |
|  `-sU` | UDP scan |
|  `-O` | OS detection |
|  `-p 80,443` / `-p-` | Porte specifiche / tutte le 65535 |
|  `-sn` | Host discovery senza port scan (ping sweep) |
|  `-A` | Aggressive (OS + version + script + traceroute) |

**Output — 3 colonne chiave:**
| Colonna | Significato |
|---|---|
| **PORT** | Numero di porta |
| **STATE** | `open` = raggiungibile · `filtered` = bloccata (firewall) · `closed` = raggiungibile ma nessun servizio |
| **SERVICE** | Servizio/programma in ascolto |

⚠️ **Regola non negoziabile:** mai eseguire port scan su sistemi **senza autorizzazione esplicita**. L'unico target pubblicamente autorizzato per pratica è **`scanme.nmap.org`**.

### Uso in contesto security
| Tool | Uso investigativo |
|---|---|
| `ip` / `ipconfig` | Ricognizione iniziale su host compromesso |
| `traceroute` | Mappare infrastruttura di rete |
| `dig` | Investigare domini malevoli, trovare infrastruttura **C2** |
| `netstat` | 🔍 **Rilevare connessioni C2 attive** su host infetto |
| `nmap` | Port scan, service enumeration, network discovery |

---

## 9. RISK MANAGEMENT

### Definizioni
- **Risk** → possibilità che un evento negativo si verifichi
- **Vulnerability** → debolezza sfruttabile
- **Threat** → la minaccia stessa

⚠️ **Punto chiave:** le **vulnerabilità si gestiscono, le minacce no**. Puoi patchare un sistema; non puoi eliminare l'esistenza degli attaccanti.

La probabilità che una minaccia sfrutti una vulnerabilità dipende da: **esistenza della minaccia** × **presenza della vulnerabilità** × **efficacia dei controlli**.

### Risk Assessment — 5 step
```
1. Identificare i potenziali rischi/pericoli
2. Identificare chi o cosa potrebbe essere danneggiato
3. Valutare severità e probabilità, definire precauzioni
4. Implementare i controlli e documentare
5. Rivedere e aggiornare periodicamente
```
⚠️ Devono essere **dinamiche** — il panorama delle minacce cambia continuamente.

### Le 4 strategie ⭐ (esplicitamente indicate come materia d'esame)
| Strategia | Cosa fai | Esempio |
|---|---|---|
| **Mitigation** | Applichi **controlli** per ridurre il rischio | Patch, firewall, policy |
| **Transfer** | Sposti il **costo** su terzi | **Assicurazione cyber**, outsourcing |
| **Acceptance** | Accetti **consapevolmente** perché gestirlo costa più del danno potenziale | Rischio residuo tollerabile |
| **Avoidance** | **Elimini la causa** | Dismetti un sistema vulnerabile |

**Schema decisionale:**
```
Rischio identificato
   ├─ Posso eliminarlo?                → AVOIDANCE
   ├─ Posso ridurlo con controlli?     → MITIGATION
   ├─ Posso passarlo a terzi?          → TRANSFER
   └─ Nessuna / costo troppo alto      → ACCEPTANCE
```

###  Matrice di rischio (probabilità × impatto)
| Livello | Probabilità | Impatto | Trattamento |
|---|---|---|---|
| **Critical** | Alta | Alta | **Mitigazione immediata** |
| **High** | Alta+Media / Media+Alta | — | Patching prioritario, monitoring rafforzato |
| **Medium** | Media | Media | Mitigazione pianificata |
| **Low** | Bassa | Bassa | **Accept** o monitor |

---

## 10. POLICIES AND PROCEDURES

### Gerarchia
```
POLICY        ← intento di alto livello ("cosa facciamo")      | Obbligatorio
   ↓
STANDARD      ← regole di implementazione consistente          | Obbligatorio
   ↓
PROCEDURE     ← step-by-step specifici ("come esattamente")    | Obbligatorio
   ↓
GUIDELINE     ← raccomandazioni, best practice                 | Consigliato
```
| Livello | Esempio |
|---|---|
| Policy | *"Tutti i dati devono essere protetti"* |
| Standard | *"Usare cifratura AES-256"* |
| Procedure | *"1. Installa il software 2. Configura..."* |
| Guideline | *"Considera l'uso della 2FA"* |

### Policy comuni ⭐
| Sigla | Nome | Cosa regola |
|---|---|---|
| **AUP** | Acceptable Use Policy | Cosa un utente **può e non può fare** sulla rete aziendale + conseguenze in caso di violazione |
| **SLA** | Service Level Agreement | Accordo provider↔cliente: servizi, livelli di performance, **tempi di risposta, penali** |
| **BYOD** | Bring Your Own Device | Uso di dispositivi **personali** sulla rete aziendale |
| **MOU** | Memorandum of Understanding | Accordo formale tra parti, ⚠️ **non legalmente vincolante** — spesso precede un contratto |

### SOP (Standard Operating Procedure)
Istruzioni **step-by-step** per eseguire un task in modo uniforme, riducendo errori e garantendo compliance.

**Caratteristiche:** scritte con input di chi le usa · **testate** prima dell'adozione · revisionate periodicamente · **accessibili a tutti** · possono avere varianti locali (leggi regionali)

💡 In un SOC, le SOP sono i **playbook di incident response**: dato un tipo di alert, la SOP dice cosa fare, chi coinvolgere, come documentare.

---

## 11. COMPLIANCE E FRAMEWORK

### Perché conta
Requisito **legale** in molti settori · riduce rischio e impatto degli incidenti · aumenta la **fiducia** di clienti/partner · fornisce uno **standard minimo** da raggiungere

### I 4 framework ⭐
| Framework | Ambito | Obbligo | Punti chiave |
|---|---|---|---|
| **GDPR** | Dati personali di soggetti **UE/EEA** (anche se l'azienda è fuori UE) | **Legge UE** | **6 basi legali** per il trattamento · **privacy by design** · notifica breach entro **72 ore** · diritti di accesso/portabilità/**cancellazione** · sanzioni fino a **€20 mln o 4% del fatturato globale** (il maggiore) |
| **ISO 27001** | Qualsiasi organizzazione | **Volontario** (ma richiesto da molti clienti) | Standard per un **ISMS** (Information Security Management System); certificazione da **auditor accreditati**; risk management + miglioramento continuo |
| **PCI DSS** | Chi tratta **pagamenti con carta** | **Obbligatorio** | Protezione dati titolari di carta. Validazione per volume: piccolo → **SAQ** (Self-Assessment Questionnaire) · medio → **QSA** esterno (Qualified Security Assessor) · grande → **ISA** interno + **Report on Compliance** |
| **HIPAA** | **Sanità USA** — protezione **ePHI** | **Legge USA** | Si applica **anche ai fornitori IT** che gestiscono ePHI. ePHI = nome, date (nascita/ricovero/dimissione), telefono, **SSN**, foto, indirizzo. Richiede controlli **tecnici** (cifratura, autenticazione, audit accessi, segmentazione) **e procedurali** (policy password, piani IR, audit) |

🧠 Nel tuo contesto professionale: **NIS2** è l'equivalente europeo per infrastrutture critiche — non è nel corso BTL1, ma se un task parla di settori regolamentati, il ragionamento è lo stesso di GDPR/ISO.

---

## 12. CHANGE E PATCH MANAGEMENT

### Change Management
Garantisce che ogni modifica all'infrastruttura sia **pianificata, documentata e verificabile**.

**A cosa serve in security:**
- **Accountability**: tracciare chi ha fatto cosa e quando
- Identificare rapidamente la responsabilità se una modifica introduce un rischio
- Gestire formalmente il deployment di patch, modifiche firewall, cambi di security control

**In pratica:** prima di deployare, si apre una **change request** revisionata e approvata dai **key stakeholder**.

### Patch Management
Deployment di patch e fix su tutti gli asset IT, per rimediare vulnerabilità in OS e software obsoleti.

⏱️ **Requisito tipico di compliance** (es. **Cyber Essentials+**): vulnerabilità **Critical/High** → remediate entro **14 giorni** dalla scoperta.

### Soluzioni di deployment
| Soluzione | Costo | Note |
|---|---|---|
| **WSUS** (Windows Server Update Services) | **Gratuito** (Microsoft) | Un server "upstream" scarica gli update da Microsoft Update e li distribuisce → gli endpoint **non hanno bisogno di accesso diretto a Internet** |
| **SCCM** (System Center Configuration Manager) | A pagamento | Usa **WSUS come backend** + controllo granulare su quando/come applicare. Include **asset inventory** e software deployment. ⚠️ Limite: pensato per Windows, gestione Mac/Linux macchinosa |
| **Commerciali** (es. ManageEngine Patch Manager Plus) | A pagamento | Supporto nativo **Windows/macOS/Linux** + software terze parti (Office, Adobe, Chrome/Firefox/Edge, 7zip...). Scan per patch mancanti + report di compliance |

**Setup enterprise tipico (in parallelo):**
```
SCCM          → patch Windows OS e prodotti Microsoft
ManageEngine  → patch software terze parti, browser, non-Windows
```

### End-of-Life (EOL)
Sistemi fuori supporto **non ricevono patch** → progressivamente più vulnerabili.
🧠 Caso storico: **BlueKeep (CVE-2019-0708)** era così critico che Microsoft rilasciò una patch **retroattiva anche per Windows XP**, EOL dal 2014.
*(Nota: è la stessa CVE usata come esempio nel dominio Threat Intelligence — vulnerabilità RDP.)*

---

## 13. ACTIVE DIRECTORY

### Le 4 funzionalità principali
| Funzione | Cosa fa |
|---|---|
| **Authentication** | Verifica l'identità al login. Supporta blocco account dopo N tentativi falliti, disabilitazione manuale |
| **Authorization** | Determina cosa l'utente può fare, in base a permessi e **appartenenza ai gruppi** |
| **Centralized Management** | Unico punto di controllo per utenti, computer, stampanti, policy — niente gestione macchina per macchina |
| **Group Policy (GPO)** | Applica security settings, installazione software, configurazioni desktop, restrizioni su scala di dominio |

### Oggetti
Ogni oggetto ha:
| Attributo | Caratteristica |
|---|---|
| **GUID** | Identificatore univoco **immutabile** — resta lo stesso anche se l'oggetto viene **rinominato o spostato** |
| **DN** (Distinguished Name) | Riflette la **posizione nella gerarchia** — **cambia** se l'oggetto viene spostato |
| **Class** | Definisce il set di attributi disponibili (User, Computer...) |

| Tipo di oggetto | Note |
|---|---|
| **User** | Username, password, dettagli, gruppi. Ha un **SID** univoco |
| **Computer** | Macchine nel dominio. **SID** assegnato al join del dominio |
| **Group** | **Security Group** = assegnazione **permessi** · **Distribution Group** = solo **mailing list**, nessun permesso |
| **OU** (Organizational Unit) | **Container** per organizzare oggetti (anche OU annidate) → **delegated administration** + applicazione mirata di GPO |
| **Printer / Shared Folder** | Configurazioni e permessi di accesso |

### SID — struttura ⭐
```
S-1-5-21-123456789-987654321-123456789-1000
└────────── Domain SID ──────────────┘ └RID┘
```
- **Domain SID** → identico per tutti gli oggetti dello stesso dominio
- **RID** (Relative Identifier) → parte finale, univoca per oggetto

⚠️ **Punto critico:** il SID resta **invariato se rinomini** l'account, ma **cambia se lo elimini e ricrei** — anche con lo stesso username, a livello di permessi è un oggetto **completamente diverso**.

🔗 Collegamento pratico: nel dominio Digital Forensics, le sottocartelle di `C:\$Recycle.Bin` sono nominate col **SID** → `wmic useraccount get name,SID` per mapparle a un utente.

### Security Group vs OU ⭐ (confusione classica)
| | **Security Group** | **Organizational Unit** |
|---|---|---|
| Scopo | **Access control** (permessi su risorse) | **Organizzazione amministrativa** |
| Uso | Assegnare permessi a file, cartelle, risorse | Applicare **GPO**, delegare amministrazione |
| Logica | *"Chi può accedere a cosa"* | *"Come è strutturata l'azienda nella directory"* |
| Appartenenza | Un utente può essere in **più** security group | Un utente sta in **una sola** OU (è una gerarchia) |

**Naming convention tipica:** `SG - [Dipartimento] - [Permesso] - [Location]`
→ `SG-IT-FullAccess-London` · `SG-Marketing-ReadOnly-Singapore` · `SG-Security-FullAccess-Global`
💡 Una convenzione chiara è fondamentale in **audit/IR**: capisci cosa fa un gruppo senza controllarne le proprietà.

**Caso d'uso file server:**
```
1. Crea SG-Design-FileServer e SG-HR-FileServer
2. Aggiungi gli utenti pertinenti a ciascun gruppo
3. Crea le sottocartelle D:/CompanyFileServer/Design/ e /HR/
4. Su ogni cartella → Properties → Security tab → assegna il SG con i permessi
→ Least Privilege applicato
```

### Domain Controller
**Funzioni:** validazione credenziali · authorization · accesso al **database AD** (interrogabile localmente o via **LDAP**) · applicazione **Group Policy** · **replicazione** tra più DC

| Tipo | Read/Write | Uso |
|---|---|---|
| **PDC Emulator** | Read/Write | Gestione **password change** + compatibilità legacy. *(Nei Windows moderni non esiste più un "primary" rigido)* |
| **BDC** | Read-only | ⚠️ **Legacy/obsoleto** (Windows NT). Oggi si usa **multi-master replication**: ogni DC legge e scrive |
| **RODC** | **Read-only** | Filiali/sedi remote dove la **sicurezza fisica non è garantita**. Può autenticare ma **non scrivere** → se compromesso fisicamente, danno contenuto |

### Domain / Tree / Forest ⭐
| Concetto | Definizione |
|---|---|
| **Domain** | Unità base con proprio DC, database AD, OU |
| **Tree** | Domain **root + child domain** collegati gerarchicamente — **namespace condiviso** (`*.NotARealCompany.com`) |
| **Forest** | Uno o più Tree, anche con **namespace completamente diversi** (`FakeCompany.com` ≠ `NotARealCompany.com`), collegati da **trust** |
| **Trust** | Relazione che permette autenticazione **cross-domain/cross-tree** — **bidirezionale** o monodirezionale |

**Esempi dal corso:**
1. **Single domain** — un dominio, un DC, OU per reparto (HR, Finance, Corporate)
2. **Multi-domain tree** — root con DC e OU proprie, che **delega** a sottodomini figli, ciascuno con **DC dedicato** (`finance.`, `engineering.`)
3. **Multi-root forest** — due tree indipendenti (scenario tipico di **acquisizione aziendale**) collegati da **bi-directional trust**

🧠 In IR: un **trust** è un percorso di attacco. Compromettere un dominio con trust verso un altro può aprire la strada al secondo.

### Cercare oggetti AD
**PowerShell:**
```powershell
Get-ADUser -Identity "NomeUtente" -Properties *          # tutto (verboso)

# versione mirata, più pratica:
Get-ADUser -Identity "NomeUtente" -Properties LastLogonDate,LockedOut,Modified,PasswordExpired,PasswordLastSet
```
**Proprietà rilevanti per un'investigazione:**
| Proprietà | Cosa ti dice |
|---|---|
| `lastLogonTimestamp` / `LastLogonDate` | **Ultimo login** → correlabile con orari sospetti |
| `LockedOut` | L'account è **attualmente bloccato**? |
| `MemberOf` | **Gruppi** → livello di privilegio e cosa un attaccante avrebbe potuto raggiungere |
| `PasswordLastSet` / `PasswordExpired` | Segnali di **account takeover recente** |
| `modifyTimeStamp` / `Modified` | Ultima modifica dell'account |

**LDAP:** protocollo standard usato da utenti/applicazioni per interrogare AD. Tool GUI: **Softerra LDAP Browser** (gratuito) per navigare visivamente la directory.

### Group Policy (GPO)
Collezione di regole che definiscono security settings, permessi e configurazioni per utenti e computer.
💡 Esempio classico: **bloccare le porte USB** su tutte le workstation per prevenire data exfiltration, invece di configurare ogni PC.

| Tipo GPO | Scope |
|---|---|
| **Local** | Singolo computer (PC standalone, testing) |
| **Non-Local** | Storato in AD, multi-computer/utente → policy aziendali |
| **Starter** | Template, punto di partenza per nuovi GPO |

#### Ordine di processing — LSDOU ⭐⭐
```
L → Local
S → Site
D → Domain
O → Organizational Unit   (dalla più esterna alla più interna/annidata)
```
**Conflict resolution:** vince **l'ultima applicata**, cioè quella **più vicina all'oggetto** (tipicamente l'OU più specifica).

**Esempio:**
```
GPO livello Domain           → permette USB
GPO livello OU "Workstations" → blocca USB
RISULTATO: USB BLOCCATO  (l'OU è processata dopo il Domain → vince)
```

#### L'eccezione: Enforce
Un GPO impostato come **Enforced** (default: No) **vince sempre**, indipendentemente dalla posizione nella gerarchia LSDOU. Un GPO domain-level **enforced** sovrascrive anche un OU-level GPO.
💡 Usalo per policy critiche che non devono essere disabilitate accidentalmente da una OU (password policy minima, logging obbligatorio).

#### Creare un GPO
```
1. Group Policy Management (gpedit.msc / Server Manager / Windows Search)
2. Click destro sul Domain → Create a GPO → nome descrittivo
3. Click destro sul GPO → Edit → Group Policy Management Editor
4. Naviga al setting → doppio click → Enable → Apply → OK
5. (Opz.) Click destro → Enforce
6. Click destro → Link an existing GPO → collega a una OU specifica
```
⏱️ **Propagazione:** refresh automatico ogni **90 minuti**, con **delay random fino a 30 minuti** (evita che tutte le macchine facciano refresh insieme sovraccaricando il DC).

🧠 Esempio dal corso: abilitare il **command-line logging** per process creation su tutte le workstation → è esattamente la telemetria che alimenta Sysmon/Defender per rilevare attività sospette (collegabile all'**Event ID 4688** visto in Digital Forensics).

### Best practice AD Security
1. **Regular auditing & monitoring** → Windows Event Log per accessi anomali, modifiche non autorizzate, login falliti
2. **Least Privilege**
3. **Segregation of Duties** → nessuna singola persona controlla un intero processo critico (chi crea account ≠ chi approva modifiche ai security setting)
4. **Patch Management** su AD server e software collegato

---

## 14. AUTENTICAZIONE AD — KERBEROS / NTLM / LDAP

### Kerberos (standard moderno Windows)
Sistema basato su **ticket cifrati**, abilita il **Single Sign-On**.
Componente centrale: **KDC** (Key Distribution Center) = **AS** (Authentication Server) + **TGS** (Ticket Granting Server).

```
1. Utente → AS:            richiede TGT (con le credenziali)
2. AS → Utente:            rilascia TGT (cifrato)
3. Utente → TGS:           usa il TGT per chiedere un Service Ticket (es. email)
4. TGS → Utente:           rilascia il Service Ticket
5. Utente → Email Server:  presenta il Service Ticket
6. Email Server:           verifica e concede accesso
```
✅ **La password non viaggia mai sulla rete dopo il login iniziale** — solo ticket cifrati.

### NTLM (legacy)
Basato su **challenge-response**:
```
1. Utente → Server:  richiesta accesso (username in chiaro)
2. Server → Utente:  invia una CHALLENGE (numero casuale)
3. Utente → Server:  cifra la challenge con l'HASH della password, rimanda il risultato
4. Server:           verifica la risposta → grant/deny
```
⚠️ Non invia la password in chiaro, **ma** è più debole di Kerberos e vulnerabile a **Pass-the-Hash** e **NTLM relay** — molto rilevanti in IR/pentest.

### LDAP Authentication
Verifica le credenziali interrogando direttamente il directory service:
```
1. Utente → LDAP Server:  bind request (username + password)
2. LDAP Server:           verifica → bind result (success/failure)
3. Utente → LDAP Server:  operation request (accesso a risorse)
4. LDAP Server:           operation result → concesso/negato
```
Usato tipicamente da **applicazioni e portali web** che si autenticano contro AD (intranet aziendali).

### Confronto ⭐
| Protocollo | Sicurezza | Password sulla rete | Note |
|---|---|---|---|
| **Kerberos** | ✅ Alta | **Mai** dopo il login iniziale | Standard moderno, **SSO**, porta **88** |
| **NTLM** | ⚠️ Media-bassa | Mai in chiaro, **ma l'hash è vulnerabile** | Legacy, target di **Pass-the-Hash** |
| **LDAP** | Dipende | **In chiaro se non c'è TLS** → usa **LDAPS** (636) | Usato da applicazioni esterne ad AD |

---

## 15. PITFALL E CONFUSIONI COMUNI

| Confusione | Distinzione |
|---|---|
| **HIDS vs HIPS** | HIDS **avvisa** · HIPS **avvisa e agisce** (blocca, cancella, termina) |
| **NIDS vs NIPS** | Stessa logica su rete. Un NIDS **inline** diventa di fatto un NIPS |
| **Fail open vs fail closed** | NIDS = **fail open** (se muore, il traffico passa) · NIPS/Firewall/NAC = **fail closed** (bloccano) |
| **Hub vs Switch** | Hub = **broadcast a tutti** (L1, insicuro) · Switch = **solo al destinatario** via MAC (L2) |
| **Router vs Bridge** | Router = reti **distinte che si parlano** (L3) · Bridge = reti che **diventano una** (L2) |
| **Security Group vs OU** | SG = **permessi su risorse** (più SG per utente) · OU = **struttura + GPO** (una sola OU per utente) |
| **GUID vs DN vs SID** | GUID = **immutabile sempre** · DN = **cambia se sposti** l'oggetto · SID = invariato se **rinomini**, cambia se **ricrei** |
| **PDC vs BDC vs RODC** | PDC Emulator = R/W, password change · BDC = **obsoleto** · RODC = **read-only** per sedi a bassa sicurezza fisica |
| **Tree vs Forest** | Tree = **namespace condiviso** (root + child) · Forest = **uno o più tree**, namespace anche diversi, uniti da **trust** |
| **Authentication vs Authorization** | *Chi sei* vs *cosa puoi fare* |
| **Policy vs Standard vs Procedure vs Guideline** | Intento · regola di implementazione · step-by-step · **raccomandazione** (solo questa non è obbligatoria) |
| **MOU vs SLA** | MOU = **non legalmente vincolante** · SLA = contrattuale con **penali** |
| **Mitigation vs Avoidance** | Mitigation = **riduci** con controlli · Avoidance = **elimini la causa** |
| **Transfer vs Acceptance** | Transfer = sposti il **costo** a terzi (assicurazione) · Acceptance = **te lo tieni** consapevolmente |
| **Signature vs Behavior-based AV** | Signature = malware **noto** · Behavior = anomalie rispetto a una **baseline** |
| **Credentialed vs Non-credentialed scan** | Con credenziali = **più dati** · senza = simula meglio l'**attaccante esterno** |
| **WSUS vs SCCM** | WSUS = **gratuito**, distribuzione base · SCCM = a pagamento, usa WSUS come backend + **controllo granulare** e inventory |
| **Kerberos vs NTLM** | Kerberos = **ticket**, moderno, SSO · NTLM = **challenge-response**, legacy, **Pass-the-Hash** |
| **LDAP vs LDAPS** | 389 in **chiaro** · 636 con **TLS** |
| **TCP vs UDP** | TCP = **handshake**, affidabile, più lento · UDP = connectionless, veloce, **DNS/streaming/VoIP** |

### Errori di ragionamento da evitare
- ❌ *"Due password = MFA"* → no, serve **fattore diverso**
- ❌ *"L'OU determina i permessi sui file"* → no, quello è il **security group**
- ❌ *"Il GPO del dominio vince sempre"* → no, vince l'**OU** (più vicina) — **a meno che** il GPO domain sia **Enforced**
- ❌ *"Le minacce si gestiscono come le vulnerabilità"* → no: **gestisci le vulnerabilità**, non l'esistenza degli attaccanti
- ❌ *"Il MAC address non si può falsificare"* → è hardcoded ma **spoofabile**
- ❌ *"Ricreare un account con lo stesso nome ripristina i permessi"* → no, **SID diverso** = oggetto diverso

---

## APPENDICE — Numeri da ricordare a memoria

| Valore | Cosa |
|---|---|
| **0–1023 / 1024–49151 / 49152–65535** | Well-known / Registered / Ephemeral |
| **7 layer** | Modello OSI |
| **3** | Fattori di autenticazione (know / have / are) |
| **4** | Strategie di risk management (Mitigate / Transfer / Accept / Avoid) |
| **5 step** | Risk assessment |
| **72 ore** | GDPR — notifica data breach |
| **€20 mln o 4%** | GDPR — sanzione massima (il maggiore dei due) |
| **14 giorni** | Cyber Essentials+ — remediation Critical/High |
| **90 min + 30 random** | Refresh GPO |
| **LSDOU** | Ordine di processing GPO |
| **6 byte hex** | Lunghezza MAC address |
| **3-way handshake** | SYN → SYN-ACK → ACK |

---

*Fonti: materiale corso BTL1 (Security Fundamentals domain) + cheat sheet pubbliche consolidate. Le sezioni  integrano argomenti standard del dominio non presenti negli appunti di partenza.*
