# PAM — Panel Access Manager
## Executive Summary

---

# ITALIANO

## Cos'è PAM

PAM (Panel Access Manager) è un sistema che permette di controllare in modo sicuro un computer Linux da uno smartphone Android, anche quando ci si trova fuori casa o su reti non affidabili.

Il caso d'uso tipico: sei fuori, devi accendere il PC da remoto, aprire o chiudere il firewall, riavviare un servizio o spegnere la macchina — tutto con un tap sul telefono, con la certezza che nessun altro possa farlo al posto tuo.

---

## Il problema che risolve

Controllare un computer da remoto non è una novità. Il problema è farlo in modo **davvero sicuro**: le soluzioni esistenti richiedono di lasciare un segreto (una password, una chiave condivisa) sia sul telefono che sul computer. Se qualcuno ruba il computer, ha in mano tutto quello che serve per impersonare il proprietario.

PAM è progettato attorno a un principio diverso: **il computer non conosce nessun segreto del telefono**. Il computer conosce solo il "valore di identità" del telefono (un dato pubblico, non riservato). L'unico pezzo riservato — il "valore di autorità" che permette di firmare i comandi — non lascia mai il telefono. È generato dentro il chip di sicurezza hardware dell'Android e non è estraibile in nessun modo, nemmeno con accesso fisico al dispositivo.

---

## Come funziona, senza termini tecnici

### Attivazione iniziale (una tantum)

1. Il software sul PC mostra un **codice QR di attivazione**, valido solo per 60 secondi e utilizzabile una sola volta.
2. L'app Android scansiona il codice. In quel momento, il telefono genera dentro il suo chip di sicurezza un "valore di autorità" (non uscirà mai dal chip) e ne comunica al PC solo il corrispondente "valore di identità" (un dato pubblico, non riservato).
3. Il PC firma e consegna all'app un **documento di identità digitale** — equivalente a un badge aziendale personalizzato per quel telefono.
4. Da quel momento, telefono e PC si riconoscono reciprocamente. Il codice QR viene invalidato.

### Invio di un comando

Quando l'utente tocca un pulsante nell'app (es. "Apri firewall"):

1. L'app costruisce un messaggio con: il comando, l'ora esatta, un codice usa-e-getta generato al momento.
2. Il chip di sicurezza del telefono **firma** quel messaggio con il suo "valore di autorità" interno. La firma è unica per quel messaggio in quel momento — non può essere riciclata.
3. Il messaggio firmato viaggia verso il PC attraverso un **canale di comunicazione cifrato** (illeggibile a chiunque lo intercetti).
4. Il PC verifica che: il documento di identità del telefono sia valido; la firma sia corretta; l'orario sia recente (entro 30 secondi); il codice usa-e-getta non sia già stato usato.
5. Solo se tutto torna, il comando viene eseguito.

---

## Caratteristiche di sicurezza, spiegate semplicemente

| Caratteristica | Cosa fa |
|---|---|
| **Canale cifrato (TLS 1.3)** | Tutto il traffico tra telefono e PC è illeggibile da chiunque si trovi sulla stessa rete |
| **Riconoscimento reciproco** | Non basta che il PC riconosca il telefono — anche il telefono verifica di star parlando con il PC giusto, tramite un codice di riconoscimento verificato durante l'attivazione |
| **Firma digitale hardware** | Ogni comando è firmato con il valore di autorità conservato nel chip del telefono. Senza biometria (impronta o viso), il chip non firma nulla |
| **Codice usa-e-getta** | Ogni messaggio contiene un codice valido una sola volta. Intercettare e rispedire un comando già inviato non produce nessun effetto |
| **Finestra temporale** | Il PC rifiuta comandi con orario sfasato di più di 30 secondi — protegge anche da attacchi che rallentano o bloccano la rete |
| **Registro immutabile** | Ogni operazione viene registrata in un log che non può essere alterato retroattivamente, firmato con una chiave che il servizio non possiede |
| **Nessuna password condivisa** | Il PC non contiene nessun dato che permetta di impersonare il telefono |
| **Protezione schermo** | L'app blocca screenshot, registrazioni schermo e condivisione — come le app bancarie |

---

## Due varianti

### PAM — Rete domestica

Pensata per chi usa PAM dalla propria rete Wi-Fi o da reti fidate. Il telefono e il PC devono essere sulla stessa rete locale, o il PC deve essere raggiungibile direttamente.

- Configurazione semplice: uno script automatico genera tutto in pochi minuti
- Porta di comunicazione non standard (7443) per ridurre l'esposizione

### PAM-hardened — Qualsiasi rete

Pensata per chi vuole usare PAM da qualsiasi posto: reti pubbliche, rete mobile, reti aziendali con restrizioni.

- Il traffico passa attraverso un server intermedio su cloud (un VPS economico, es. Oracle Free Tier gratuito), che funge da "ponte"
- Il ponte vede solo traffico cifrato — non può leggere i comandi né impersonare nessuno
- Il canale verso il ponte è a sua volta cifrato con un secondo strato (WireGuard, lo stesso protocollo usato dalle VPN più moderne)
- Risultato: doppio strato di cifratura end-to-end

---

## A chi è rivolto

PAM è pensato per:

- **Appassionati di tecnologia e homelabber** che vogliono controllare il proprio PC da remoto senza compromessi sulla sicurezza
- **Professionisti IT** che gestiscono macchine Linux personali o di laboratorio
- **Chiunque voglia un'alternativa alle soluzioni commerciali** (TeamViewer, AnyDesk, servizi cloud) che non richiede account esterni, non passa dati su server di terzi, e non ha costi ricorrenti

---

## Stack tecnologico (per chi vuole saperlo)

- **App Android**: Flutter (Dart), biometria con Android Keystore hardware-backed
- **Servizio PC**: Python 3, HTTPS con autenticazione reciproca (mTLS), firma Ed25519
- **Interfaccia grafica PC**: GTK3 (C)
- **Tunnel (variante hardened)**: WireGuard
- **Piattaforma server relay**: qualsiasi VPS Linux (testato su Oracle Free Tier ARM)

---
---

# ENGLISH

## What is PAM

PAM (Panel Access Manager) is a system that allows you to securely control a Linux computer from an Android smartphone, even when away from home or on untrusted networks.

Typical use case: you're out, you need to wake your PC remotely, open or close the firewall, restart a service, or shut the machine down — all with a tap on your phone, with the certainty that no one else can do it in your place.

---

## The Problem It Solves

Remote computer control is nothing new. The challenge is doing it **truly securely**: existing solutions require leaving a secret (a password, a shared key) on both the phone and the computer. If someone steals the computer, they have everything they need to impersonate the owner.

PAM is built around a different principle: **the computer holds no secret belonging to the phone**. The computer only knows the phone's "identity value" — a public piece of data, not sensitive. The only sensitive piece — the "authority value" that authorises commands — never leaves the phone. It is generated inside the Android device's hardware security chip and cannot be extracted by any means, even with physical access to the device.

---

## How It Works, Without Technical Jargon

### Initial Setup (one-time)

1. The PC software displays an **activation QR code**, valid for only 60 seconds and usable exactly once.
2. The Android app scans the code. At that moment, the phone generates an "authority value" inside its security chip (it will never leave the chip) and sends the PC only the corresponding "identity value" (a public, non-sensitive piece of data).
3. The PC signs and delivers to the app a **digital identity document** — equivalent to a personalised company badge for that specific phone.
4. From that point on, phone and PC recognise each other. The QR code is permanently invalidated.

### Sending a Command

When the user taps a button in the app (e.g. "Open firewall"):

1. The app builds a message containing: the command, the exact timestamp, a one-time code generated on the spot.
2. The phone's security chip **signs** that message with its internal "authority value". The signature is unique to that exact message at that exact moment — it cannot be reused.
3. The signed message travels to the PC through an **encrypted communication channel** (unreadable to anyone who intercepts it).
4. The PC verifies that: the phone's identity document is valid; the signature is correct; the timestamp is recent (within 30 seconds); the one-time code has not already been used.
5. Only if everything checks out is the command executed.

---

## Security Features, Simply Explained

| Feature | What it does |
|---|---|
| **Encrypted channel (TLS 1.3)** | All traffic between phone and PC is unreadable to anyone on the same network |
| **Mutual recognition** | It's not enough for the PC to recognise the phone — the phone also verifies it's talking to the right PC, via a verification code confirmed during setup |
| **Hardware digital signature** | Every command is signed with the authority value held inside the phone's chip. Without biometrics (fingerprint or face), the chip signs nothing |
| **One-time code** | Every message contains a code valid for a single use. Intercepting and resending a previously sent command has no effect |
| **Time window** | The PC rejects commands with a timestamp more than 30 seconds off — protects against attacks that delay or replay traffic |
| **Tamper-proof audit log** | Every operation is recorded in a log that cannot be altered retroactively, signed with a key the service itself does not hold |
| **No shared secrets** | The PC contains no data that would allow impersonating the phone |
| **Screen protection** | The app blocks screenshots, screen recording, and screen sharing — identical to the mechanism used by banking apps |

---

## Two Variants

### PAM — Home Network

Designed for use on a home Wi-Fi or trusted network. Phone and PC must be on the same local network, or the PC must be directly reachable.

- Simple setup: a single automated script generates all required credentials in minutes
- Non-standard communication channel (port 7443) to reduce exposure

### PAM-hardened — Any Network

Designed for use from anywhere: public Wi-Fi, mobile data, corporate networks with restrictions.

- Traffic is relayed through a cloud intermediary server (an inexpensive VPS — e.g. Oracle Free Tier, which is free), acting as a "bridge"
- The bridge sees only encrypted traffic — it cannot read commands or impersonate anyone
- The channel to the bridge is itself encrypted with a second layer (WireGuard, the same protocol used by modern VPN services)
- Result: double end-to-end encryption layer

---

## Who It Is For

PAM is designed for:

- **Tech enthusiasts and homelab operators** who want to control their PC remotely without security compromises
- **IT professionals** managing personal or lab Linux machines
- **Anyone looking for an alternative to commercial solutions** (TeamViewer, AnyDesk, cloud services) that requires no external accounts, routes no data through third-party servers, and has no recurring costs

---

## Technology Stack (for those who want to know)

- **Android app**: Flutter (Dart), biometrics with hardware-backed Android Keystore
- **PC service**: Python 3, HTTPS with mutual authentication (mTLS), Ed25519 digital signatures
- **PC graphical interface**: GTK3 (C)
- **Tunnel (hardened variant)**: WireGuard
- **Relay server platform**: any Linux VPS (tested on Oracle Free Tier ARM)
