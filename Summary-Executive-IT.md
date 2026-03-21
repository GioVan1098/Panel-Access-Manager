# PAM — Panel Access Manager

PAM è un'applicazione che permette di controllare un computer Linux da smartphone Android, anche da reti pubbliche o da fuori casa. Accendere il PC da remoto, aprire o chiudere il firewall, riavviare un servizio, spegnere la macchina — tutto con un tap, senza dover lasciare password in giro o affidarsi a servizi cloud di terzi.

---

## Il punto di partenza

Le soluzioni esistenti per il controllo remoto — TeamViewer, AnyDesk, e simili — funzionano tutte allo stesso modo: c'è un segreto (una password, una chiave condivisa) che vive sia sul telefono che sul computer. Se qualcuno ruba il PC, ha già tutto il necessario per spacciarsi per il proprietario.

PAM parte da un presupposto diverso: **il computer non conosce nessun segreto del telefono**. Conosce solo il suo "valore di identità" — un dato pubblico, non riservato, inutile da solo. L'unico pezzo sensibile — quello che autorizza i comandi — rimane fisicamente nel chip di sicurezza dello smartphone, generato lì dentro e non estraibile in nessun modo, neanche con accesso fisico al dispositivo.

---

## Come funziona

La prima volta si usa un codice QR mostrato dal PC, valido 60 secondi e monouso. L'app lo scansiona, il chip del telefono genera internamente il suo "valore di autorità" e comunica al PC solo la controparte pubblica. Il PC rilascia un documento di identità digitale per quel telefono — simile a un badge personalizzato — e da quel momento i due si riconoscono. Il QR viene bruciato.

Ogni volta che si invia un comando, il chip del telefono lo firma con il suo valore di autorità (operazione che richiede la biometria dell'utente — impronta o volto). La firma è unica per quel comando in quell'istante preciso: intercettarla e rispedirla non serve a nulla. Il PC verifica firma, identità, orario e che il messaggio non sia già stato ricevuto in precedenza. Se tutto quadra, esegue. Altrimenti rifiuta.

---

## Sicurezza

| | |
|---|---|
| Canale cifrato | Tutto il traffico è illeggibile a chiunque si trovi sulla stessa rete |
| Riconoscimento reciproco | Non solo il PC verifica il telefono — anche il telefono verifica di parlare con il PC giusto, tramite un codice di riconoscimento stabilito durante l'attivazione |
| Firma hardware | Ogni comando è firmato dentro il chip del telefono. Senza biometria dell'utente, non esce nulla |
| Codici monouso | Ogni messaggio ha un codice usa-e-getta: intercettarlo e rispedirlo non produce nessun effetto |
| Finestra temporale | Vengono accettati solo messaggi con orario recente (±30 secondi): protegge da chi tenta di ritardare o riproporre comunicazioni già catturate |
| Registro firmato | Ogni operazione viene registrata in un log firmato con una chiave che il servizio stesso non possiede — non può essere alterato retroattivamente nemmeno da chi ha accesso al server |
| Zero segreti condivisi | Il PC non contiene nulla che permetterebbe di impersonare il telefono |
| Protezione schermo | L'app blocca screenshot, registrazione schermo e condivisione — stesso meccanismo delle app bancarie |

---

## Le due versioni

**PAM** è pensato per la rete di casa o per reti fidate. Configurazione automatica, un singolo script genera tutto in pochi minuti.

**PAM-hardened** funziona da qualsiasi rete — Wi-Fi pubblico, dati mobili, reti aziendali con restrizioni. Il traffico passa attraverso un server intermedio sul cloud (un VPS, anche gratuito) che fa da ponte tra telefono e PC. Il ponte vede solo dati cifrati — non può leggere nulla né sostituirsi a nessuno. Il canale verso il ponte è a sua volta protetto da un secondo strato di cifratura, lo stesso usato dalle VPN moderne. In pratica: doppio tunnel, nessun punto di lettura.

---

## A chi si rivolge

Principalmente a chi gestisce macchine Linux in autonomia — appassionati, homelabber, professionisti IT — e vuole un controllo remoto serio senza dipendere da account su servizi esterni, senza costi ricorrenti e senza che i propri dati passino per infrastrutture di terzi.

---

## Sotto il cofano

App Android in Flutter, servizio PC in Python 3, interfaccia grafica in C con GTK3. Il tunnel nella versione hardened usa WireGuard. Il server di relay può essere qualsiasi VPS Linux, inclusi i tier gratuiti.
