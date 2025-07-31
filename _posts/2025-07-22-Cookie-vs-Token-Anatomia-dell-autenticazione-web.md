---
title: "Cookie vs Token: Anatomia dell'autenticazione web"
description: Un'analisi approfondita delle differenze tra cookie e token nell'autenticazione web, con focus su sicurezza, usabilità e implementazione.
author: dua2z3rr
date: 2025-07-22 7:00:00
categories: [Approfondimenti]
tags: ["Approfondimento: Web Security", "Approfondimento: API", "Approfondimento: Sistemi di Autenticazione"]
---

![Desktop View](/assets/img/Cookie_vs_Token/cookie.png)

Assicurarsi che gli utenti possano accedere in modo sicuro e senza problemi è fondamentale per qualsiasi applicazione web. Due dei metodi più comuni per gestire l'autenticazione degli utenti sono i cookie e i token. In questo articolo, esploreremo le differenze tra questi due approcci, i loro vantaggi e svantaggi, e come scegliere quello giusto per la tua applicazione.

## Cos'è un Cookie?

{: .mt-5 .mb-4 }

I cookie sono piccoli file di testo che un server web manda al browser dell'utente per poi essere memorizzati. Questi file contengono varie informazioni, tra cui il nome dell'utente, le preferenze e le sessioni di autenticazione. I cookie vengono inviati con ogni richiesta HTTP al server, permettendo al server di identificare l'utente e mantenere lo stato della sessione. I cookie possono essere implementati molto facilmente e sono supportati da molti browser e framework web.

Esempio di codice di Node.js/Express:

```javascript
res.cookie("sessionID", "abc123", { httpOnly: true, maxAge: 900000 });
```

### Pro e Contro dei Cookie

#### Vantaggi



1. Esperienza fluida fra subdomains
   - I cookie possono essere configurati per essere accessibili da più sottodomini, facilitando l'autenticazione tra diverse parti di un'applicazione web.

2. Sicurezza all'avanguardia contro attacchi XSS
   - I cookie possono essere marcati come `HttpOnly`, impedendo l'accesso tramite JavaScript e riducendo il rischio di attacchi Cross-Site Scripting (XSS).

3. Minimo spazio richiesto
   - I cookie sono generalmente piccoli, occupando solo pochi kilobyte, il che li rende leggeri e facili da gestire.

4. Gestiti automaticamente dal browser
   - I browser gestiscono automaticamente i cookie, inviandoli con ogni richiesta al server, il che semplifica la gestione della sessione.

#### Svantaggi

1. Attacchi CSRF
   - I cookie sono vulnerabili agli attacchi Cross-Site Request Forgery (CSRF), dove un attaccante può inviare richieste non autorizzate utilizzando i cookie dell'utente senza che quest'ultimo ne sia consapevole. Esistono tecniche per mitigare questo problema, ma spesso rendono l'esperienza utente meno fluida.
2. Problemi di privacy
   - Come tutti sappiamo, i cookie possono essere utilizzati per tracciare gli utenti attraverso diverse sessioni e siti web, sollevando preoccupazioni sulla privacy.

## Cos'è un Token?
{: .mt-5 .mb-4 }

I token sono stringhe uniche criptate generate dal server e inviate al client dopo un'autenticazione riuscita. A differenza dei cookie, i token non sono memorizzati nel browser, ma possono essere inviati come parte delle intestazioni HTTP o nel corpo della richiesta. I token sono spesso utilizzati in applicazioni RESTful e API, dove la statelessness è una caratteristica chiave.

### Pro e Contro dei Token

#### Vantaggi

1. Facili da usare
   - JWTs (JSON Web Tokens) e altri tipi di token sono facili da implementare e possono essere utilizzati in vari contesti, inclusi client mobile e applicazioni web.
2. Capacità cross-platform
   - Grazie alla loro natura stateless, i token possono essere utilizzati su molte piattaforme, tra cui molte applicazioni dell'IoT (Internet of Things).
3. Molte possibilità di salvataggio
   - I token possono essere salvati in vari modi, come nel local storage del browser o in un database, offrendo flessibilità nella gestione della sessione.



#### Svantaggi



1. Non possono essere revocati
   - Dopo che un JWT è stato emesso, è molto, molto difficile revocarlo. Anche se un token viene compromesso, rimarrà valido fino alla sua scadenza, a meno che non si implementi un sistema di blacklist per token.
2. Molto più ingombranti
   - I token, specialmente i JWT, possono essere molto più grandi dei cookie, occupando più spazio e aumentando il tempo di caricamento delle pagine.

## Confronto tra Cookie e Token
{: .mt-5 .mb-4 }


| Caratteristica        | Cookie                                          | Token                                                                                     |
| --------------------- | ----------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Persistenza           | Memorizzati nel browser                         | Non memorizzati nel browser o server                                                      |
| Sicurezza             | Vulnerabili a furti di sessione e CSRF          | Vulnerabili a compromissione, brute-forcing (se prevedibili), intercettazione nella cache |
| Revoca                | Facile da revocare (basta cancellare il cookie) | Difficile da revocare (necessaria una blacklist)                                          |
| Supporto cross-domain | Limitato (richiede configurazione)              | Ottimo (può essere usato ovunque)                                                         |
| Dimensione            | Piccoli (pochi KB)                              | Generalmente più grandi (specialmente JWT)                                                |
