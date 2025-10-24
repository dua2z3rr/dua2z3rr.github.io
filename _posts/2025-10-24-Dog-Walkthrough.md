---
title: Dog Walkthrough
description: Dog è una macchina Linux di difficoltà easy che comporta la lettura di informazioni sensibili attraverso un repository git esposto e l'esposizione di credenziali per ottenere l'accesso da amministratore a BackdropCMS. I privilegi di amministratore permettono a un attaccante di sfruttare un'esecuzione di codice remoto (RCE) caricando un archivio malevolo contenente una backdoor PHP per ottenere un primo accesso al sistema. L'account utente johncusack riutilizza inoltre la password di BackdropCMS. Dopo aver compromesso l'account johncusack, l'attaccante scopre che l'utente può eseguire l'eseguibile bee con privilegi sudo, il che permette di ottenere i privilegi di root.
author: dua2z3rr
date: 2025-10-25 1:00:00
categories: [Machines]
tags: ["Vulnerabilità: Remote Code Execution", "Vulnerabilità: Arbitrary File Upload", "Codice: PHP", "Codice: SQL", "Codice: Bash"]
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

Troviamo anche l'hash per le password: `aWFvPQNGZSz1DQ701dD4lC5v1hQW34NefHvyZUzlThQ`.

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

