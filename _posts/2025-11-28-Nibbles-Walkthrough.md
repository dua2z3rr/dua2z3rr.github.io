---
title: Nibbles Walkthrough
description: "Nibbles è una macchina abbastanza semplice, tuttavia con l'inclusione di una blacklist di login, è decisamente più impegnativo trovare credenziali valide. Fortunatamente, è possibile enumerare un username e indovinare la password corretta non richiede molto tempo per la maggior parte degli utenti."
author: dua2z3rr
date: 2025-11-29 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Vulnerability Assessment", "Area di Interesse: Software & OS exploitation", "Area di Interesse: Security Tools", "Vulnerabilità: Remote Code Execution", "Vulnerabilità: Default Credentials"]
image: /assets/img/nibbles/nibbles-resized.png
---

## Enumerazione Esterna

### nmap

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap nibbles.htb -vv -p-
<SNIP>
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

<SNIP>

┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap nibbles.htb -vv -p22,80 -sC -sV
<SNIP>
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
|   256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Sito

Andiamo sul sito e troviamo davanti a noi una pagina con scritto `hello world!`.

![Desktop View](/assets/img/nibbles/nibbles-1.png)

Controllando il codice sorgente della pagina trovo un commento che ci da un indizio su dove dobbiamo andare.

![Desktop View](/assets/img/nibbles/nibbles-2.png)

Visitiamo la directory **/nibbleblog/**.

![Desktop View](/assets/img/nibbles/nibbles-3.png)

### ffuf

Nella directory appena scoperta, non troviamo nulla nel codice sorgente e nessun altra pagina che ci reindirizza a qualcosa di utile. Procediamo quindi a fare fuzzing delle directory.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ffuf -w SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt:FUZZ -u http://nibbles.htb/nibbleblog/FUZZ -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nibbles.htb/nibbleblog/FUZZ
 :: Wordlist         : FUZZ: /home/dua2z3rr/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 2987, Words: 116, Lines: 61, Duration: 33ms]
content                 [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 21ms]
themes                  [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 19ms]
admin                   [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 19ms]
plugins                 [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 19ms]
languages               [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 19ms]
                        [Status: 200, Size: 2987, Words: 116, Lines: 61, Duration: 28ms]
```

Essendo una applicazione php, proviamo ad accedere alla pagina **admin.php**.

![Desktop View](/assets/img/nibbles/nibbles-4.png)

### Default Credentials

Proviamo ad accedere alla admin dashboard tramite le credenziali di default di nibbleblog. Ecco cosa ho trovato cercondole online:

![Desktop View](/assets/img/nibbles/nibbles-5.png)

> Se ottieni un errore riguardante essere sulla blacklist, attendi un paio di minuti e riuscirai ad accedere!
{: .prompt-info }

Alla fine riusciamo ad accedere con le credenziali **admin:nibbles**.

### Admin Dashboard

Analizzando la **admin dashboard**, scopro che possiamo creare delle nuova pagine, includendo anche del codice sorgente. Posso utilizzare del codice **php** per ottenere una reverse shell sull'host della vittima.


