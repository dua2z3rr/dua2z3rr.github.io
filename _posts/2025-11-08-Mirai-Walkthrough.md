---
title: Mirai Walkthrough
description: "Mirai dimostra uno dei vettori d'attacco in più rapida crescita dei tempi moderni: i dispositivi IoT configurati in modo improprio. Questo vettore d'attacco è costantemente in aumento man mano che sempre più dispositivi IoT vengono creati e distribuiti in tutto il mondo, ed è attivamente sfruttato da una vasta gamma di botnet. I dispositivi IoT interni sono inoltre utilizzati da attori malevoli per ottenere una persistenza a lungo termine."
author: dua2z3rr
date: 2025-11-08 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Web Application", "Area di Interesse: Forensics", "Area di Interesse: Niche Technologies", "Area di Interesse: IoT", "Area di Interesse: Broken Authentication and Authorization", "Area di Interesse: Host", "Vulnerabilità: Information Disclosure", "Vulnerabilità: Default Credentials"]
image: /assets/img/mirai/mirai-resized.png
---

## Enumerazione Esterna

### Nmap

Cominciamo da uno scan nmap.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap 10.10.10.48 -vv -p-
<SNIP>
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack
53/tcp    open  domain  syn-ack
80/tcp    open  http    syn-ack
1499/tcp  open  fhc     syn-ack
32400/tcp open  plex    syn-ack
32469/tcp open  unknown syn-ack

<SNIP>

┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap 10.10.10.48 -vv -p22,53,80,1499,32400,32469 -sC -sV
<SNIP>
PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
| ssh-hostkey: 
|   1024 aa:ef:5c:e0:8e:86:97:82:47:ff:4a:e5:40:18:90:c5 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAJpzaaGcmwdVrkG//X5kr6m9em2hEu3SianCnerFwTGHgUHrRpR6iocVhd8gN21TPNTwFF47q8nUitupMBnvImwAs8NcjLVclPSdFJSWwTxbaBiXOqyjV5BcKty+s2N8I9neI2coRBtZDUwUiF/1gUAZIimeKOj2x39kcBpcpM6ZAAAAFQDwL9La/FPu1rEutE8yfdIgxTDDNQAAAIBJbfYW/IeOFHPiKBzHWiM8JTjhPCcvjIkNjKMMdS6uo00/JQH4VUUTscc/LTvYmQeLAyc7GYQ/AcLgoYFHm8hDgFVN2D4BQ7yGQT9dU4GAOp4/H1wHPKlAiBuDQMsyEk2s2J+60Rt+hUKCZfnxPOoD9l+VEWfZQYCTOBi3gOAotgAAAIBd6OWkakYL2e132lg6Z02202PIq9zvAx3tfViuU9CGStiIW4eH4qrhSMiUKrhbNeCzvdcw6pRWK41+vDiQrhV12/w6JSowf9KHxvoprAGiEg7GjyvidBr9Mzv1WajlU9BQO0Nc7poV2UzyMwLYLqzdjBJT28WUs3qYTxanaUrV9g==
|   2048 e8:c1:9d:c5:43:ab:fe:61:23:3b:d7:e4:af:9b:74:18 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCpSoRAKB+cPR8bChDdajCIpf4p1zHfZyu2xnIkqRAgm6Dws2zcy+VAZriPDRUrht10GfsBLZtp/1PZpkUd2b1PKvN2YIg4SDtpvTrdwAM2uCgUrZdKRoFa+nd8REgkTg8JRYkSGQ/RxBZzb06JZhRSvLABFve3rEPVdwTf4mzzNuryV4DNctrAojjP4Sq7Msc24poQRG9AkeyS1h4zrZMbB0DQaKoyY3pss5FWJ+qa83XNsqjnKlKhSbjH17pBFhlfo/6bGkIE68vS5CQi9Phygke6/a39EP2pJp6WzT5KI3Yosex3Br85kbh/J8CVf4EDIRs5qismW+AZLeJUJHrj
|   256 b6:a0:78:38:d0:c8:10:94:8b:44:b2:ea:a0:17:42:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCl89gWp+rA+2SLZzt3r7x+9sXFOCy9g3C9Yk1S21hT/VOmlqYys1fbAvqwoVvkpRvHRzbd5CxViOVih0TeW/bM=
|   256 4d:68:40:f7:20:c4:e5:52:80:7a:44:38:b8:a2:a7:52 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILvYtCvO/UREAhODuSsm7liSb9SZ8gLoZtn7P46SIDZL
53/tcp    open  domain  syn-ack dnsmasq 2.76
| dns-nsid: 
|_  bind.version: dnsmasq-2.76
80/tcp    open  http    syn-ack lighttpd 1.4.35
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: lighttpd/1.4.35
1499/tcp  open  upnp    syn-ack Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
32400/tcp open  http    syn-ack Plex Media Server httpd
|_http-cors: HEAD GET POST PUT DELETE OPTIONS
|_http-favicon: Plex
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-title: Unauthorized
32469/tcp open  upnp    syn-ack Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Porte:
- 22: **SSH**
- 53: **DNS**
- 80: **HTTP**, il sito utilizza **lighttpd 1.4.35**.
- 1499: **UPnP** (universal plug and play), versione **Platinum UPnP 1.0.5.13**
- 32400: **HTTP**, il sito hosta **Plex Media Server**
- 32469: **UPnP** con la stessa versione precednete

### HTTP

Quando proviamo ad accedere alla porta 80, otteniamo un errore 404. Quindi, proviamo a visitare la porta 32400.

![Desktop View](/assets/img/mirai/mirai-1.png)

Facciamo **Sign Up**.

![Desktop View](/assets/img/mirai/mirai-2.png)

Non troviamo nulla di interessante qui

### FFuF

Agggiungo mirai.htb al file **/etc/hosts** e faccio fuzzing della porta 80 e trovo la directory **admin**:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ffuf -w SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt:FUZZ -u http://mirai.htb:80/FUZZ -ic -fw 400

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://mirai.htb:80/FUZZ
 :: Wordlist         : FUZZ: /home/dua2z3rr/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 400
________________________________________________

admin                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 46ms]
versions                [Status: 200, Size: 18, Words: 1, Lines: 1, Duration: 64ms]
```

Allora provo a rientrare sulla porta 80 e trovo questo:

![Desktop View](/assets/img/mirai/mirai-5.png)

### Ricerca Credenziali di Default

Trovo un commento su una help page per un rasperry pi.

![Desktop View](/assets/img/mirai/mirai-4.png)

### Login Page

![Desktop View](/assets/img/mirai/mirai-6.png)

Possiamo loggarci su ssh immediatamente con le credenziali appena ottenute e cambiare la password della login page.

```shell
root@raspberrypi:/home/pi# sudo pihole -a -p password
```

![Desktop View](/assets/img/mirai/mirai-7.png)

Prendiamo la user flag nel Desktop di **pi**

## Shell come root

### Enumerazione Interna

Prima abbiamo notato le porte UPnP, quindi vado nella directory media e trovo questo file di testo:

```shell
root@raspberrypi:~# cat root.txt
I lost my original root.txt! I think I may have a backup on my USB stick...
```

Controlliamo la USB.

```shell
root@raspberrypi:/media/usbstick# cat damnit.txt 
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?

-James
```

Cerchiamo un tool per recuperare i file della root flag.

### Enumerazione USB

```shell
root@raspberrypi:/media/usbstick/lost+found# sudo strings /dev/sdb
>r &
/media/usbstick
lost+found
root.txt
damnit.txt
>r &
>r &
/media/usbstick
lost+found
root.txt
damnit.txt
>r &
/media/usbstick
2]8^
lost+found
root.txt
damnit.txt
>r &
<ROOT FLAG>
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?
-James
```

Prendiamo la root flag e terminiamo la box.
