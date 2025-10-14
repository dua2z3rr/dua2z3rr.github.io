---
title: Grandpa Walkthrough
description: Grandpa è una delle macchine più semplici su Hack The Box, tuttavia tratta l'ampiamente sfruttata vulnerabilità CVE-2017-7269. Questa vulnerabilità è banale da sfruttare e, quando divenne di dominio pubblico, concesse accesso immediato a migliaia di server IIS in tutto il mondo.
author: dua2z3rr
date: 2025-10-15 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Vulnerability Assessment", "Area di Interesse: Software & OS exploitation", "Area di Interesse: Security Tools", "Vulnerabilità: Arbitrary File Upload", "Vulnerabilità: Misconfiguration", "Codice: ASP"]
image: /assets/img/grandpa/grandpa-resized.png
---

## Enumerazione Esterna

### Nmap

Cominciamo con uno scan di nmap.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $nmap 10.10.10.14 -vv -sC -sV
<SNIP>
PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Microsoft IIS httpd 6.0
|_http-server-header: Microsoft-IIS/6.0
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/6.0
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   WebDAV type: Unknown
|   Server Date: Tue, 14 Oct 2025 07:16:21 GMT
|_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT POST MOVE MKCOL PROPPATCH
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-title: Under Construction
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Ricerca exploit

Questa versione di IIS è molto famosa perchè permette, attraverso una richiesta **PUT**.

### Exploitation

