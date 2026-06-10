---
title: "baby nginxatsu - HTB Easy Challenge | Nginx Misconfiguration"
description: "Walkthrough of Baby NginxAtsu from Hack The Box. An easy web challenge featuring nginx configuration file generation functionality with directory listing vulnerability on /storage. Database backup file (tar.gz) accessible through autoindex reveals SQLite database containing admin credentials. MD5 password hash cracked via hashcat with rockyou wordlist enables admin account access and flag retrieval."
author: dua2z3rr
date: 2026-06-10 1:00:00
categories:
  - HackTheBox
  - Challenges
tags: ["web"]
---

## Challenge Description

Can you find a way to login as the administrator of the website and free nginxatsu?

---

## Solution

### Website Discovery

For this web challenge, we don't have the source code. Let's open the site.

![login page](assets/img/baby_nginxatsu/login.png)

Before trying SQL injections, the challenge clearly suggests the vulnerability will involve nginx. Let's go to the registration page and create an account.

![register page](assets/img/baby_nginxatsu/register.png)

After logging in with the newly created account, we reach the home page.

![home page](assets/img/baby_nginxatsu/home-page.png)

This page allows us to dynamically create nginx configuration files. I immediately suspect the site's nginx configuration file was created the same way.

### Generate Sample Configuration

Before touching the various inputs, let's generate a configuration file:

![config file](assets/img/baby_nginxatsu/config-file.png)

Clicking **view raw** shows it in raw format. The most interesting part is the URL path:

`http://154.57.164.80:32244/storage/nginx_6a297b1c3c402.conf`

This indicates files are stored in `/storage/`. Let's read the entire default nginx configuration file:

```nginx
user www;
pid /run/nginx.pid;
error_log /dev/stderr info;

events {
    worker_connections 1024;
}

http {
    server_tokens off;

    charset utf-8;
    keepalive_timeout 20s;
    sendfile on;
    tcp_nopush on;
    client_max_body_size 2M;

    include  /etc/nginx/mime.types;

    server {
        listen 80;
        server_name _;

        index index.php;
        root /www/public;

        # We sure hope so that we don't spill any secrets
        # within the open directory on /storage
        
        location /storage {
            autoindex on;
        }
        
        location / {
            try_files $uri $uri/ /index.php?$query_string;
            location ~ \.php$ {
                try_files $uri =404;
                fastcgi_pass unix:/run/php-fpm.sock;
                fastcgi_index index.php;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                include fastcgi_params;
            }
        }
    }
}
```

Below the comment that helps us know the direction we have to take, we see `autoindex on`. This means if we navigate to `/storage/`, we'll get a listing of all files. Let's test this and confirm that the site's nginx configuration and generated configuration files are the same.

### Directory Listing Vulnerability

![storage directory index](assets/img/baby_nginxatsu/storage-dir.png)

At the bottom of the directory we can see the compressed folder **v1_db_backup_1604123342.tar.gz**. Let's extract it and see what's inside:

```shell
[Jun 10, 2026 - 20:57:30 (CEST)] exegol-main baby_nginxatsu # tree .
.
├── backup.tar.gz
└── database
    └── database.sqlite
```

Let's open the sqlite file with sqlite3:

```sql
sqlite> .tables
failed_jobs      nginx_configs    users
migrations       password_resets

sqlite> PRAGMA table_info(users);
0|id|INTEGER|1||1
1|name|varchar|1||0
2|email|varchar|1||0
3|password|varchar|1||0
4|api_token|varchar|1||0
5|remember_token|varchar|0||0
6|created_at|datetime|0||0
7|updated_at|datetime|0||0

sqlite> select * from users;
1|jr|nginxatsu-adm-01@makelarid.es|e7816e9a10590b1e33b87ec2fa65e6cd|D3brGCwzdDCzPh5lVzOss6LxFjYjLfoMTajpS7SWlUlB4pbdSwnj1zShXFRILOmYvkMj||2026-06-10 14:53:06|2026-06-10 14:53:06
2|Giovann1|nginxatsu-giv@makelarid.es|5dbf5c28ca9b22cc47fcf96b0a26e1dd|nBdnQbZnMuEU93JzKHNLJLSdjgGxamvRjmx0Q9xBp30IdfOLplTvbBuNxElxrx3k7aDs||2026-06-10 14:53:06|2026-06-10 14:53:06
3|me0wth|nginxatsu-me0wth@makelarid.es|883ae9eaf32e8b1ec115e8e18e58e2e6|Tp7Xy9hyCn17sMyrqC1ztQf1qFvo5HqTsUL7gzrkl7zo8AwTalAhjKLCHG7z9H7vWN0L||2026-06-10 14:53:06|2026-06-10 14:53:06
```

### Hash Identification and Cracking

The admin account password hash is `e7816e9a10590b1e33b87ec2fa65e6cd`. Let's identify the hash type and crack it:

```shell
[Jun 09, 2026 - 09:37:13 (CEST)] exegol-main /workspace # hashid -m e7816e9a10590b1e33b87ec2fa65e6cd
Analyzing 'e7816e9a10590b1e33b87ec2fa65e6cd'
[+] MD2
[+] MD5 [Hashcat Mode: 0]
[+] MD4 [Hashcat Mode: 900]
[+] Double MD5 [Hashcat Mode: 2600]
[+] LM [Hashcat Mode: 3000]
[+] RIPEMD-128
[+] Haval-128
[+] Tiger-128
[+] Skein-256(128)
[+] Skein-512(128)
[+] Lotus Notes/Domino 5 [Hashcat Mode: 8600]
[+] Skype [Hashcat Mode: 23]
[+] Snefru-128
[+] NTLM [Hashcat Mode: 1000]
[+] Domain Cached Credentials [Hashcat Mode: 1100]
[+] Domain Cached Credentials 2 [Hashcat Mode: 2100]
[+] DNSSEC(NSEC3) [Hashcat Mode: 8300]
[+] RAdmin v2.x [Hashcat Mode: 9900]

[Jun 10, 2026 - 17:10:48 (CEST)] exegol-main /workspace # hashcat -a 0 -m 0 hash /opt/lists/rockyou.txt
hashcat (v6.2.6) starting
<SNIP>
Hashes: 1 digests; 1 unique digests, 1 unique salts
<SNIP>
Dictionary cache built:
* Filename..: /opt/lists/rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 1 sec

e7816e9a10590b1e33b87ec2fa65e6cd:adminadmin1

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: e7816e9a10590b1e33b87ec2fa65e6cd
Time.Started.....: Wed Jun 10 17:10:59 2026 (2 secs)
Time.Estimated...: Wed Jun 10 17:11:01 2026 (0 secs)
<SNIP>
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10358784/14344384 (72.21%)
<SNIP>
Speed.#1.........:  6327.6 kH/s (0.12ms) @ Accel:512 Loops:1 Thr:1 Vec:8
<SNIP>
Started: Wed Jun 10 17:10:57 2026
Stopped: Wed Jun 10 17:11:01 2026
```

**Password found:** `adminadmin1`

### Admin Access and Flag

The password for the account with email `nginxatsu-adm-01@makelarid.es` is `adminadmin1`. Let's return to the login screen and access with these new credentials to obtain the flag on the site's home page.

**Flag obtained.**