---
title: Photon Lockdown - HTB Very Easy Hardware Challenge | SquashFS Firmware Hardcoded Credentials
description: Complete walkthrough of Photon Lockdown from Hack The Box. A very easy hardware challenge where a copy of an Optical Network Terminal's firmware is provided and suspected to contain hardcoded credentials. The firmware's rootfs is a SquashFS filesystem, which is extracted with unsquashfs to reveal a standard Linux root directory. Grepping the extracted filesystem for HTB (or PASSW) surfaces the SUSER_PASSWORD value in etc/config_default.xml, which contains the flag.
author: dua2z3rr
date: 2026-09-09 1:00:00
categories:
  - Challenges
  - HackTheBox
tags:
  - hardware
---

## Challenge Overview

We've located the adversary's location and must now secure access to their Optical Network Terminal to disable their internet connection. Fortunately, we've obtained a copy of the device's firmware, which is suspected to contain hardcoded credentials. Can you extract the password from it?

---

## Solution

### Initial Files

After downloading and extracting the zip, we end up with three files: `rootfs`, `fwu_ver` and `hw_ver`. The last 2 files don't interest us, since they contain the firmware versions which we don't need for this challenge. What interests us instead is the first file.

```shell
file rootfs                       
rootfs: Squashfs filesystem, little endian, version 4.0, zlib compressed, 10936182 bytes, 910 inodes, blocksize: 131072 bytes, created: Sun Oct  1 07:02:43 2023
```

The `rootfs` file is a **Squashfs filesystem** file.

> SquashFS is a compressed, read-only filesystem for Linux that aims to save space. In practice it's a compressed filesystem, which is why if we use the cat command on it (or cd) it's unreadable (or inaccessible).
{: .prompt-info }

We can decompress the filesystem with the `unsquashfs` command:

```shell
unsquashfs rootfs                                                                                                                 
Parallel unsquashfs: Using 16 processors  
865 inodes (620 blocks) to write  
  
[=========================================================================================================================================================================================================================|] 1485/1485 100%  
  
created 440 files  
created 45 directories  
created 187 symlinks  
created 238 devices  
created 0 fifos  
created 0 sockets  
created 0 hardlinks
```

The command created 2 new folders:

```shell
ls -al  
total 10688  
drwxr-sr-x 1 root rvm        86 Sep  9 17:15 .  
drwxrws--- 1 root rvm         6 Sep  9 17:11 ..  
drwxrws--- 1 root rvm        44 Sep  9 17:14 extractions  
-rw-r--r-- 1 root rvm         6 Oct 11  2023 fwu_ver  
-rw-r--r-- 1 root rvm         3 Oct 11  2023 hw_ver  
-rw-r--r-- 1 root rvm  10936320 Oct  1  2023 rootfs  
drwxrwxr-x 1 root root      140 Aug 10  2022 squashfs-root
```

If we enter squashfs-root we'll see the classic root directory of a Linux system.

```shell
cd squashfs-root

ls -al  
total 16  
drwxrwxr-x 1 root root  140 Aug 10  2022 .  
drwxr-sr-x 1 root rvm    86 Sep  9 17:15 ..  
drwxrwxr-x 1 root root 2836 Aug 10  2022 bin  
lrwxrwxrwx 1 root root   13 Aug 10  2022 config -> ./var/config/  
drwxrwxr-x 1 root root 2320 Aug 10  2022 dev  
drwxrwxr-x 1 root root 1014 Oct  1  2023 etc  
drwxrwxr-x 1 root root   16 Oct  1  2023 home  
drwxrwxr-x 1 root root    0 Oct  1  2023 image  
drwxrwxr-x 1 root root 3314 Aug 10  2022 lib  
-rw-rw-r-- 1 root root    0 Aug 10  2022 .lstripped  
lrwxrwxrwx 1 root root    8 Aug 10  2022 mnt -> /var/mnt  
drwxrwxr-x 1 root root    0 Aug 10  2022 overlay  
drwxrwxr-x 1 root root    0 Aug 10  2022 proc  
drwxrwxr-x 1 root root    0 Aug 10  2022 run  
lrwxrwxrwx 1 root root    4 Aug 10  2022 sbin -> /bin  
drwxrwxr-x 1 root root    0 Aug 10  2022 sys  
lrwxrwxrwx 1 root root    8 Aug 10  2022 tmp -> /var/tmp  
drwxrwxr-x 1 root root   10 Aug 10  2022 usr  
drwxrwxr-x 1 root root    0 Aug 10  2022 var
```

### Password Discovery

To find the flag, we can simply use grep.

```shell
grep -r HTB                     
grep: bin/ip: binary file matches  
grep: bin/tc: binary file matches  
etc/config_default.xml:<Value Name="SUSER_PASSWORD" Value="HTB{F4K3_FL4G}"/>
```

If we don't want to search directly for the flag, we can use the same command but searching for **PASSW**:

```shell
grep -r PASSW  
bin/Upgrade:#usage: logo [FILENAME] [SERVERIP] [USERNAME] [PASSWORD]  
bin/Upgrade:#       cfgc [FILENAME] [SERVERIP] [USERNAME] [PASSWORD]  

<SNIP>

etc/config_default.xml:<Value Name="RS_PASSWORD" Value=""/>  
etc/config_default.xml:<Value Name="ACCOUNT_RS_PASSWORD" Value=""/>  
etc/config_default.xml:<Value Name="WLAN1_RS_PASSWORD" Value=""/>  
etc/config_default.xml:<Value Name="WLAN1_ACCOUNT_RS_PASSWORD" Value=""/>  
etc/config_default.xml:<Value Name="SUSER_PASSWORD" Value="HTB{F4K3_FL4G}"/>  
etc/config_default.xml:<Value Name="CWMP_ACS_PASSWORD" Value="password"/>  
etc/config_default.xml:<Value Name="CWMP_CONREQ_PASSWORD" Value=""/>  
etc/config_default.xml:<Value Name="CWMP_LAN_CONFIGPASSWD" Value=""/>  
etc/config_default.xml:<Value Name="CWMP_CERT_PASSWORD" Value="client"/>  
etc/config_default.xml:<Value Name="LOID_PASSWD" Value=""/>  
etc/config_default.xml:<Value Name="LOID_PASSWD_OLD" Value=""/>  
etc/config_default.xml:<Value Name="GPON_PLOAM_PASSWD" Value="1234567890"/>  
etc/runomci.sh:gpon_ploam_pwd=`mib get GPON_PLOAM_PASSWD | sed 's/GPON_PLOAM_PASSWD=//g'`  
etc/runomci.sh:gpon_loidPwd=`mib get LOID_PASSWD | sed 's/LOID_PASSWD=//g' | grep -v entry | grep -v failed`  
etc/runomci.sh:gpon_loidPwd_old=`mib get LOID_PASSWD_OLD | sed 's/LOID_PASSWD_OLD=//g' | grep -v entry | grep -v failed`  
etc/scripts/modutils.sh:            ngpon_pwd=`flash get GPON_PLOAM_PASSWD | cut -d '=' -f2 `
```

**Flag obtained.**
