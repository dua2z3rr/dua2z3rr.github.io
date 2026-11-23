---
title: CryptOfTheUndead - HTB Very Easy Reversing Challenge | ChaCha20 Symmetric Decryption via Hardcoded Key
description: Complete walkthrough of CryptOfTheUndead from Hack The Box. A very easy reversing challenge where a binary "zombifies" files using ChaCha20 with a hardcoded 32-byte key exposed in `strings`. Since ChaCha20 is a symmetric cipher, feeding an encrypted file back into the same binary (after renaming it to bypass the `.undead` guard) recovers the plaintext and reveals the flag.
author: dua2z3rr
date: 2026-11-23 1:00:00
categories:
  - Challenges
  - HackTheBox
tags:
  - reversing
---

## Challenge Overview

All my important files have been zombified by the notorious Zombie Cybercrime Gang. Can you lay them to rest and bring my files back?

---

## Solution

### Initial Files

After downloading and extracting the zip, we end up with three files:

```shell
ls -al  
total 32  
drwxr-sr-x 1 root rvm   100 Nov 23 21:36 .  
drwxrws--- 1 root rvm    46 Nov 23 12:43 ..  
-rwxr-xr-x 1 root rvm 16512 Oct  9  2024 crypt  
-rw-rw---- 1 root rvm     5 Aug  2 18:09 fake_flag.undead  
-rw-r--r-- 1 root rvm    34 Nov 23 21:36 flag.txt.undead
```

If we try to read the `.undead` files, they're unreadable:

```
cat flag.txt.undead  
.@GTP�U�u���  
   7Y�� "D��  
            �#
```

### Dynamic Analysis

Let's run the binary:

```shell
./crypt
Usage: ./crypt file_to_encrypt
```

We create a file containing just the word "hey":

```shell
nvim tmp.txt      
                    
cat tmp.txt           
hey  

./crypt tmp.txt    
successfully zombified your file!  

cat tmp.txt.undead    
r��G# 
```

The text gets encrypted, and the same must have happened to the flag. The file was also renamed to `tmp.txt.undead`. Let's run `strings` on the binary:

```
strings crypt                                                                                      
/lib64/ld-linux-x86-64.so.2  
puts  
perror  
strncpy  

<SNIP>

jff.  
E@H9  
8[]A\A]A^A_  
crypt  
Usage: %s file_to_encrypt  
.undead  
error reading file  
error renaming file  
error opening new file  
chacha.c  
0 != counter[1]  
error: that which is undead may not be encrypted  
BRAAAAAAAAAAAAAAAAAAAAAAAAAINS!!  
successfully zombified your file!  
chacha20_block_next  
expand 32-byte k  
;*3$"  
GCC: (GNU) 14.2.1 20240805  
GCC: (GNU) 14.2.1 20240910  
main.c  
main.cold  
chacha.c  
__PRETTY_FUNCTION__.0  
_DYNAMIC  
__GNU_EH_FRAME_HDR  
_GLOBAL_OFFSET_TABLE_  
free@GLIBC_2.2.5  
__libc_start_main@GLIBC_2.34  
strncpy@GLIBC_2.2.5  
strncmp@GLIBC_2.2.5  
_ITM_deregisterTMCloneTable  
puts@GLIBC_2.2.5  
chacha20_init_context  
write@GLIBC_2.2.5  
_edata  
_fini  
strlen@GLIBC_2.2.5  
__stack_chk_fail@GLIBC_2.4  
printf@GLIBC_2.2.5  
encrypt_buf  
__assert_fail@GLIBC_2.2.5  
chacha20_xor  
close@GLIBC_2.2.5  
read@GLIBC_2.2.5  
__data_start  
__gmon_start__  
__dso_handle  

<SNIP>
```

As we can see from `strings`, there's a file called `chacha.c` and an exactly 32-character string that looks like a key: `BRAAAAAAAAAAAAAAAAAAAAAAAAAINS!!`.

ChaCha is a symmetric cipher, which uses the same key to encrypt and decrypt. So we can try to use the `crypt` binary itself to decrypt.

### Flag Recovery

```shell
ls       
crypt  fake_flag.undead  flag.txt.undead  tmp.txt.undead  

cat fake_flag.undead     
R��6/#

./crypt fake_flag.undead    
error: that which is undead may not be encrypted  

mv fake_flag.undead fake_flag  

./crypt fake_flag.undead        
error: that which is undead may not be encrypted  

./crypt fake_flag               
successfully zombified your file!  

cat fake_flag.undead  
HTB{
```

**Flag obtained.**
