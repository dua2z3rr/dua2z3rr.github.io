---
title: "Baby RE - HTB Easy Challenge | Hardcoded Key & Static Analysis"
description: "Walkthrough for Baby RE challenge from Hack The Box. A reversing challenge where the `strings` command reveals a partial flag, and Ghidra is used to decompile the binary and recover the complete hardcoded key."
author: dua2z3rr
date: 2026-02-25 2:00:00
categories:
  - HackTheBox
  - Challenges
tags: ["reversing"]
---

## Challenge Overview

Show us your basic skills! (P.S. There are 4 ways to solve this, are you willing to try them all?)

---

## Solution

### Initial Execution

Running the binary prompts for a key input:

```shell
[Feb 25, 2026 - 11:02:43 (CET)] exegol-main Baby RE # ./baby  
Insert key:  
  
Try again later.
```

### Strings Analysis

Running `strings` on the binary reveals a partial flag, along with a message discouraging this approach:

```shell
[Feb 25, 2026 - 11:04:40 (CET)] exegol-main Baby RE # strings baby  
...
HTB{B4BYH  # FLAG
_R3V_TH4H  
TS_Ef  
...
Dont run `strings` on this challenge, that is not the way!!!!  
Insert key:  
abcde122313  
Try again later.
...
```

The flag is present but split across multiple lines, making it incomplete.

### Decompilation with Ghidra

Opening the binary in Ghidra and inspecting the `main` function reveals the complete hardcoded flag used in the `strcmp` comparison:

![main-function-in-ghidra](assets/img/Baby-RE/main.png)

The full flag is `HTB{B4BY_R3V_TH4TS_EZ}`.

**Flag obtained.**
