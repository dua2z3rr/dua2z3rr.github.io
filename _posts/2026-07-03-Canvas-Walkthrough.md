---
title: "Canvas - HTB Easy Challenge | JavaScript Obfuscation Reversing"
description: "Complete walkthrough of Canvas from Hack The Box. An easy misc challenge featuring a heavily obfuscated JavaScript login script serving a static website. Analyzing the login.js source reveals an array of hexadecimal byte values matching the HTB{...} flag format. Converting the hex bytes to their ASCII characters with a short Python script directly recovers the flag."
author: dua2z3rr
date: 2026-07-03 1:00:00
categories:
  - HackTheBox
  - Challenges
tags: ["misc"]
---

## Challenge Overview

We want to update our website but we are unable to because the developer who coded this left today. Can you take a look?

---

## Solution

### Source Code

Here's the source code structure using the `tree .` command:

```
.
├── css
│   └── style.css
├── dashboard.html
├── index.html
└── js
    └── login.js

3 directories, 7 files
```

### File Analysis

The HTML and CSS files don't matter to us. What matters is the **login.js** file. Here's its content (originally a single line, but reformatted with JavaScript's prettier for readability):

```js
var _0x4e0b = [
  "\x74\x6f\x53\x74\x72\x69\x6e\x67",
  "\x75\x73\x65\x72\x6e\x61\x6d\x65",
  "\x63\x6f\x6e\x73\x6f\x6c\x65",
  "\x67\x65\x74\x45\x6c\x65\x6d\x65\x6e\x74\x42\x79\x49\x64",
  "\x6c\x6f\x67",
  "\x62\x69\x6e\x64",
  "\x64\x69\x73\x61\x62\x6c\x65\x64",
  "\x61\x70\x70\x6c\x79",
  "\x61\x64\x6d\x69\x6e",
  "\x70\x72\x6f\x74\x6f\x74\x79\x70\x65",
  "\x7b\x7d\x2e\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72\x28\x22\x72\x65\x74\x75\x72\x6e\x20\x74\x68\x69\x73\x22\x29\x28\x20\x29",
  "\x20\x61\x74\x74\x65\x6d\x70\x74\x3b",
  "\x76\x61\x6c\x75\x65",
  "\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72",
  "\x59\x6f\x75\x20\x68\x61\x76\x65\x20\x6c\x65\x66\x74\x20",
  "\x74\x72\x61\x63\x65",
  "\x72\x65\x74\x75\x72\x6e\x20\x2f\x22\x20\x2b\x20\x74\x68\x69\x73\x20\x2b\x20\x22\x2f",
  "\x74\x61\x62\x6c\x65",
  "\x6c\x65\x6e\x67\x74\x68",
  "\x5f\x5f\x70\x72\x6f\x74\x6f\x5f\x5f",
  "\x65\x72\x72\x6f\x72",
  "\x4c\x6f\x67\x69\x6e\x20\x73\x75\x63\x63\x65\x73\x73\x66\x75\x6c\x6c\x79",
];
(function (_0x173c04, _0x4e0b6e) {
  var _0x20fedb = function (_0x2548ec) {
      while (--_0x2548ec) {
        _0x173c04["\x70\x75\x73\x68"](_0x173c04["\x73\x68\x69\x66\x74"]());
      }
    },
    _0x544f36 = function () {
      var _0x4c641a = {
          "\x64\x61\x74\x61": {
            "\x6b\x65\x79": "\x63\x6f\x6f\x6b\x69\x65",
            
<SNIP>

var res = String["\x66\x72\x6f\x6d\x43\x68\x61\x72\x43\x6f\x64\x65"](
  0x48,
  0x54,
  0x42,
  0x7b,
  0x57,
  0x33,
  0x4c,
  0x63,
  0x30,
  0x6d,
  0x33,
  0x5f,
  0x37,
  0x30,
  0x5f,
  0x4a,
  0x34,
  0x56,
  0x34,
  0x35,
  0x43,
  0x52,
  0x31,
  0x70,
  0x37,
  0x5f,
  0x64,
  0x33,
  0x30,
  0x62,
  0x46,
  0x75,
  0x35,
  0x43,
  0x34,
  0x37,
  0x31,
  0x30,
  0x4e,
  0x7d,
  0xa,
);
```

The JavaScript code has clearly been obfuscated, replacing plaintext strings with hex-encoded text. Most of this code doesn't matter, since knowing the HTB{flag} format we can search for the byte `0x48`, representing the uppercase H, to locate the flag.

### Exploit

We can find the uppercase H and T bytes at the bottom of the code (last part of the snippet above). Here's a short Python exploit to quickly do the conversion:

```python
hex_encoded_flag = [0x48,0x54,0x42,0x7B,0x57,0x33,0x4C,0x63,0x30,0x6D,0x33,0x5F,0x37,0x30,0x5F,0x4A,0x34,0x56,0x34,0x35,0x43,0x52,0x31,0x70,0x37,0x5F,0x64,0x33,0x30,0x62,0x46,0x75,0x35,0x43,0x34,0x37,0x31,0x30,0x4E,0x7D,0xA]
flag = ''

for i in hex_encoded_flag:
    flag += chr(i)

print(flag)
```

**Flag obtained.**
