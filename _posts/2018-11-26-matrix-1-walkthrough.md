---
layout: post
title: "Matrix: 1 Walkthrough"
subtitle: "It means buckle your seatbelt, Dorothy because Kansas is going bye bye."
date: 2018-11-26 11:03:25 +0000
last_modified_at: 2018-11-26 11:09:45 +0000
category: Walkthrough
tags: [VulnHub, Matrix]
comments: true
image:
  feature: matrix-1-walkthrough.jpg
  credit: Septimiu / Pixabay
  creditlink: https://pixabay.com/en/desktop-people-human-hand-man-3170198/
---

This post documents the complete walkthrough of Matrix: 1, a boot2root [VM][1] created by [Ajay Verma][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## Background

This is your last chance. After this, there is no turning back. You take the blue pill - the story ends, you wake up in your bed and believe whatever you want to believe. You take the red pill - you stay in Wonderland and I show you how deep the rabbit-hole goes.

## Information Gathering

Let’s start with a nmap scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.30.129
...
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 64 OpenSSH 7.7 (protocol 2.0)
| ssh-hostkey:
|   2048 9c:8b:c7:7b:48:db:db:0c:4b:68:69:80:7b:12:4e:49 (RSA)
|   256 49:6c:23:38:fb:79:cb:e0:b3:fe:b2:f4:32:a2:70:8e (ECDSA)
|_  256 53:27:6f:04:ed:d1:e7:81:fb:00:98:54:e6:00:84:4a (ED25519)
80/tcp    open  http    syn-ack ttl 64 SimpleHTTPServer 0.6 (Python 2.7.14)
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: SimpleHTTP/0.6 Python/2.7.14
|_http-title: Welcome in Matrix
31337/tcp open  http    syn-ack ttl 64 SimpleHTTPServer 0.6 (Python 2.7.14)
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: SimpleHTTP/0.6 Python/2.7.14
|_http-title: Welcome in Matrix
```

`nmap` finds `22/tcp`, `80/tcp` and `31337/tcp` open. The interesting bit is that both `http` servers are Python's `SimpleHTTPServer`.

## Cypher's Message

Cypher left a message in the HTML source code of `31337/tcp`.

```
# curl -s 192.168.30.129:31337 | sed '71!d' | sed -r 's/\s+//' | cut -d'>' -f2 | cut -d'<' -f1 | base64 -d && echo
echo "Then you'll see, that it is not the spoon that bends, it is only yourself. " > Cypher.matrix
```

The message is redirected to a file. Perhaps the file is present?

<a class="image-popup">
![096cd22e.png](/assets/images/posts/matrix-1-walkthrough/096cd22e.png)
</a>

What do we have here?

<a class="image-popup">
![e95088f2.png](/assets/images/posts/matrix-1-walkthrough/e95088f2.png)
</a>

Brainfuck!

Using an online [interpreter](https://copy.sh/brainfuck/), one can easily decipher (no pun intended) it, in which case, the message is:

```
You can enter into matrix as guest, with password k1ll0rXX Note: Actually, I forget last two characters so I have replaced with XX try your luck and find correct string of password.
```

## Entering the Matrix

From the message, it's clear that we need to brute-force our way into the Matrix. The tool of choice here is `hydra`. It's equally easy to use Python to generate a password list for `hydra`'s use.

<div class="filename"><span>genme.py</span></div>

```py
import itertools
import os
import string

charset  = string.ascii_letters + string.digits
killer   = 'k1ll0r'
password = open('passwords.txt', 'w')
string   = ''

for (a, b) in itertools.product(charset, repeat=2):
    string += killer + a + b + '\n'

password.write(string)
password.close()

os.system('sort -R < password.txt > pass.txt && rm passwords.txt && mv pass.txt passwords.txt')
```

The random sort at the end is for good measure—hopefully luck is on our side—and we don't have go all the way to the end to get our password.

Time to give it a shot.

<a class="image-popup">
![f279c0e2.png](/assets/images/posts/matrix-1-walkthrough/f279c0e2.png)
</a>

Awesome. Took less than a minute.

## Bypass Restricted Shell

I give to you a restricted shell. Damn.

<a class="image-popup">
![6119306b.png](/assets/images/posts/matrix-1-walkthrough/6119306b.png)
</a>

No sweat. We can log out and log back in again, making use of the fact that SSH executes command upon login like so.

<a class="image-popup">
![e2ad406e.png](/assets/images/posts/matrix-1-walkthrough/e2ad406e.png)
</a>

The surprise doesn't end here.

<a class="image-popup">
![ca82e1bf.png](/assets/images/posts/matrix-1-walkthrough/ca82e1bf.png)
</a>

I guess it's over.

<a class="image-popup">
![9ccb4955.png](/assets/images/posts/matrix-1-walkthrough/9ccb4955.png)
</a>

## What's the Flag?

Getting the flag is one command away.

<a class="image-popup">
![18312981.png](/assets/images/posts/matrix-1-walkthrough/18312981.png)
</a>

:dancer:

[1]: https://www.vulnhub.com/entry/matrix-1,259/
[2]: https://twitter.com/@unknowndevice64
[3]: https://www.vulnhub.com/
