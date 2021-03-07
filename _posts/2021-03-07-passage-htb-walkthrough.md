---
layout: post  
title: "Passage: Hack The Box Walkthrough"
date: 2021-03-07 12:13:48 +0000
last_modified_at: 2021-03-07 12:13:48 +0000
category: Walkthrough
tags: ["Hack The Box", Passage, retired, Linux, Medium]
comments: true
protect: false
image:
  feature: passage-htb-walkthrough.png
---

This post documents the complete walkthrough of Passage, a retired vulnerable [VM][1] created by [ChefByzen][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Passage is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.206 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-09-06 15:07:44 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.206
Discovered open port 80/tcp on 10.10.10.206
```

Nothing unusual. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80 -A --reason 10.10.10.206 -oN nmap.txt
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
|   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
|_  256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Passage News
```

This is a shit-show. Here's what the site looks like.

{% include image.html image_alt="8a2a3f1f.png" image_src="/359d2d20-0e80-48ca-825a-b99ddc31956a/8a2a3f1f.png" %}

Looking at the source of `CuteNews/rss.php` suggests that we are looking at CuteNews and I should add `passage.htb` into `/etc/hosts`.

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<?xml-stylesheet type="text/css" href="http://passage.htb/CuteNews/skins/rss_style.css" ?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
<title>Passage RSS Feed</title>
<link>http://passage.htb/news.php</link>
<language>en-us</language>
<description></description>
<!-- <docs>This is an RSS 2.0 file intended to be viewed in a newsreader or syndicated to another site. For more information on RSS check: http://www.feedburner.com/fb/a/aboutrss</docs> -->
<generator>CuteNews</generator>
<atom:link href="http://passage.htb/CuteNews/rss.php" rel="self" type="application/rss+xml" /><item>
   <title><![CDATA[**Implemented Fail2Ban**]]></title>
   <link>http://passage.htb/news.php?id=11</link>
   <description><![CDATA[Due to unusally large amounts of traffic,]]></description>
   <guid isPermaLink="false">1592488043</guid>
   <pubDate>Thu, 18 Jun 2020 09:47:23 -0400</pubDate>
</item>
<item>
   <title><![CDATA[Phasellus tristique urna]]></title>
   <link>http://passage.htb/news.php?id=8</link>
   <description><![CDATA[Sed felis pharetra, nec sodales diam sagittis.]]></description>
   <guid isPermaLink="false">1591987514</guid>
   <pubDate>Fri, 12 Jun 2020 14:45:14 -0400</pubDate>
</item>
<item>
   <title><![CDATA[Aenean dapibus nec]]></title>
   <link>http://passage.htb/news.php?id=7</link>
   <description><![CDATA[Urna eget vulputate.]]></description>
   <guid isPermaLink="false">1591450298</guid>
   <pubDate>Sat, 06 Jun 2020 09:31:38 -0400</pubDate>
</item>
<item>
   <title><![CDATA[Nullam metus tellus]]></title>
   <link>http://passage.htb/news.php?id=6</link>
   <description><![CDATA[Ornare ut fringilla id, accumsan quis turpis.]]></description>
   <guid isPermaLink="false">1588433035</guid>
   <pubDate>Sat, 02 May 2020 11:23:55 -0400</pubDate>
</item>
<item>
   <title><![CDATA[Fusce cursus, nulla in ultricies]]></title>
   <link>http://passage.htb/news.php?id=5</link>
   <description><![CDATA[Posuere, lectus metus ultricies neque, eu pulvinar enim nisi id tortor.]]></description>
   <guid isPermaLink="false">1587128696</guid>
   <pubDate>Fri, 17 Apr 2020 09:04:56 -0400</pubDate>
</item>
<item>
   <title><![CDATA[Maecenas varius convallis]]></title>
   <link>http://passage.htb/news.php?id=4</link>
   <description><![CDATA[Nisi ut porta.]]></description>
   <guid isPermaLink="false">1586711095</guid>
   <pubDate>Sun, 12 Apr 2020 13:04:55 -0400</pubDate>
</item>
<item>
   <title><![CDATA[Nunc facilisis ornare]]></title>
   <link>http://passage.htb/news.php?id=3</link>
   <description><![CDATA[Arcu quis finibus.]]></description>
   <guid isPermaLink="false">1585405439</guid>
   <pubDate>Sat, 28 Mar 2020 10:23:59 -0400</pubDate>
</item>
<item>
   <title><![CDATA[Sed porta lectus]]></title>
   <link>http://passage.htb/news.php?id=2</link>
   <description><![CDATA[Vitae justo ultricies vehicula.]]></description>
   <guid isPermaLink="false">1584459160</guid>
   <pubDate>Tue, 17 Mar 2020 11:32:40 -0400</pubDate>
</item>
<item>
   <title><![CDATA[Lorem ipsum dolor]]></title>
   <link>http://passage.htb/news.php?id=1</link>
   <description><![CDATA[Sit amet, consectetur adipiscing elit.]]></description>
   <guid isPermaLink="false">1583243399</guid>
   <pubDate>Tue, 03 Mar 2020 08:49:59 -0500</pubDate>
</item>
<!-- News Powered by CuteNews: http://cutephp.com/ --></channel></rss>
```

### CuteNews 2.1.2 - 'avatar' Remote Code Execution (Metasploit)

Searching for CuteNews exploits with `searchsploit` reveals the following.

{% include image.html image_alt="eefe03c8.png" image_src="/359d2d20-0e80-48ca-825a-b99ddc31956a/eefe03c8.png" %}

It was a simple matter of copying the Metasploit module to `~/.msf4/modules/exploits/multi/http/cutenews_avatar_rce.rb` and `reload_all` in `msfconsole` for it to work. Oh yes, there's an minor typo in this module, a missing comma between the two URL references. :laughing:

Since this is an authenticated RCE exploit, we need credentials. Lucky for us, the site has a user registration function.

{% include image.html image_alt="07e6b0f6.png" image_src="/359d2d20-0e80-48ca-825a-b99ddc31956a/07e6b0f6.png" %}

And we are in!

{% include image.html image_alt="38565204.png" image_src="/359d2d20-0e80-48ca-825a-b99ddc31956a/38565204.png" %}

Hold up, this is only part of the puzzle. We haven't run our exploit.

{% include image.html image_alt="ec737c90.png" image_src="/359d2d20-0e80-48ca-825a-b99ddc31956a/ec737c90.png" %}

## Foothold

Let's exploit.

{% include image.html image_alt="0f0d5b82.png" image_src="/359d2d20-0e80-48ca-825a-b99ddc31956a/0f0d5b82.png" %}

OK. This time we are truly in! Because I prefer a full TTY shell, let's run another reverse shell back to us. Again, lucky for us, there's a `nc` lying around that comes with the `-e` switch.

{% include image.html image_alt="79547e2f.png" image_src="/359d2d20-0e80-48ca-825a-b99ddc31956a/79547e2f.png" %}

### CuteNews `cdata` directory

It should be clear at this point we should try to gain access to `paul`'s account and then make our way to `nadav`'s account.

{% include image.html image_alt="593e04bd.png" image_src="/359d2d20-0e80-48ca-825a-b99ddc31956a/593e04bd.png" %}

A little digging around CuteNews configuration soon revealed the presence of directory `cdata/users`, where all the users information is `base64`-encoded like so.

```
<?php die('Direct call - access denied'); ?>
YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTc6Im5hZGF2QHBhc3NhZ2UuaHRiIjtzOjU6ImFkbWluIjt9fQ==
```

Here's a little Linux-fu to save the day.

{% include image.html image_alt="7c75e3b1.png" image_src="/359d2d20-0e80-48ca-825a-b99ddc31956a/7c75e3b1.png" %}

CrackStation tells me that the password for that hash is `atlanta1`.

{% include image.html image_alt="44695bc3.png" image_src="/359d2d20-0e80-48ca-825a-b99ddc31956a/44695bc3.png" %}

And there you have it.

{% include image.html image_alt="8130cfbf.png" image_src="/359d2d20-0e80-48ca-825a-b99ddc31956a/8130cfbf.png" %}

The file `user.txt` is at `paul`'s home directory.

{% include image.html image_alt="b176edad.png" image_src="/359d2d20-0e80-48ca-825a-b99ddc31956a/b176edad.png" %}

## Privilege Escalation

During enumeration of `paul`'s account, I notice that `nadav`'s SSH key is in `/home/paul/.ssh`. Sneaky~

{% include image.html image_alt="38b454db.png" image_src="/359d2d20-0e80-48ca-825a-b99ddc31956a/38b454db.png" %}

This means that we are able to SSH to `nadav`'s account like so.

{% include image.html image_alt="61c7b06c.png" image_src="/359d2d20-0e80-48ca-825a-b99ddc31956a/61c7b06c.png" %}

During enumeration of `nadav`'s account, I saw the hint left behind by the creator.

{% include image.html image_alt="b177f51e.png" image_src="/359d2d20-0e80-48ca-825a-b99ddc31956a/b177f51e.png" %}

### USBCreator D-Bus Privilege Escalation in Ubuntu Desktop

The hint led me to [this](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/).

> A vulnerability in the USBCreator D-Bus interface allows an attacker with access to a user in the sudoer group to bypass the password security policy imposed by the sudo program. The vulnerability allows an attacker to overwrite arbitrary files with arbitrary content, as root – without supplying a password.

Check out the groups `nadav` is in.

{% include image.html image_alt="83cfb2d3.png" image_src="/359d2d20-0e80-48ca-825a-b99ddc31956a/83cfb2d3.png" %}

Please tell me you're seeing this too? Is the creator and the author of the write-up the same person?

{% include image.html image_alt="0db7f452.png" image_src="/359d2d20-0e80-48ca-825a-b99ddc31956a/0db7f452.png" %}

Anyway, the end is here...

{% include image.html image_alt="3cd5f846.png" image_src="/359d2d20-0e80-48ca-825a-b99ddc31956a/3cd5f846.png" %}

Time to claim the prize!

{% include image.html image_alt="db671105.png" image_src="/359d2d20-0e80-48ca-825a-b99ddc31956a/db671105.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/275
[2]: https://www.hackthebox.eu/home/users/profile/140851
[3]: https://www.hackthebox.eu/
