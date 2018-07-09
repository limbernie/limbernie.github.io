---
layout: post
date: 2018-07-01 12:29:18 +0000
last_modified_at: 2018-07-06 15:30:45 +0000
title: "LazySysAdmin: 1 Walkthrough"
subtitle: "Oopsie Woopsie"
category: Walkthrough
tags: [VulnHub, "LazySysAdmin"]
comments: true
image:
  feature: lazysysadmin-1-walkthrough.jpg
  credit: StockSnap / Pixabay
  creditlink: https://pixabay.com/en/people-man-guy-cry-tears-groom-2566201/
---

This post documents the complete walkthrough of LazySysAdmin: 1, a boot2root [VM][1] created by [Togie Mcdogie][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

The story of a lonely and lazy sysadmin who :cry: himself to sleep.

### Information Gathering

Let's start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.20.130
...
PORT     STATE SERVICE     REASON         VERSION
22/tcp   open  ssh         syn-ack ttl 64 OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 b5:38:66:0f:a1:ee:cd:41:69:3b:82:cf:ad:a1:f7:13 (DSA)
|   2048 58:5a:63:69:d0:da:dd:51:cc:c1:6e:00:fd:7e:61:d0 (RSA)
|   256 61:30:f3:55:1a:0d:de:c8:6a:59:5b:c9:9c:b4:92:04 (ECDSA)
|_  256 1f:65:c0:dd:15:e6:e4:21:f2:c1:9b:a3:b6:55:a0:45 (ED25519)
80/tcp   open  http        syn-ack ttl 64 Apache httpd 2.4.7 ((Ubuntu))
|_http-generator: Silex v2.2.7
| http-methods:
|_  Supported Methods: POST OPTIONS GET HEAD
| http-robots.txt: 4 disallowed entries
|_/old/ /test/ /TR2/ /Backnode_files/
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Backnode
139/tcp  open  netbios-ssn syn-ack ttl 64 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn syn-ack ttl 64 Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
3306/tcp open  mysql       syn-ack ttl 64 MySQL (unauthorized)
6667/tcp open  irc         syn-ack ttl 64 InspIRCd
| irc-info:
|   server: Admin.local
|   users: 1
|   servers: 1
|   chans: 0
|   lusers: 1
|   lservers: 0
|   source ident: nmap
|   source host: 192.168.20.128
|_  error: Closing link: (nmap@192.168.20.128) [Client exited]
```

I'm surprised to be honest. The host has **Samba**; it has **MySQL**. It even has **InspIRCd** beyond the usual `http` and `ssh` services.

### Directory Enumeration

Besides the disallowed entries in `robots.txt`, I found the following directories with `dirbuster` and its largest directory wordlist.

```
Dir found: / - 200
Dir found: /apache/ - 200
Dir found: /Backnode_files/ - 200
Dir found: /old/ - 200
Dir found: /phpmyadmin/ - 200
Dir found: /test/ - 200
Dir found: /wordpress/ - 200
Dir found: /wp/ - 200
```

Hmm. The sysadmin has installed **phpMyAdmin** and **WordPress**. The rest of the directories is empty except for `/Backnode_files`.

_Image shows phpMyAdmin_

![phpMyAdmin](/assets/images/posts/lazysysadmin-1-walkthrough/e2b8ea94.png)

_Image shows WordPress_

![WordPress](/assets/images/posts/lazysysadmin-1-walkthrough/a933d856.png)

### Samba Share

Using Gnome Files, I was able to mount `share$`. Here's what I did.

First, I connect to the Samba server.

![Connect to Samba](/assets/images/posts/lazysysadmin-1-walkthrough/0065abf5.png)

Once connected, the available shares are in display—`share$` should be interesting.

![Shares](/assets/images/posts/lazysysadmin-1-walkthrough/2c5579d4.png)

What a pleasant surprise—`share$` is the webroot.

![Webroot](/assets/images/posts/lazysysadmin-1-walkthrough/2a7c4208.png)

The sysadmin is lazy indeed. Plenty of juicy information to discover in the webroot.

```
# cat deets.txt
CBF Remembering all these passwords.

Remember to remove this file and update your password after we push out the server.

Password 12345
```

This is what I'm doing lol.

```
# cat todolist.txt
Prevent users from being able to view to web root using the local file browser
```

OOPSIE WOOPSIE!!  
Uwu We made a fucky wucky!!

```
# cat wordpress/wp-config.php
...
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'Admin');

/** MySQL database password */
define('DB_PASSWORD', 'TogieMYSQL12345^^');
```

The sysadmin has messed up—big time.

### WordPress Admin

Let's use `wpscan` to identify the users in WordPress.

```
# wpscan --url http://192.168.20.130/wordpress --enumerate u
...
[+] Enumerating usernames ...
[+] We identified the following 1 user:
    +----+-------+---------+
    | ID | Login | Name    |
    +----+-------+---------+
    | 1  | admin | Admin – |
    +----+-------+---------+
[!] Default first WordPress username 'admin' is still used
```

I was lucky. The lazy sysadmin used `TogieMYSQL12345^^`—the database password as the password to the WordPress `admin` account.

![WordPress Admin](/assets/images/posts/lazysysadmin-1-walkthrough/e993d1f5.png)

### Low-Privilege Shell

Now that I've access to WordPress as `admin`, I can edit one of the PHP files using WordPress Theme Editor to execute remote commands like so.

![404.php](/assets/images/posts/lazysysadmin-1-walkthrough/36981d72.png)

I sure can execute remote commands.

![Remote Command Execution](/assets/images/posts/lazysysadmin-1-walkthrough/34de78db.png)

Let's abuse the remote command execution to get a reverse shell.

On the attacking machine, do the following:

1. Use `msfvenom` to generate a reverse shell and name it as `rev`.
2. Host the shell with Python `SimpleHTTPServer` module.
3. Set up `netcat` listener to receive the shell.

On the remote command execution page, do the following:

<ol start="4">
  <li>Use <code>wget</code> to transfer the shell over to <code>/tmp/rev</code>.</li>
  <li>Make the shell executable with <code>chmod +x</code>.</li>
  <li>Execute the reverse shell.</li>
</ol>

If everything went well, you should have a low-privilege shell like this.

![Low-Privilege Shell](/assets/images/posts/lazysysadmin-1-walkthrough/b1270b84.png)

### Privilege Escalation

We know the sysadmin is lazy and has a habit of using the same password for different accounts. That's why I wasn't surprised when I manage to `su` to `togie` using `12345` as the password.

![togie](/assets/images/posts/lazysysadmin-1-walkthrough/6e5ffcd2.png)

What's horrifying is this—`togie` is able to `sudo` as `root`!

![sudo](/assets/images/posts/lazysysadmin-1-walkthrough/7fa8938d.png)

Although `togie` is using `rbash`—or restricted `bash`, it's trivial to change the shell back to `bash` with `chsh`.

### I Love Me Some Random Strings

![ef7f90db.png](/assets/images/posts/lazysysadmin-1-walkthrough/ef7f90db.png)

:dancer:

[1]: https://www.vulnhub.com/entry/lazysysadmin-1,205/
[2]: https://twitter.com/@TogieMcdogie
[3]: https://www.vulnhub.com
