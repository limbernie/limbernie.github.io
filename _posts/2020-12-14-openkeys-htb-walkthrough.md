---
layout: post  
title: "OpenKeyS: Hack The Box Walkthrough"
date: 2020-12-14 06:53:53 +0000
last_modified_at: 2020-12-14 06:53:53 +0000
category: Walkthrough
tags: ["Hack The Box", OpenKeyS, retired, OpenBSD, Medium]
comments: true
protect: false
image:
  feature: openkeys-htb-walkthrough.png
---

This post documents the complete walkthrough of OpenKeyS, a retired vulnerable [VM][1] created by [polarbearer][2] and [GibParadox][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

OpenKeyS is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.199 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-07-26 13:44:02 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.199
Discovered open port 22/tcp on 10.10.10.199
```

Really?! Just two open ports. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80 -A --reason 10.10.10.199 -oN nmap.txt
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey:
|   3072 5e:ff:81:e9:1f:9b:f8:9a:25:df:5d:82:1a:dd:7a:81 (RSA)
|   256 64:7a:5a:52:85:c5:6d:d5:4a:6b:a7:1a:9a:8a:b9:bb (ECDSA)
|_  256 12:35:4b:6e:23:09:dc:ea:00:8c:72:20:c7:50:32:f3 (ED25519)
80/tcp open  http    syn-ack ttl 63 OpenBSD httpd
| http-methods:
|_  Supported Methods: GET HEAD
|_http-title: Site doesn't have a title (text/html).
```

No shit. Here's what the `http` service looks like.

{% include image.html image_alt="4bdd1f82.png" image_src="/891b5459-710d-4a42-9ae1-02274c169047/4bdd1f82.png" %}

### Directory/File Enumeration

Let's see what we can find with `gobuster` and SecLists.

```
# gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt -t 20 -x php,txt,htm,html -e -u http://10.10.10.199/
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.199/
[+] Threads:        20
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt,htm,html
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/07/26 14:02:36 Starting gobuster
===============================================================
http://10.10.10.199/css (Status: 301)
http://10.10.10.199/js (Status: 301)
http://10.10.10.199/includes (Status: 301)
http://10.10.10.199/images (Status: 301)
http://10.10.10.199/index.html (Status: 200)
http://10.10.10.199/index.php (Status: 200)
http://10.10.10.199/fonts (Status: 301)
http://10.10.10.199/vendor (Status: 301)
Progress: 5824 / 17771 (32.77%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2020/07/26 14:09:47 Finished
===============================================================
```

This sure looks interesting.

{% include image.html image_alt="1ed71c1f.png" image_src="/891b5459-710d-4a42-9ae1-02274c169047/1ed71c1f.png" %}

### Recovery of `auth.php.swp`

Let's see what information is available in the swap file.

{% include image.html image_alt="cadb7c0f.png" image_src="/891b5459-710d-4a42-9ae1-02274c169047/cadb7c0f.png" %}

Interesting. We have a user name `jennifer` and the host name is `openkeys.htb`. I'd better put that in `/etc/hosts`. Now, let's recover `/var/www/htdocs/includes/auth.php`.

<div class="filename"><span>auth.php</span></div>

```php
<?php

function authenticate($username, $password)
{
    $cmd = escapeshellcmd("../auth_helpers/check_auth " . $username . " " . $password);
    system($cmd, $retcode);
    return $retcode;
}

function is_active_session()
{
    // Session timeout in seconds
    $session_timeout = 300;

    // Start the session
    session_start();

    // Is the user logged in?
    if(isset($_SESSION["logged_in"]))
    {
        // Has the session expired?
        $time = $_SERVER['REQUEST_TIME'];
        if (isset($_SESSION['last_activity']) &&
            ($time - $_SESSION['last_activity']) > $session_timeout)
        {
            close_session();
            return False;
        }
        else
        {
            // Session is active, update last activity time and return True
            $_SESSION['last_activity'] = $time;
            return True;
        }
    }
    else
    {
        return False;
    }
}

function init_session()
{
    $_SESSION["logged_in"] = True;
    $_SESSION["login_time"] = $_SERVER['REQUEST_TIME'];
    $_SESSION["last_activity"] = $_SERVER['REQUEST_TIME'];
    $_SESSION["remote_addr"] = $_SERVER['REMOTE_ADDR'];
    $_SESSION["user_agent"] = $_SERVER['HTTP_USER_AGENT'];
    $_SESSION["username"] = $_REQUEST['username'];
}

function close_session()
{
    session_unset();
    session_destroy();
    session_start();
}


?>
```

Interesting directory `../auth_helpers`. It exists.

{% include image.html image_alt="281aa064.png" image_src="/891b5459-710d-4a42-9ae1-02274c169047/281aa064.png" %}

Disassembly (`objdump`) of `check_auth` in OpenBSD 6.6 reveals that the program is a wrapper for `auth_userokay(3)`.

{% include image.html image_alt="2616fb7a.png" image_src="/891b5459-710d-4a42-9ae1-02274c169047/2616fb7a.png" %}

### CVE-2019-19521 - OpenBSD Authentication Bypass

Looks like `index.php` might be susceptible to CVE-2019-19521 using `-schallenge` as username.

{% include image.html image_alt="c53c4a75.png" image_src="/891b5459-710d-4a42-9ae1-02274c169047/c53c4a75.png" %}

Let's give it a shot.

{% include image.html image_alt="86eb6427.png" image_src="/891b5459-710d-4a42-9ae1-02274c169047/86eb6427.png" %}

I'm close! If only I could smuggle `jennifer` into `$_SESSION["username"]`. Wait a minute, I think I can. Check out `init_session()` from `auth.php`.

```php
function init_session()
{
    $_SESSION["logged_in"] = True;
    $_SESSION["login_time"] = $_SERVER['REQUEST_TIME'];
    $_SESSION["last_activity"] = $_SERVER['REQUEST_TIME'];
    $_SESSION["remote_addr"] = $_SERVER['REMOTE_ADDR'];
    $_SESSION["user_agent"] = $_SERVER['HTTP_USER_AGENT'];
    $_SESSION["username"] = $_REQUEST['username'];
}
```

According to PHP [manual](https://www.php.net/manual/en/reserved.variables.request.php),

> $_REQUEST is an associative arraythat by default contains the contents of $_GET, $_POST and $_COOKIE.


### Fetching `jennifer`'s SSH key

What if I introduce a cookie named `username` with a value of `jennifer`?

{% include image.html image_alt="9218140f.png" image_src="/891b5459-710d-4a42-9ae1-02274c169047/9218140f.png" %}

Awesome.

## Foothold

Armed with this key, I can log in as `jennifer`.

{% include image.html image_alt="c6e29756.png" image_src="/891b5459-710d-4a42-9ae1-02274c169047/c6e29756.png" %}

The file `user.txt` is at `jennifer`'s home directory.

{% include image.html image_alt="9210cf54.png" image_src="/891b5459-710d-4a42-9ae1-02274c169047/9210cf54.png" %}

## Privilege Escalation

It's pretty clear the entire box is built around Qualys' security [advisory](https://www.qualys.com/2019/12/04/cve-2019-19521/authentication-vulnerabilities-openbsd.txt) on OpenBSD authentication vulnerabilities.

### CVE-2019-19522: Local privilege escalation via S/Key and YubiKey

This exploit has a prerequisite - *CVE-2019-19520: Local privilege escalation via xlock*. Good thing I found a single exploit [script](https://github.com/bcoles/local-exploits/tree/master/CVE-2019-19520) that combines the two of them. Let's give it a shot.

{% include asciinema.html url="https://asciinema.org/a/U9lbk17y10ZDMqwAjUheodI6G" title="openbsd-authroot" author="limbernie" poster="npt:0:20"%}

With that, getting `root.txt` is trivial.

{% include image.html image_alt="11207720.png" image_src="/891b5459-710d-4a42-9ae1-02274c169047/11207720.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/267
[2]: https://www.hackthebox.eu/home/users/profile/159204
[3]: https://www.hackthebox.eu/home/users/profile/125033
[4]: https://www.hackthebox.eu/
