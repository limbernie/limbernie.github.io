---
layout: post
title: "Waldo: Hack The Box Walkthrough"
date: 2018-12-15 17:14:15 +0000
last_modified_at: 2018-12-15 17:25:12 +0000
category: Walkthrough
tags: ["Hack The Box", Waldo, retired]
comments: false
image:
  feature: waldo-htb-walkthrough.jpg
---

This post documents the complete walkthrough of Waldo, a retired vulnerable [VM][1] created by [strawman][2] and [capnspacehook][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

Waldo is a retired vulnerable VM from Hack The Box.

### Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 10.10.10.87
...
PORT     STATE    SERVICE        REASON         VERSION
22/tcp   open     ssh            syn-ack ttl 63 OpenSSH 7.5 (protocol 2.0)
| ssh-hostkey:
|   2048 c4:ff:81:aa:ac:df:66:9e:da:e1:c8:78:00:ab:32:9e (RSA)
|   256 b3:e7:54:6a:16:bd:c9:29:1f:4a:8c:cd:4c:01:24:27 (ECDSA)
|_  256 38:64:ac:57:56:44:d5:69:de:74:a8:88:dc:a0:b4:fd (ED25519)
80/tcp   open     http           syn-ack ttl 63 nginx 1.12.2
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.12.2
| http-title: List Manager
|_Requested resource was /list.html
|_http-trane-info: Problem with XML parsing of /evox/about
8888/tcp filtered sun-answerbook no-response
```

Let's see what we can find with the `http` service. This is how the site looks like.

<a class="image-popup">
![89f7b696.png](/assets/images/posts/waldo-htb-walkthrough/89f7b696.png)
</a>

Colorful!

### JavaScript/PHP Helpers

The site allows the creation/deletion of lists with the help of a combination of JavaScript and PHP. This is obvious when you look at the JavaScript debugger.

<a class="image-popup">
![5736b3b6.png](/assets/images/posts/waldo-htb-walkthrough/5736b3b6.png)
</a>

The functions `readDir()` and `readFile()` are POST requests to `dirRead.php` `fileRead.php` respectively. Using the JavaScript console in the Developer Tools, allows us to read files where we have `read` permissions of course.

<a class="image-popup">
![687a1107.png](/assets/images/posts/waldo-htb-walkthrough/687a1107.png)
</a>

There's one small problem. The code tries to prevent directory traversal through a string search-and-replace filter. Nothing we can't bypass. :grin:

You can see that the code is essentially removing the occurrences of `../` and `..\"`. What happens if we use a file path like this?

```
....\"/....\"/....\"/
```

This is what's remaining after the `str_replace` operation.

```
../../../
```

You get a classic directory traversal pattern!

Let's give it a shot and see if we can read `/etc/passwd`.

<a class="image-popup">
![2cd45594.png](/assets/images/posts/waldo-htb-walkthrough/2cd45594.png)
</a>

Perfect.

### Low-Privilege Shell

By making use of the helper functions, I can read most of the directories and files that I have permissions. I also found the location of the `user.txt` at `/home/nobody` but I lacked the permission to read it.

<a class="image-popup">
![9ee4b27e.png](/assets/images/posts/waldo-htb-walkthrough/9ee4b27e.png)
</a>

What is also interesting is the presence of the `.ssh` directory and `authorized_keys` in it. What this means is that I must find  the corresponding RSA private key that will allow me to SSH in as `nobody`.

<a class="image-popup">
![398f80e1.png](/assets/images/posts/waldo-htb-walkthrough/398f80e1.png)
</a>

Let's copy the RSA private key and give it a shot.

<a class="image-popup">
![847be22f.png](/assets/images/posts/waldo-htb-walkthrough/847be22f.png)
</a>

There you have it and here's the `user.txt`.

<a class="image-popup">
![db9d1f6d.png](/assets/images/posts/waldo-htb-walkthrough/db9d1f6d.png)
</a>

If you look at the `authorized_keys`, it seems to suggest the presence of user `monitor`. It should be clear from the beginning I'm inside a docker container due to the use of Alpine Linux.

<a class="image-popup">
![048815d6.png](/assets/images/posts/waldo-htb-walkthrough/048815d6.png)
</a>

Damn.

After some investigation, it appears that the SSH session I'm hooked up to gets forwarded to the docker container listening at `8888/tcp`.

<a class="image-popup">
![0e534c95.png](/assets/images/posts/waldo-htb-walkthrough/0e534c95.png)
</a>

A `netstat` to display the listening ports confirms it.

<a class="image-popup">
![d1e114a0.png](/assets/images/posts/waldo-htb-walkthrough/d1e114a0.png)
</a>

And only `nobody` can log in.

<a class="image-popup">
![9047fb63.png](/assets/images/posts/waldo-htb-walkthrough/9047fb63.png)
</a>

What if the private key also allows me to log in to `monitor`'s account locally? Let's try it.

<a class="image-popup">
![823aefac.png](/assets/images/posts/waldo-htb-walkthrough/823aefac.png)
</a>

Holy cow!

### Waldo's Land

It's clear that `monitor` is using a restricted bash. It's easy to bypass that. We know that SSH allows command execution upon login. Let's leverage on that.

<a class="image-popup">
![52fc22e8.png](/assets/images/posts/waldo-htb-walkthrough/52fc22e8.png)
</a>

Now, we just need to export a proper `PATH` and we should be set.

```
$ export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$PATH
```

### Privilege Escalation

During enumeration of `monitor`'s account, I noticed an executable that's able to access logs that only `root` can read.

![1e73ef2b.png](/assets/images/posts/waldo-htb-walkthrough/1e73ef2b.png)
<a class="image-popup">
</a>

No matter where I copy it to and change the `PATH` search order, I can't duplicate the permissions. It then dawned upon me that the file has other ***capabilities***.

<a class="image-popup">
![09274d61.png](/assets/images/posts/waldo-htb-walkthrough/09274d61.png)
</a>

This means that the executable can bypass DAC to read and search any system files. Maybe there are other files with ***capabilities***? Let's do a recursive search with `getcap` to find out.

<a class="image-popup">
![a63dacfb.png](/assets/images/posts/waldo-htb-walkthrough/a63dacfb.png)
</a>

What do you know! We can make use of `tac` to read the `root.txt`.

<a class="image-popup">
![3d0409cd.png](/assets/images/posts/waldo-htb-walkthrough/3d0409cd.png)
</a>

:dancer:

### Afterthought

Although I found the presence of `id_rsa` and `id_rsa.pub` in `/root/.ssh`, it's a shame `root` is not allowed to SSH locally because `PermitRootLogin` is set to `no` in `/etc/ssh/sshd_config` and to add salt to the injury, `authorized_keys` is not present.

Well, one could still read `/etc/shadow` for offline cracking. But, good luck to that. :grin:

[1]: https://www.hackthebox.eu/home/machines/profile/149
[2]: https://www.hackthebox.eu/home/users/profile/1895
[3]: https://www.hackthebox.eu/home/users/profile/35484
[4]: https://www.hackthebox.eu/
