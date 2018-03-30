---
layout: post
title: "Who Doesn't like Pink?"
category: Walkthrough
tags: [VulnHub, "Pinky's Palace"]
comments: true
image:
  feature: pink.jpg
  credit: pixel2013 / Pixabay
  creditlink: https://pixabay.com/en/macarons-raspberries-mint-pastries-2548827/
---

This post documents the complete walkthrough of Pinky's Palace: 1, a boot2root [VM][1] created by [Pink_P4nther][2] and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background
Pinky is creating his very own website! He has began setting up services and some simple web applications.

### Information Gathering

Let's kick this off with a `nmap` scan to establish the services available in the host:

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.30.4
...
PORT      STATE SERVICE    REASON         VERSION
8080/tcp  open  http       syn-ack ttl 64 nginx 1.10.3
|_http-server-header: nginx/1.10.3
|_http-title: 403 Forbidden
31337/tcp open  http-proxy syn-ack ttl 64 Squid http proxy 3.5.23
|_http-server-header: squid/3.5.23
|_http-title: ERROR: The requested URL could not be retrieved
64666/tcp open  ssh        syn-ack ttl 64 OpenSSH 7.4p1 Debian 10+deb9u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 df:02:12:4f:4c:6d:50:27:6a:84:e9:0e:5b:65:bf:a0 (RSA)
|_  256 0a:ad:aa:c7:16:f7:15:07:f0:a8:50:23:17:f3:1c:2e (ECDSA)
```

No matter what I did, the web server always returned `403 Forbidden` which was frustrating. Even when I passed the HTTP request through the proxy (squid), I was still greeted with the same response. Then it struck me when I navigated to the proxy at `http://192.168.30.4:31337`. I should be using the hostname instead of the IP address!

![screenshot-1](/assets/images/posts/pinkys-palace-walkthrough/screenshot-1.png)

Woohoo. In full pink glory!

![screenshot-2](/assets/images/posts/pinkys-palace-walkthrough/screenshot-2.png)

### Directory/File Enumeration

Now that I've gotten over the first hurdle, let's use `dirbuster` to enumerate the available directories/files out there. But first, we need to set up the proxy in `dirbuster`.

![screenshot-3](/assets/images/posts/pinkys-palace-walkthrough/screenshot-3.png)

Next, use a bigger wordlist to maximize the chances of getting a hit.

![screenshot-4](/assets/images/posts/pinkys-palace-walkthrough/screenshot-4.png)

After `dirbuster` has completed doing its thing, this is what I got.

![screenshot-5](/assets/images/posts/pinkys-palace-walkthrough/screenshot-5.png)

### Pinky's Admin Files Login

This was the attack surface I saw when the browser was pointed to `http://pinkys-palace:8080/littlesecrets-main/`.

![screenshot-6](/assets/images/posts/pinkys-palace-walkthrough/screenshot-6.png)

The form on this page was pointed to `login.php` and any failed login attempts were logged at `logs.php`. Here's an example when I used the credential (`admin:admin`) to log in.

![screenshot-7](/assets/images/posts/pinkys-palace-walkthrough/screenshot-7.png)

![screenshot-8](/assets/images/posts/pinkys-palace-walkthrough/screenshot-8.png)

Noticed that three parameters (`user`, `pass` and `User-Agent`) were logged? This calls for `sqlmap` which can test these parameters for SQLi far better and faster than I can.

### SQL Injection

According to `sqlmap` usage [wiki](https://github.com/sqlmapproject/sqlmap/wiki/Usage),

>The HTTP `User-Agent` header is tested against SQL injection if the `--level` is set to 3 or above.

Similarly, we need to set up proxy for `sqlmap` like we did for `dirbuster` in order to reach `pinkys-palace`. Armed with all the information that we've gathered so far, it's time to construct the `sqlmap` command.

```
# sqlmap --level=3 --proxy=http://192.168.30.4:31337 --data="user=admin&pass=admin" --url=http://pinkys-palace:8080/littlesecrets-main/login.php
```

Here's the test result from `sqlmap`.

![screenshot-9](/assets/images/posts/pinkys-palace-walkthrough/screenshot-9.png)

Awesome. 

We have an injection point. Time-based blind SQLi as the name suggests is pretty time-consuming for enumeration because the technique is a lot like fishing - `sqlmap` throws out a bait and waits for a fish to bite to ascertain its existence.

Moving on, we can now enumerate the tables.

![screenshot-10](/assets/images/posts/pinkys-palace-walkthrough/screenshot-10.png)

Let's dump the `users` table from `pinky_sec_db`.

![screenshot-11](/assets/images/posts/pinkys-palace-walkthrough/screenshot-11.png)

Let's crack these hashes.

```
# john --format=raw-md5 --show hashes.txt 
pinkymanage:3pinkysaf33pinkysaf3::::::

1 password hash cracked, 1 left
```

### Low Privilege Shell

I was able to login to `pinkymanage`'s account via SSH with the cracked password.

![screenshot-12](/assets/images/posts/pinkys-palace-walkthrough/screenshot-12.png)

### Ultra Secret Admin Files

During enumeration of `pinkymanage`'s account, `ultrasecretadminf1l35` was spotted in `littlesecrets-main`.

![screenshot-13](/assets/images/posts/pinkys-palace-walkthrough/screenshot-13.png)

The file `.ultrasecret` turned out to be the `base64` encoded version of a RSA private key as hinted by `note.txt`.

```
Hmm just in case I get locked out of my server I put this rsa key here.. Nobody will find it heh..
```

I've placed the decoded RSA private key in `/tmp` and changed its permissions. Unfortunately, the key owner's information was not stored in the key itself.

![screenshot-14](/assets/images/posts/pinkys-palace-walkthrough/screenshot-14.png)

Looking at `/etc/passwd` confirmed the existence of `pinky`.

![screenshot-15](/assets/images/posts/pinkys-palace-walkthrough/screenshot-15.png)

Perhaps the RSA private key can be used to login to `pinky`'s account assuming the corresponding public key was listed in `/home/pinky/.ssh/authorized_keys`? Well, there's only one way to find out.

![screenshot-16](/assets/images/posts/pinkys-palace-walkthrough/screenshot-16.png)

Sweet!

### Privilege Escalation

During enumeration of `pinky`'s account, an executable `adminhelper` at the home directory was observed to have the `setuid` attribute enabled.

![screenshot-17](/assets/images/posts/pinkys-palace-walkthrough/screenshot-17.png)

There was an accompanying note to the executable as well.

![screenshot-18](/assets/images/posts/pinkys-palace-walkthrough/screenshot-18.png)

It's likely that we are looking at a classic stack buffer overflow as the following supported that suspicion. 

_ASLR disabled_

![screenshot-19](/assets/images/posts/pinkys-palace-walkthrough/screenshot-19.png)

_Stack execution_

![screenshot-20](/assets/images/posts/pinkys-palace-walkthrough/screenshot-20.png)

Good thing `adminhelper` was really small and simple. This is how the disassembly of the main function looked like.

![screenshot-21](/assets/images/posts/pinkys-palace-walkthrough/screenshot-21.png)

This certainly brought back fond memories of 32-bit Linux exploit development. I'm pretty excited to try my hands on 64-bit Linux exploit development. Noticed the 64-bit registers (r??) and how arguments are passed through registers instead of the stack?

I downloaded a copy of `adminhelper` (through `scp` with the help of the RSA private key) to my Kali VM where [PEDA](https://github.com/longld/peda) is available. PEDA will greatly assist in the exploit development such as finding the correct offset as well as presenting the disassembly context in color. 

Here I've created a random pattern of 80 bytes saved in `buf`. Why 80 bytes? Even though it's optional, noticed that 80 (`0x50`) bytes of space was allocated in the stack? This is to make way for the destination buffer to be supplied to `strcpy()`. 

![screenshot-22](/assets/images/posts/pinkys-palace-walkthrough/screenshot-22.png)

Next, I ran `adminhelper` with the supplied argument.

![screenshot-23](/assets/images/posts/pinkys-palace-walkthrough/screenshot-23.png)

This will trigger a segmentation fault.

![screenshot-24](/assets/images/posts/pinkys-palace-walkthrough/screenshot-24.png)

Examine the string ("`IAAEAA4A`") at the stack to determine the offset.

![screenshot-25](/assets/images/posts/pinkys-palace-walkthrough/screenshot-25.png)

Verify that the offset can be used to control the RIP register.

![screenshot-26](/assets/images/posts/pinkys-palace-walkthrough/screenshot-26.png)

Even though the stack is aligned along 8 bytes boundary, the return address in the stack is only 6 bytes.

![screenshot-27](/assets/images/posts/pinkys-palace-walkthrough/screenshot-27.png)

Now that we can control RIP with the offset at 72 bytes, we can place our shellcode in an environment variable and use the following code to determine the memory address of the environment variable where the shellcode begins. This will be our return address in the exploit.

{% highlight c linenos %}
/* cat getenvaddr.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char *ptr;

    if(argc < 3) {
        printf("Usage: %s <environment variable> <target program name>\n", argv[0]);
        exit(0);
    }
    ptr = getenv(argv[1]); /* get env var location */
    ptr += (strlen(argv[0]) - strlen(argv[2]))*2; /* adjust for program name */
    printf("%s will be at %p\n", argv[1], ptr);
}
{% endhighlight %}

Since we are using the environment variable to store our payload, the size of the payload shouldn't be an issue. Having said that, I still prefer a minimalist approach and decided to use the shortest possible [shellcode](http://shell-storm.org/shellcode/files/shellcode-806.php) (27 bytes) to execute `/bin/sh` in x86-64.

```
\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05
```

Once we've copied `getenvaddr.c` over with `scp` and compiled it, it's time to get the party going.

![screenshot-28](/assets/images/posts/pinkys-palace-walkthrough/screenshot-28.png)

A perfectionist may argue that `euid=0` is not a proper proper `root` shell. Well, that can be fixed rather easily.

![screenshot-28](/assets/images/posts/pinkys-palace-walkthrough/screenshot-29.png)

### Eyes on the Prize

![screenshot-30](/assets/images/posts/pinkys-palace-walkthrough/screenshot-30.png)

:dancer:

[1]: https://www.vulnhub.com/entry/pinkys-palace-1,225/
[2]: https://twitter.com/@Pink_P4nther
[3]: https://www.vulnhub.com

*[ASLR]: Address Space Layout Randomization
*[SQLi]: SQL Injection
*[SSH]: Secure Shell
