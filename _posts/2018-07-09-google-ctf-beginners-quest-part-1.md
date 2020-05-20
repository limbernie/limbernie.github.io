---
layout: post
date: 2018-07-09 17:58:57 +0000
last_modified_at: 2018-12-09 08:13:42 +0000
title: "Google CTF: Beginners Quest (Part 1)"
category: CTF
tags: [Google]
comments: true
image:
  feature: google-ctf-beginners-quest.png
---

This post documents Part 1 of my attempt to complete [Google CTF: Beginners Quest](https://capturetheflag.withgoogle.com/#beginners/). If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background

Google concluded their [Google CTF](https://capturetheflag.withgoogle.com/) not too long ago. I didn't take part, so I thought of giving a go at the Beginners Quest first. I was thinking to myself, "_how hard could this be?_"—boy was I wrong. It's not that easy.

The quest has nineteen challenges as shown in the quest map—each color representing a category: <span style="color: rgb(203, 140, 217)">**purple**</span> (**misc**), <span style="color: rgb(34, 205, 75)">**green**</span> (**pwn/pwn-re**), <span style="color: rgb(231, 206, 66)">**yellow**</span> (**re**), and <span style="color: rgb(75, 142, 255)">**blue**</span> (**web**). Every challenge, if there's a need—contains an attachment—an archive file with its SHA256 hash as filename.

<map id="image-map" name="image-map">
<area shape="circle" alt="Letter" title="Letter" coords="135,141,14" href="#letter" />
<area shape="circle" alt="Floppy" title="Floppy" coords="212,141,14" href="#floppy" />
<area shape="circle" alt="Floppy 2" title="Floppy 2" coords="253,194,14" href="#floppy-2" />
<area shape="circle" alt="Moar" title="Moar" coords="213,246,14" href="#moar" />
<area shape="circle" alt="Admin UI" title="Admin UI" coords="291,245,14" href="#admin-ui" />
<area shape="circle" alt="Admin UI 2" title="Admin UI 2" coords="368,194,14" href="#admin-ui-2" />
<area shape="circle" alt="JS Safe" title="JS Safe" coords="291,142,14" href="#js-safe" />
<area shape="circle" alt="OCR is Cool" title="OCR is Cool" coords="213,37,14" href="#ocr-is-cool" />
<area shape="circle" alt="Security by Obscurity" title="Security by Obscurity" coords="291,89,14" href="#security-by-obscurity" />
</map>
<img src="/assets/images/posts/google-ctf-beginners-quest-part-1/map.png" usemap="#image-map">

Click or tap on the circles above to go to the respective challenge and its write-up. If the hyperlink is not working for a challenge, I've not worked on it yet. That's what Part 2 is for. :smile:

_A special shoutout to [ktbonefish](https://www.reddit.com/u/ktbonefish), [tsuro\_](https://www.reddit.com/u/tsuro_) and [Pharisaeus](https://www.reddit.com/u/Pharisaeus). They gave constructive comment and feedback that helped to improve the quality of this write-up._

### Letter

Let's start with the first challenge—Letter. The attachment is [here](https://storage.googleapis.com/gctf-2018-attachments/5a0fad5699f75dee39434cc26587411b948e0574a545ef4157e5bf4700e9d62a).

{% include image.html image_alt="Letter" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/38765a0d.png" %}

First, let's rename the file as `letter.zip`. I'll do the same for any challenge that comes with an attachment; I'll download the attachment and rename it as `<challenge>.zip`. For example, if the next challenge is **Floppy**, I'll rename the attachment as `floppy.zip`.

```
# unzip -l letter.zip
Archive:  letter.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
    59922  1980-00-00 00:00   challenge.pdf
---------                     -------
    59922                     1 file
```

The file `letter.zip` contains a PDF file `challenge.pdf`. This is how `challenge.pdf` looks like in a modern browser.

{% include image.html image_alt="challenge.pdf" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/c1f48a50.png" %}

The challenge is to read the password. That's trivial. Select the password field, copy it, and then paste it, say in a terminal.

The flag is `CTF{ICanReadDis}`.

### Floppy

The attachment is [here](https://storage.googleapis.com/gctf-2018-attachments/4e69382f661878c7da8f8b6b8bf73a20acd6f04ec253020100dfedbd5083bb39).

{% include image.html image_alt="Floppy" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/720dc921.png" %}

Let's unzip `floppy.zip`.

```
# unzip -l floppy.zip
Archive:  floppy.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     1414  1980-00-00 00:00   foo.ico
---------                     -------
     1414                     1 file
```

There's more to `foo.ico` than meets the eye.

```
# binwalk foo.ico

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
765           0x2FD           Zip archive data, at least v2.0 to extract, compressed size: 123, uncompressed size: 136, name: driver.txt
956           0x3BC           Zip archive data, at least v2.0 to extract, compressed size: 214, uncompressed size: 225, name: www.com
1392          0x570           End of Zip archive
```

We can use `unzip` to extract what's in `foo.ico`.

```
# unzip foo.ico
Archive:  foo.ico
warning [foo.ico]:  765 extra bytes at beginning or within zipfile
  (attempting to process anyway)
  inflating: driver.txt              
  inflating: www.com                 
```

The flag for this challenge is in `driver.txt`.

```
# cat driver.txt
This is the driver for the Aluminum-Key Hardware password storage device.
     CTF{qeY80sU6Ktko8BJW}

In case of emergency, run www.com
```
The flag is `CTF{qeY80sU6Ktko8BJW}`.

### Floppy 2

There's no attachment in this challenge. The challenge is basically an exercise in compiling [DOSBox](https://www.dosbox.com/) debugger and debugging a 16-bit DOS application, for those old enough to recognize the ".com" extension in `www.com`.

{% include image.html image_alt="Floppy 2" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/fd7a52f2.png" %}

The trick to enabling debugger in DOSBox is to specify `--enable-debug=heavy` during configuration of compile options. Having said that, the steps for compiling DOSBox is beyond the scope of this article.

The debugger will appear beside DOSBox upon execution.

_The DOSBox command prompt._

{% include image.html image_alt="DOSBox" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/cb693a12.png" %}

_The DOSBox debugger._

{% include image.html image_alt="DOSBox Debugger" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/868cac24.png" %}

The next step is to mount the directory containing `www.com` as a virtual C: drive with the `MOUNT` command.

{% include image.html image_alt="Mount Virtual Drive" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/8c0bd606.png" %}

Once the virtual drive is mounted, we can start to debug `www.com` with the `DEBUG` command.

{% include image.html image_alt="Enter Debug Mode" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/43c6994f.png" %}

_The debugger pauses at the first instruction of the debugged application._

{% include image.html image_alt="Pause Debugger" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/68b0b2f0.png" %}

According to [Wikipedia](https://en.wikipedia.org/wiki/COM_file), the COM binary format stores all its code and data in one segment. This is clear in the debugger view above—both the code and data segment are at `0x1FE`.

As you can see in the image below, the flag is in display. `int 21` accesses the [DOS API](https://en.wikipedia.org/wiki/MS-DOS_API#DOS_INT_21h_services) and the `AH` register contains `09h` which is the command to print the string "The Foobanizer9000 is no longer on the OffHub DMZ." to `stdout`.

{% include image.html image_alt="Flag" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/9e5c5f68.png" %}

The flag is `CTF{g00do1dDOS-FTW}`.

### Moar

There's no attachment in this challenge. Instead, there's a hint to connect to `moar.ctfcompetition.com` at port 1337 with `nc`.

{% include image.html image_alt="Moar" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/a05ddef8.png" %}

Let's do that.

{% include image.html image_alt="nc" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/ec2efe5b.png" %}

The man page of `socat` is in display. A common method to execute shell command is to prepend the command with a bang (!).

{% include image.html image_alt="Shell Command" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/607e0a0b.png" %}

Awesome.

The flag is in `/home/moar/disable_dmz.sh`.

{% include image.html image_alt="Flag" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/a58ddf24.png" %}

The flag is `CTF{SOmething-CATastr0phic}`.

### Admin UI

There's no attachment in this challenge. Instead, there's a hint to connect to `mngmnt-iface.ctfcompetition.com` at port 1337 with `nc`.

{% include image.html image_alt="Admin UI" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/5aa004e3.png" %}

This is how the interface looks like.

{% include image.html image_alt="Interface" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/ef2df23c.png" %}

The first clue lies in **Option 2 - Read EULA/patch notes** as I request for a non-existent file path. The error suggests some kind of directory traversal vulnerability is in place.

{% include image.html image_alt="Error" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/1e4b55c5.png" %}

I was able to read `/etc/passwd`.

{% include image.html image_alt="/etc/passwd" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/1d870198.png" %}

If I had to guess, I would say the flag is at `/home/user`.

{% include image.html image_alt="Flag" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/03072e8a.png" %}

The flag is `CTF{I_luv_buggy_sOFtware}`.

### Admin UI 2

There's no attachment in this challenge. Instead, we are to continue from the previous challenge.

{% include image.html image_alt="Admin UI 2" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/00550c00.png" %}

The challenge lies in guessing the location of the binary and how to get a pristine copy for reverse engineering. After a couple of rounds of guessing, the binary is at `/home/user/main`.

I use the following command to get a pristine copy of `main`.

```
echo -ne '2\n../main\n3\n' \
| nc mngmnt-iface.ctfcompetition.com 1337 \
| sed '9,$!d' \
| head -n -3 > main
```

_Update: You can use the traversal technique to read `/proc/self/exe` for the file or `/proc/self/cmdline` for the path—both ways are better than guessing. :laughing:_

Here comes the next challenge—reverse engineering. The obvious place to look for password is in function that deal with authentication. We have two such functions: `primary_login()` and `secondary_login()`.

```
# readelf -s main | grep login
    55: 000000004141456b   221 FUNC    GLOBAL DEFAULT    1 _Z13primary_loginv
    93: 0000000041414446   293 FUNC    GLOBAL DEFAULT    1 _Z15secondary_loginv
```

_Comparison of the first password with the file `flag`._

{% include image.html image_alt="primary_login" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/b6d12561.png" %}

The first password is whatever that's in the file `flag`, which happens to be the flag for **Admin UI**. The second password is a bit more hidden.

_Checking the length of the second password._

{% include image.html image_alt="secondary_login" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/146dcbf5.png" %}

Turns out it doesn't matter what the second password is—as long as it's thirty-five characters long—you'll have access to a limited shell.

{% include image.html image_alt="Authenticated" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/45147773.png" %}

Well, this still doesn't give us the flag. We've to dig deeper in the memory.

_XOR operation with `0xc7`._

{% include image.html image_alt="xor" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/0f9c83d6.png" %}

This will go on for thirty-five times—at least we know the flag has thirty-five characters.

_The encrypted flag is at RSP._

{% include image.html image_alt="secondary_login()" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/d5f78721.png" %}

The XOR routine, hidden in the `secondary_login` function, encrypts the flag with `0xc7`, and place it at the stack. To get to the bytes at the stack, I place a breakpoint at `*secondary_login+229` where we can then examine the bytes with `x/35b $rsp`.

{% include image.html image_alt="Flag" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/9612527b.png" %}

Let's save the output above to `dump`.

```
# cat dump
0x7fffffffde10:	0x84	0x93	0x81	0xbc	0x93	0xb0	0xa8	0x98
0x7fffffffde18:	0x97	0xa6	0xb4	0x94	0xb0	0xa8	0xb5	0x83
0x7fffffffde20:	0xbd	0x98	0x85	0xa2	0xb3	0xb3	0xa2	0xb5
0x7fffffffde28:	0x98	0xb3	0xaf	0xf3	0xa9	0x98	0xf6	0x98
0x7fffffffde30:	0xac	0xf8	0xba
```

We've to XOR the bytes with `0xc7` to retrieve back the flag. To that end, I wrote a script `decrypt.sh` to automate this process.

<div class="filename"><span>decrypt.sh</span></div>
```bash
#!/bin/bash

MAGIC=0xc7

BYTES=$(cut -d':' -f2- $1 \
        | sed -r -e 's/\s+//g' -e 's/0x//g' \
        | tr -d '\n' \
        | sed -r 's/(..)/\1 /g')

for b in $BYTES; do
  printf "%02x" $((0x$b ^ $MAGIC));
done | xxd -p -r && echo
```

```
# ./decrypt.sh dump
CTF{Two_PasSworDz_Better_th4n_1_k?}
```

The flag is `CTF{Two_PasSworDz_Better_th4n_1_k?}`.

### OCR is Cool

The attachment is [here](https://storage.googleapis.com/gctf-2018-attachments/7ad5a7d71a7ac5f5056bb95dd326603e77a38f25a76a1fb7f7e6461e7d27b6a3).

{% include image.html image_alt="OCR is Cool" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/bde8ed42.png" %}

Let's unzip `OCR_is_cool.zip`.

```
# unzip -l ocr_is_cool.zip
Archive:  ocr_is_cool.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
   141505  1980-00-00 00:00   OCR_is_cool.png
---------                     -------
   141505                     1 file
```

This is how `OCR_is_cool.png` looks like—or rather how the encrypted flag looks like.

{% include image.html image_alt="Encrypted Flag" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/6291b626.png" %}

I made the assumption that "VMY" represents "CTF" after encryption. Note the curly braces after "VMY"—another good hint. It's obvious that the contents of the email is not in plaintext, encrypted by some kind of substitution cipher—possibly Caesar cipher.

<pre style="font-size: 1.0rem; line-height: 100%">
|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|
|·|·|·|·|·|·|·|·|·|·|·|·|·|·|·|·|·|·|·|·|·|C|·|·|·|·|
|·|·|·|·|·|·|·|·|·|·|·|·|T|·|·|·|·|·|·|·|·|·|·|·|·|·|
|·|·|·|·|·|·|·|·|·|·|·|·|·|·|·|·|·|·|·|·|·|·|·|·|F|·|
|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|A|B|C|D|E|F|G|
</pre>

The `tr` utility is perfect for such one-to-one transformation from SET1 to SET2. To that end, I wrote `caesar.sh`, a `bash` script wrapped around `tr`.

<div class="filename"><span>caesar.sh</span></div>
```bash
#!/bin/bash

cat $1 | tr 'a-zA-Z' 'h-za-gH-ZA-G'
```

I made a copy of the flag with OCR and used `caesar.sh` to decrypt it.

```
# ./caesar.sh flag.txt
CTF{caesarcipherisasubstitutioncipher}
```

The flag is `CTF{caesarcipherisasubstitutioncipher}`.

### Security by Obscurity

The attachment is [here](https://storage.googleapis.com/gctf-2018-attachments/2cdc6654fb2f8158cd976d8ffac28218b15d052b5c2853232e4c1bafcb632383).

{% include image.html image_alt="Security by Obscurity" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/e3bd9923.png" %}

Let's unzip `security_by_obscurity.zip`.

```
# unzip -l security_by_obscurity.zip
Archive:  security_by_obscurity.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
    11100  1980-00-00 00:00   password.x.a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.p.o.n.m.l.k.j.i.h.g.f.e.d.c.b.a.a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p
---------                     -------
    11100                     1 file
```

This challenge involves the recursive extraction of different types: zip, xz, bzip2 and gzip, in that order. To that end, I wrote `extract.sh`, a `bash` script using `7z` as the general extraction utility.

<div class="filename"><span>extract.sh</span></div>
```bash
#!/bin/bash

START=$1

while :; do
  if file -b $START | grep -Eio '^(zip|xz|bzip2|gzip)' &>/dev/null; then
    echo "[+] Extracting $START"
    7z e $START &>/dev/null
    if [ $? -eq 0 ]; then
      START=$(7z l $START | grep -A2 Name | sed '$!d' | awk '{ print $NF }')
      continue
    else
      break
    fi
  else
    break
  fi
done
```
The final extracted file `password.x` is a password-protected zip file. Using John the Ripper, I was able to determine the password—`asdf`, and the flag is in `password.txt` after extraction.

```
# cat password.txt
CTF{CompressionIsNotEncryption}
```

The flag is `CTF{CompressionIsNotEncryption}`.

### JS Safe

The attachment is [here](https://storage.googleapis.com/gctf-2018-attachments/7a50da3856dc766fc167a3a9395e86bdcecabefc1f67c53f0b5d4a660f17cd50).

{% include image.html image_alt="JS Safe" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/db9cd26e.png" %}

Let's unzip `js-safe.zip`.

```
# unzip -l js-safe.zip
Archive:  js-safe.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     6983  1980-00-00 00:00   js_safe_1.html
---------                     -------
     6983                     1 file
```

This is how `js_safe_1.html` looks like in the browser.

{% include image.html image_alt="js_safe_1.html" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/897cc75c.png" %}

Modern browsers these days come with a JS debugger, and that's what I'm using to tackle this challenge. Whenever the value of the textbox changes, the JS engine calls the asynchronous function `open_safe()`.

{% include image.html image_alt="open_safe()" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/92059013.png" %}

We can see from above that the password must match the pattern `/^CTF{([0-9a-zA-Z_@!?-]+)}$/` to proceed. The challenge lies in determining the password to unlock the safe. And guess what—the password is the flag, judging from the password format.

The string inside `CTF{...}` is then supplied as argument to another asynchronous function `x()`. This function is the key to determining the password.

{% include image.html image_alt="x()" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/c8d96eec.png" %}

The logic of the function `x()` is in the long string starting with `icff` and ending with `ьcee`—encoded. The decoding regime will iterate the string, four characters at a time—where each character represents the index to the property of the `env` object. Since we are looking at inline JS, we can always include our own code to decode the function `x()`.

{% include image.html image_alt="js_safe_2.html" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/4809e649.png" %}

I've added the above code to display the decoded function in the console. Towards the end of the decoding regime is where the comparison between the supplied hash and the correct hash occurs, `XOR`ing them one byte at a time, checking if it evaluates to zero. SHA256 is the cryptographic function used to create a 32-byte hash.

{% include image.html image_alt="Hash Comparison" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/ad79aeab.png" %}

Armed with this knowledge, we can add another round of code—three lines to be exact—to extract the bytes of the correct hash.

{% include image.html image_alt="js_safe_3.html" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/cebe0cbb.png" %}

Whenever the function is `ѡ`, we extract the second member of the first argument, resulting in the following hash getting printed to the console.

{% include image.html image_alt="Password Hash" image_src="/assets/images/posts/google-ctf-beginners-quest-part-1/a537ca47.png" %}

We can do a Google search as suggested in the comment of function `x()` or we can crack the hash with John the Ripper.

```
// TODO: check if they can just use Google to get the password once they understand how this works.
```

In any case, both ways result in the same answer: `Passw0rd!`

```
# /opt/john/john --format=raw-sha256 -w:/usr/share/wordlists/rockyou.txt hash.txt
Loaded 1 password hash (Raw-SHA256 [SHA256 128/128 AVX 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Passw0rd!        (?)
1g 0:00:00:00 DONE (2018-07-07 13:52) 4.761g/s 1404Kp/s 1404Kc/s 1404KC/s bedshaped..redsox45
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

The flag is `CTF{Passw0rd!}`.
