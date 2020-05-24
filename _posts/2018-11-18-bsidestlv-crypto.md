---
layout: post
title: "BSidesTLV: 2018 CTF (Crypto)"
date: 2018-11-18 12:15:24 +0000
last_modified_time: 2018-11-18 17:51:38 +0000
category: CTF
tags: [BSidesTLV]
comments: true
image:
  feature: https://res.cloudinary.com/limbernie/image/upload/img/bsidestlv.jpg
---

This post documents my attempt to complete [BSidesTLV: 2018 CTF (Crypto)](https://www.vulnhub.com/entry/bsidestlv-2018-ctf,250/). If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background

The 2018 BSidesTLV CTF competition brought together over 310 teams burning the midnight oil to crack our challenges in a bout that lasted for two weeks. You can now enjoy the same pain and suffering, using this easy-to-use, condensed VM that now hosts all our challenges in an easy to digest format. The CTF has five categories:

+ Web (10 challenges)
+ Reverse Engineering (3 challenges)
+ Misc (3 challenges)
+ Forensics (1 challenge)
+ Crypto (2 challenges)
  1. <a href="#{{ 'T.A.R.D.I.S.' | downcase | replace: ' ', '-' | replace: '.', '' }}">T.A.R.D.I.S.</a>
  2. <a href="#{{ 'Crypto2' | downcase | replace: ' ', '-'}}">Crypto2</a>

What follows is my humble attempt of cracking the challenges in the **Crypto** category.

### T.A.R.D.I.S.

This is how the challenge looks like.

<a class="image-popup">
![abe520df.png](/assets/images/posts/bsidestlv-crypto/abe520df.png)
</a>

The challenge presents a password verification time in microseconds whenever the attempt fails. Here's how it looks like.

<a class="image-popup">
![e8c1dd01.png](/assets/images/posts/bsidestlv-crypto/e8c1dd01.png)
</a>

Looks what happen when the first digit is correct. The processing time increases.

<a class="image-popup">
![c21354ac.png](/assets/images/posts/bsidestlv-crypto/c21354ac.png)
</a>

I suspect the verification process looks at one digit at a time. With that in mind, I wrote a bash script to help automate the side-channel attack.

<div class="filename"><span>attack.sh</span></div>

```bash
#!/bin/bash

HOST=challenges.bsidestlv.com
PORT=5050
NUM=10
HINT=$(perl -e "print '0' x $NUM")
HIT=""

function solve() {
  local csrf=$(curl -c cookie \
                    -s http://$HOST:$PORT \
               | grep csrf \
               | cut -d'"' -f8)

  local retn=$(curl -b cookie \
                    -s \
                    -d "password=$1" \
                    -d "csrf_token=$csrf" \
                    http://$HOST:$PORT \
               | grep 'class=message' \
               | grep -Eo '[0-9]+')

  rm cookie; echo $retn
}

for p in $(seq 0 $((NUM-1))); do
  FRONT=$(cut -c1-$((p)) <<<"$HINT" 2>/dev/null)
  BACK=$(cut -c$((p+2))-$NUM <<<"$HINT" 2>/dev/null)
  TIME=$(for n in $(seq 0 $((NUM-1))); do printf "%d:%d\n" $(solve ${FRONT}${n}${BACK}) $n; done)

  if [ $p -eq $((NUM-1)) ]; then
    HIT=${HIT}$(echo "$TIME" \
                | sort -t':' -k1n \
                | head -1 \
                | cut -d':' -f1)
  fi
    HIT=${HIT}$(echo "$TIME" \
                | sort -t':' -k1nr \
                | head -1 \
                | cut -d':' -f2)

  HINT=$(cut -c-$NUM <<<"${HIT}${HINT}")
done; echo $HINT
```

Let's give it a shot.

<a class="image-popup">
![e2fda688.png](/assets/images/posts/bsidestlv-crypto/e2fda688.png)
</a>

This is what you see when you provide the correct password, `8105237467`.

<a class="image-popup">
![8fc6229e.png](/assets/images/posts/bsidestlv-crypto/8fc6229e.png)
</a>

The flag is `BSidesTLV{7456urtyifkygvjhb}`.

### Crypto2

This is how the challenge looks like.

<a class="image-popup">
![0f0ce266.png](/assets/images/posts/bsidestlv-crypto/0f0ce266.png)
</a>

Let's take a look at what we are dealing with.

<a class="image-popup">
![49baf6fc.png](/assets/images/posts/bsidestlv-crypto/49baf6fc.png)
</a>

Notice that it's not a single quote but an apostrophe (or right single quote)?

<a class="image-popup">
![7b63efeb.png](/assets/images/posts/bsidestlv-crypto/7b63efeb.png)
</a>

In any case, `’` is represented by three bytes: `\xe2\x80\x99`. I'm not sure if this observation is going to be useful now, we'll see. Suffice to say, the content of `Anorak’s Invitation.txt` is not human-readable.

<a class="image-popup">
![a1cfd101.png](/assets/images/posts/bsidestlv-crypto/a1cfd101.png)
</a>

Anorak's Invitation is a video game message from James Halliday, the creator of OASIS in the book/movie "Ready Player One". Although I'm familiar with the movie, having watched it not too long ago, I'm not too familiar with the book.

According to the challenge's hint, the creator is not venturing beyond basic ciphers; we can assume the use of basic cryptosystem such as substitution, Caesar's cipher, etc, which leaves the punctuation marks untouched.

Let's perform some basic analysis on the bytes using the Unicode representation of English punctuation marks such as apostrophe `\x32\x80\x99`, period and a single space thereafter, `\x2e20`, left double quote `\xe2\x80\x9c` and right double quote `\xe2\x80\x9d`.

_apostrophe_

```
# xxd -p encrypted.txt | tr -d '\n' | grep -Eo 'e28099' | wc -l
76
```

_period and a single space_

```
# xxd -p encrypted.txt | tr -d '\n' | grep -Eo '2e20' | wc -l
101
```

_left double quote_

```
# xxd -p encrypted.txt | tr -d '\n' | grep -Eo 'e2809c' | wc -l
32
```
_right double quote_

```
# xxd -p encrypted.txt | tr -d '\n' | grep -Eo 'e2809d' | wc -l
31
```

Sure smells like English text to me. From here, it's not hard to deduce that the creator used the original text of "Ready Player One" as the plaintext, given the hint `Anorak’s Invitation.txt`. If only I can find the original text in the book!

The biggest challenge now becomes finding the correct text from the book to launch a known-plaintext attack ([KPA](https://en.wikipedia.org/wiki/Known-plaintext_attack)) against the cryptosystem. Despite my sincerest effort, I can only find the first two chapters of the book. It's a copyrighted book after all. :wink:

Assuming the creator bought the book, the original text must be from a legitimate source. Long story short, I've painstakingly put together the plaintext, also known as _crib_, from the Prologue of the book.

<a class="image-popup">
![4d524b61.png](/assets/images/posts/bsidestlv-crypto/4d524b61.png)
</a>

The encrypted flag is at file offset `0x44b3` with a length of 22 characters.

Armed with the plaintext, we can use the following Python code, along with it's builtin dictionary structure to build a codebook:

```py
from itertools import izip

s = ''
dic = {}
n = 0x44af    # this is where the ciphertext or plaintext ends

encrypt = open('encrypted.txt', 'r').read()
decrypt = open('plaintext.txt', 'r').read()

for (c,d) in izip(encrypt[:n], decrypt[:n]):
  dic[c] = d

for x in encrypt[-22:]:
  s += dic[x]

print s
```

<a class="image-popup">
![5c1f67cf.png](/assets/images/posts/bsidestlv-crypto/5c1f67cf.png)
</a>

I'm definitely on to something! Let's assume that `\xbb` and `\xd4` represents `{` and `}` respectively.

<a class="image-popup">
![d49a0e88.png](/assets/images/posts/bsidestlv-crypto/d49a0e88.png)
</a>

Looks like I'm on the right path. Let's put an underscore `_` to represent `\x9b` (it's the only occurrence by the way).

<a class="image-popup">
![fdc4eca7.png](/assets/images/posts/bsidestlv-crypto/fdc4eca7.png)
</a>

By way of inductive reasoning, I think we can infer that the character represented by the underscore is also a digit. From here, it's trivial to use trial-and-error to get to the last digit. We supply the flag, stepping up or down, one at a time, depending on which digit you start with first, to CTFd, and see which one is the correct one.

The flag is `BSidesTLV{49489416671}`.
