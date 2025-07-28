# First Hunt [_snakeCTF 2023_]

**Category**: osint

## Challenge

Hey!
We intercepted this strange message, 
I think we finally found them.
Let me know if you find something

## Attachments

An eml file named `info`.

## Solution

In the email we learn about a potential "product" exchange.
The receiver is informed to change the credentials for the shop, "paste them somewhere" and burn the message after.

So the first thing we can do is to search for the place where the credentials are stored (or better, "pasted").

Searching for the account on pastebin we can find the credentials.

Once we find the (pastebin)[https://pastebin.com/u/wazzujf2?source=post_page-----df99a71ea174--------------------------------] account, we can find the credentials.

We can now login to the shop and find the flag.

> snakeCTF{h1dd3n_s3rv1ce5_4re_fuN_t0_bu1ld}


