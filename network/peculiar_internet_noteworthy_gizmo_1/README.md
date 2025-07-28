# Peculiar Internet Noteworthy Gizmo 1 [_snakeCTF 2023_]

**Category**: network


## Description

The network was dead quiet. Yet, in the eerie silence, I could almost feel the netadmin's presence, their thoughts and intentions woven into the very fabric of the IPAM.

Note: `nmap` is allowed INSIDE the instance.

_The flag is NOT in standard format!_

## Hint

The internal hosts only respond to ping, no ports are open

## Solution

The mention to IPAM should point in the direction of analyzing IP addresses. Moreover, the acronym of the title is `ping`.

Checking the available network interfaces (with e.g. `ip a`) reveals a `chall` interface:

```
2: chall: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN group default qlen 1000
    link/ether ce:22:7c:6f:80:a7 brd ff:ff:ff:ff:ff:ff
    inet 10.10.0.1/23 scope global chall
      valid_lft forever preferred_lft forever
```

Since `nmap` is allowed a ping scan can be performed: `nmap -sn -n 10.10.0.0/23`.

The result of this scan shows that some hosts (133 out of 512) are up.
Also, some kind of (possibly binary) pattern can be seen in the output: only two hosts (the `0.1` and the `0.2`) do not fit well in it.

Plotting the hosts on the terminal could prove useful:

```
_XX____________________________________________________________________________________________________________________X_X_X____XXX_X____X_XXX____XXX_X_XXX____X____XXX_X_XXX_X____XXX____X_X_XXX_X____XXX_X_X_X____X____X____X_XXX_XXX_X____XXX_X_X_X____XXX_XXX_XXX____XXX_XXX_XXX____X_XXX_XXX_X____XXX_XXX____XXX_XXX_XXX____X_XXX_X____X_X_X____X____XXX_X_XXX_X____XXX_XXX_XXX____XXX_X_X____X____________________________________________________________________________________________________________________________
```

It seems like there are some blocks of either one or three consecutive hosts up. Moreover, the spaces between these blocks are also of one or four hosts down. This seems like Morse code, where `X` is a dot, `XXX` is a dash, `_` is an intra-character gap and `____` is an inter-character gap.

Parsing the string this way leads to the flag:

```
... -. .- -.- . -.-. - ..-. -... . . .--. -... --- --- .--. -- --- .-. ... . -.-. --- -.. .
SNAKECTFBEEPBOOPMORSECODE
```

## Solver

```python
data = """
Nmap scan report for 10.10.0.1
Nmap scan report for 10.10.0.2
Nmap scan report for 10.10.0.119
[...]
Nmap scan report for 10.10.1.131
"""

data = [d[len("Nmap scan report for 10.10.") :] for d in data.split("\n")[1:-1]]
data = [d.split(".") for d in data]
data = [(int(a) << 8) + int(b) for [a, b] in data]

print(data)

dmap = [" " for _ in range(512)]

for d in data:
    dmap[d] = "X"

dmap = "".join(dmap)

print(dmap + "a")

dmap = dmap.replace("XXX", "-")
dmap = dmap.replace("X", ".")
dmap = dmap.replace("   ", "A")
dmap = dmap.replace(" ", "")
dmap = dmap.replace("A", " ")

print(dmap)
```


