# peculiar internet noteworthy gizmo 2

## Description

The once-elusive netadmin's messages now resonate clearly through the wider network, their intentions revealed for all of us to see.

Note: `nmap` is allowed INSIDE the instance.

## Hint

https://xkcd.com/195/

## Solution

The solution is similar to the one for level 1. Here the `chall` net is way bigger (`/20`), so maybe some other encoding is used. The hint should point to the standard way to map the IPv4 space: Hilbert curves.

The `nmap` command is like before: `nmap -sn -n 10.20.0.0/20`.

From the fact that in a `/20` there are 4096 addresses, a 64x64 grid is needed. The order of the required Hilbert curve is 6, since 64 is equal to 2^6.

Plotting the data using a 6th order 2-dimension Hilbert curve reveals a QRcode:

![the plotted data](map2.png)

Scanning the QRcode reveals the flag: `snakeCTF{next_time_map_all_internet_with_hilbert_curves}`

## Solver

```python
data = """
Nmap scan report for 10.20.0.1
Nmap scan report for 10.20.0.2
Nmap scan report for 10.20.0.160
[...]
Nmap scan report for 10.20.15.117
"""

data = [d[len("Nmap scan report for 10.20.") :] for d in data.split("\n")[1:-1]]
data = [d.split(".") for d in data]
data = [(int(a) << 8) + int(b) for [a, b] in data]

print(data)

from hilbertcurve.hilbertcurve import HilbertCurve

hilbert_curve = HilbertCurve(6, 2)
points = hilbert_curve.points_from_distances(data)

print(points)

from PIL import Image

img = Image.new("1", (64, 64), 1)

for p in points:
    img.putpixel(p, 0)

img.save("map2.png")
```
