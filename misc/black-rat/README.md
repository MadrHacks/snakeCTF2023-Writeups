# Black Rat [_snakeCTF 2023_]

**Category**: misc

## Challenge

I intercepted something weird, are we under attack? Should we be scared? Is this a prank? Please check and let me knows

## Solution

Reading the pcap, we notice that we have to deal with a USB device which is doing something.
We have to discover what is doing.

Using tshark we discover that we could be dealing with mouse movement, so we try to recover the coordinates.

We save these coordinates to a file that will be later accessed to find the flag.

We then can write a script (attached) that takes the pcap in input and tracks down if a button is pressed or not.

Plotting the graph we see the flag

> snakeCTF{c4tch_m3_if_u_c4n!}


