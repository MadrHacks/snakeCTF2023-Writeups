# Closed Web Net [_snakeCTF 2023_]

**Category**: network


## Challenge message

I have this old 2006 home automation gateway, but I lost the password to access it.
I have a pcap file of the network traffic between it and a client.
Can you help me?

Flag format: `snakeCTF{PASSWORD_MODELNAME_FIRMWAREVERSION}` \
The firmware version must be in the format `V.R.B` where `V`, `R` and `B` are numbers.

## Description

This challenge is about the protocol [BTicino OpenWebNet](https://developer.legrand.com/Documentation/) protocol. \
More specifically, the challenge is centered around the older authentication system used in pre-2016 devices. \
Also, in this challenge we can see how some devices are insecure by design.

## Objective

- Find the protocol and its documentation
- Find the old authentication algorithm
- Find the password and the nonce in the pcap file
- Bruteforce the password
- Get the model code in the pcap file
- Using the model code, get the model name from the documentation
- Send the flag

## Solving

### Finding the protocol

The first step is to find the protocol used by the device. \
The best thing to do is to analyze the pcap file with Wireshark.
First of all, we can filter out all the unnecessary traffic by using the filter `!tls && !dns && tcp.port != 443`. \
What we remain with is HTTP traffic and TCP traffic on port 20000.
By looking at the HTTP traffic we can see that the client is a raspberry pi and it's running `apt update` \
But the most interesting part is the TCP traffic on port 20000.
After searching for the port on Google, we find out on [Wikipedia](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers)
that the protocol is called OpenWebNet and it's used by BTicino devices. \
The second result on Google for "OpenWebNet" is the introduction of the documentation of the protocol. \
So, after some more research we find the [page](https://developer.legrand.com/Documentation/) with every section of the documentation.
And there is a file about some authentication algorithm.

### Finding the authentication algorithm

But there is one problem, the documentation for the authentication system is from 2016, 10 years after the device was
made. \
After reading it, we can notice that an older authentication system is mentioned.
So, we can assume that the device is using the older authentication system. \
But how can we find the old authentication algorithm? \
Simply, by looking at other implementations of the protocol. The documentation for this algorithm is public, so probably
someone has already implemented it in a client. \
Therefore, after a little more investigation we come across this [implementation](https://github.com/karel1980/reopenwebnet)
of the protocol in python with the old authentication algorithm.
The algorithm is very simple, and it's mainly composed of *shift* and *and* logic operations, so it's easily
bruteforceable.

### How to get the model's name?

We know that we are talking about some kind of gateway, so the best thing to do is to search in the documentation for the [gateway](https://developer.legrand.com/uploads/2019/12/WHO_13.pdf). \
In the documentation we can find the model's exact message to request the model's name and also the firmware version.
So, the message for requesting the model's name is `*#13**15##` and the server will respond with a code that represents the model. \
And the message for requesting the firmware version is `*#13**16##`.

### Putting everything together

Now that we have all the information we need, we can write the script to bruteforce the password and get all the information.

[solver.py](attachments/solver.py)

After running the script, we get the flag: `snakeCTF{12345_F452_3.1.16}`

### Note

The password is `12345` because it's the default password for the device and in some models (like the F452) it cannot be changed.
This can be easily bruteforcable or found in the documentation or various forums.


