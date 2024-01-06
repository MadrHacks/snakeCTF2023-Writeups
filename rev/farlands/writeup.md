# Farlands

## Description

> Don't get lost!

## Analysis

Launching the binary we can see that it's asking for input and then a hex string is printed. We are given an `output.txt` file so the logical conclusion is that the flag is the input that generates that same output.

Running `readelf` on the binary, we notice that the sections have been stripped away and that it allocates five RWX segments (at 0x160000, 0x320000, 0x640000, 0xbeef0000 and 0xdead0000).
The entrypoint is at 0x64052a, so we can assume there's a function there. However looking at the disassembly shows the following:
```
=> 0x64052a:	mov    edi,0x1
   0x64052f:	mov    edx,0x10
   0x640534:	movabs rsi,0xbeef01a0
   0x64053e:	mov    eax,0x9a
   0x640543:	mov    ecx,0x406
   0x640548:	push   rcx
   0x640549:	add    BYTE PTR ds:0x640552,0x3
   0x640551:	lar    ecx,WORD PTR [rax+0x1]
   0x640555:	(bad)
   0x640556:	mov    eax,0x9a
   0x64055b:	shr    r11d,0x8
   0x64055f:	and    r11,0x1
   0x640563:	sub    BYTE PTR [rcx+r11*1-0x1],0x3
   0x640569:	pop    rcx
   0x64056a:	or     rcx,r11
   0x64056d:	loop   0x640548
```
There's a weird `lar` instruction and a `(bad)`, though we can see at `0x640549` that those instructions are getting modified (remember that all the segments are RWX), and become `syscall; add rsi, rdx`. The binary is calling the `modify_ldt` syscall, which is used to add or remove entries from the Local Descriptor Table (check [LDT @ OSDev.org](https://wiki.osdev.org/Local_Descriptor_Table) and [Segmentation in protected mode @ OSDev.org](https://wiki.osdev.org/Segmentation#Protected_Mode)), which will be later used to run code in 16-bit and 32-bit mode and with a different base address.
We also see at `0x64055b` - `0x64056a` that the binary is doing some anti-debugging by reading at the flags (r11) and saved IP (rcx) after the `syscall` instruction, checking the status of the Trap Flag which is set to 1 while single-stepping on GDB.

The loaded segments, stored as `struct user_desc`, are located at `0xbeef01a0` and are 1030 in total.

The binary then does its first far-call to a procedure at 0x320062 to load `/proc/self/status` and the S-boxes (they are stored inside the `limit` field of 1024 segments) which will be used later. Since the loading of the SBOXes doesn't really include any form of antidebugging, they can just be dumped from memory at `0xbeef7800`.

> Note: Far calls will probably mess with your decompiler and your debugger. The best way to handle this at a decompiler level is to patch out all of the setup for the call with a normal call or jump instruction, this way you should be able to decompile properly. Some decompilers such as Ghidra and IDA provide ways to handle 32-bit and 16-bit code, so that can also be used as an aid to read the disassembly of the far targets.
> For the debugger, you might have some problems with the disassembly since it won't consider the segment base, however the registers should still be right and you should be able to step with no problems.

Another far call is made to `0x320050` to do a simple ptrace-check, then the binary calls `0x64007d` to actually get and process the input.

After reading the input, a 32-bit function at `0x320059` is called. This function is just a trampoline to a 16-bit function defined at `0x1600bf`, which does `strlen(eax) ^ ax ^ 0x66b8`. Since the input is always stored at `0xdead1338`, the xor-key is `0x1338 ^ 0x66b8`, which is `0x7580`.

Another anti-debugging ptrace-based check is called, then the xored `size` is used to calculate a 4-byte key starting from the first four bytes of the input: `__builtin_bswap32(*(unsigned int*) &input[0]) ^ (size | size << 16)` (bswap inverts the endianness). We know the flag must start with `snakeCTF{`, thus the first four characters will be `snak`.

At this point, the value of the field `TracerPid` is extracted from the previously loaded `/proc/self/status` file. This value and the result of the previous calls to ptrace will be used in the encryption algorithm, so we need to keep in mind their expected values (0 for the first ptrace, -1 for the second ptrace, and 0 for `TracerPid`)

The encryption algorithm is an SP network with 8 rounds and a block length of 64, with different S-boxes and P-boxes for each round. The previously computed 4-bytes key is used to xor the input with the function at `0x320009` for each round, then a 256-byte S-box is applied, and finally the P-box is applied. 

After another ptrace check, the result is encrypted 2 bytes at a time with RSA through the function at `0x320026`. The e value is constant and set to `0xbf`, while the N value gets computed at `0x160043` using the previously mentioned first four bytes of the input, thus it can be assumed to be constant and is equal to `0xf01f0945`, which can be trivially factorized to `0xf529 * 0xfabd`.

Finally, the result is xored using a 4-byte key which is computed as follows: `(size >> 8 | size << 8 | (size & 0xff) << 24) ^ limit_key`, where size is the previously computed xored size and limit_key is the value present in the `limit` field of the LDT segment identified by the entry number `72` (`0x9ad7`)

The output is then printed and the program exits.

## Solution

All the operations can be reversed, except from the size calculation. Since the size can only be in the range 0 - 64 (probably less since `snakeCTF{}` must be included), it can be bruteforced. The following script will try to recover the input given a dump of the S-boxes `sboxes.bin` and of the P-boxes `pboxes.bin` (both of which can be obtained through GDB), and the output of the binary (output.txt):

```
#!/usr/bin/env python3
from pwn import *
from Crypto.Util.number import *

sboxes = [x for x in open('sboxes.bin', 'rb').read()]
sboxes = [sboxes[i*256:(i+1)*256] for i in range(8)]

pboxes = open('pboxes.bin', 'rb').read()
pboxes = [u16(pboxes[i:i+2]) for i in range(0, len(pboxes), 2)]
pboxes = [pboxes[i*512:(i+1)*512] for i in range(8)]

def dec(i: int):
    p = 0xf529
    q = 0xfabd
    d = inverse(0xbf, (p-1)*(q-1))
    return pow(i, d, p*q)

def gen_len_enc(length: int):
    return 0x1338 ^ 0x66b8 ^ length

def gen_key(lenkey: int):
    return u32(b"snak"[::-1]) ^ (lenkey << 16 | lenkey)
    
def rev_round(ct: bytes, round: int, xorkey: int):
    ctbytes = list(ct)

    pbox = pboxes[round]
    sbox = sboxes[round]

    for i in reversed(range(512)):
        src_byte = i//8
        src_bit = i%8
        dst_byte = pbox[i]//8
        dst_bit = pbox[i]%8

        src = (ctbytes[src_byte] >> src_bit) & 1
        ctbytes[src_byte] ^= src << src_bit

        dst = (ctbytes[dst_byte] >> dst_bit) & 1
        ctbytes[dst_byte] ^= dst << dst_bit

        ctbytes[src_byte] ^= dst << src_bit
        ctbytes[dst_byte] ^= src << dst_bit

    for i in range(64):
        ctbytes[i] = sbox.index(ctbytes[i])

    ctbytes = bytes(ctbytes)
    return b"".join([p32(u32(ctbytes[i:i+4]) ^ xorkey) for i in range(0, len(ctbytes), 4)])

def undo_rsa_enc(src: bytes, size_key: int):
    src = b"".join([p32(u32(src[i:i+4]) ^ (size_key << 8 | size_key >> 8 | (size_key & 0xff) << 24)) for i in range(0, len(src), 4)])
    return b"".join([p16(dec((u32(src[i:i+4]) ^ 0x9ad7)) & 0xFFFF) for i in range(0, len(src), 4)])

def rev(out: bytes) -> bytes:
    for i in range(64):
        len_key = gen_len_enc(i)
        xorkey = gen_key(len_key)
        test_dec = undo_rsa_enc(out, len_key)
        for j in reversed(range(8)):
            test_dec = rev_round(test_dec, j, xorkey)

        if b"snak" in test_dec:
            return test_dec
            
if __name__ == "__main__":
    out = bytes.fromhex(open("output.txt", "r").read().strip())
    print(rev(out))
```
