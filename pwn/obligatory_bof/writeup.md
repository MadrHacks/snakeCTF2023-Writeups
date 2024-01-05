# Obligatory BOF

## Description

Well, you gotta do what you gotta do!

nc pwn.snakectf.org 1338

## Solution

### Reversing

Reversing is again pretty simple.

The main looks like the following:

```c
undefined8 main(void) {
  char buffer [32] = {0};

  init();
  printf("Well, just tell me what to do: ");
  read(0,buffer,0x100);
  puts("Ok, got it!");
  return 0;
}
```

An input is taken from the user, and then the program returns.

### Vulnerability

There is another (plain) buffer overflow in the `read` call: the buffer is of size `0x20`, but the read call reads up to `0x100` bytes.

### Exploitation

This time, we do not have an easy way to get a shell. Instead, we must first leak libc address, and then use it to craft a ROP chain that calls `system("/bin/sh")`

You can find the [solver](../solver/solve.py) here.
