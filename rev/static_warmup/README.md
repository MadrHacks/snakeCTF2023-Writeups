# Static Warmup [_snakeCTF 2023_]

**Category**: rev


## Description

Who says you have to move to warmup?

## Solution

### Static analysis

Using the `file` command we discover that the file is an x86 elf stripped and statically linked.

Opening with ghidra, we can quickly recognise the main function that calls a function, we can call it `checkFlag()`, on our input and prints "correct" if it returns True.


`checkFlag()` in ghidra after a bit of var renaming looks like this:


```c
undefined8 checkflag(char *param_1)

{
  long lVar1;
  undefined8 ret;
  long in_FS_OFFSET;
  int i;
  byte xor_data [16];
  undefined auStack_38 [24];
  long local_20;
  
  lVar1 = unkFunc0(param_1);
  if (lVar1 == 0x24) {
    ret = unkFunc1(8);
    unkfunc2(ret,param_1,8);
    unkFunc3(ret,xor_data);
    unkfunc2(auStack_38,xor_data,0x10);
    i = 0;
    while( true ) {
      lVar1 = unkFunc0(param_1);
      if (lVar1 - 8 <= i) break;
      if ((byte)(xor_data[i] ^ param_1[i + 8]) != (&xored)[i]) {
        ret = 0;
        return ret;
      }
      i = i + 1;
    }
    ret = 1;
  }
  else {
    ret = 0;
  }

  return ret;
}
```

We have some unknown functions, and we have to remember the elf is stripped and statically linked, which means that they could be standard library functions.
For example, the first one could be a strlen since it takes a pointer to a string and returns an int, but we can confirm this with a dynamic analysis.

### Dynamic analysis

Running the command `./crackme aaaaaaaaa` on gdb and braking immediately after the unkFunc0 call we can see that the return value on rax is 0x9, confirming that it's strlen.

Doing the same for unkFunc2 we can see that it returns the first eight char of our input meaning that it's some kind of substring, maybe strncpy, we have to remember that the first eight char are the same for every flag: `snakeCTF`.

We don't really care about what the other functions are since after adjusting the length of our string to pass the if-clause we can dump the value of xor_data with gdb.


After getting the `xor_data` dump we can xor it with `xored`, that we can find in the `.data` section of the binary file, and get the flag.


