# Military Grade Authentication [_snakeCTF 2023_]

**Category**: pwn


## Description

We just started using this military-grade software to authenticate access to our infrastructure.

We don't really understand it, but I'm sure that it's secure! We don't know the password either, after all!

nc pwn.snakectf.org 1337

## Solution

### Reversing

Reversing is pretty simple as the binary is pretty simple and contains symbols.

The main looks like the following:

```c
void main(void) {
  int urandom_fd;
  ssize_t sVar1;
  char our_pwd [32] = {0};
  char rand_pwd [32] = {0};

  init();
  urandom_fd = open("/dev/urandom",0);
  if (urandom_fd == -1) {
    err(1,"Someone stole my entropy file");
  }
  sVar1 = read(urandom_fd,rand_pwd,0x20);
  if (sVar1 != 0x20) {
    errx(1,"How does this even happen??");
  }
  close(urandom_fd);
  printf(s__Stop_right_here_,_this_is_a_pri_00102058);
  sVar1 = read(0,our_pwd,0x80);
  if (sVar1 < 1) {
    err(1,"read broken lol");
  }
  urandom_fd = strcmp(our_pwd,rand_pwd);
  if (urandom_fd == 0) {
    puts(s__Looking_good._You_can_go_ahead._00102118);
    get_shell();
  }
  puts(s__Hey!_What_are_you_trying_to_do?_00102148);
  exit(1);
}
```

Basically, we can see that a random password is read from `/dev/urandom`, and then compared with a user-provided password. If they match, the user is granted a shell.

### Vulnerability

The vulnerability is easy to spot: the user-provided password uses a buffer of size `0x20`, but `0x80` bytes are read into it, leading to a buffer overflow.

### Exploitation

As the challenge already provides a way to get a shell, we can use the buffer overflow to make the password compare succeed. In order to do that, we can simply make sure the two strings are equal. The simplest way is to make both strings start with a null byte.

You can find the [solver](../solver/solve.py) here.


