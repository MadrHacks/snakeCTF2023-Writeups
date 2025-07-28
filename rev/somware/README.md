# 🏃Somware [_snakeCTF 2023_]

**Category**: rev


## Description

I wanted to play the new SNAKE game for free, but now all my files stopped working. Can you help me?


--------

### **WARNING**
**This file WILL infect all other files in the folder where it is executed!**

**Zip password is _atuorischioepericolo_**

--------

## Solution

Running the file we can see we are asked for an activation key in order to proceed.

Using `strace` we notice that ptrace is called, a classic anti-debug method, running the program with `gdb` we can block the execution and then reach the point when we write our activation key.
This can be done with the following gdb function:
```console
define runtocheck
  delete
  b ptrace
  b write if 1==$rdi
  run
  fini
  # avoid ptrace return 
  set $eax=0
  # skip header print
  ignore $bpnum 12
  c
  #exit i/o function
  fini
  fini
  fini
  fini
  fini
  fini
  fini
  fini
  fini
  end
```


We can now read the assembly since all the checks are done in a series of ifs:

```assembly
=> cmp    QWORD PTR [rsp+0x38],0xf  // check len input == 0xf
   jne    0x55555558c296
   jne    0x55555558c296
   mov    rax,QWORD PTR [rsp+0x30]  // move input to rax
   cmp    BYTE PTR [rax+0x3],0x2d   //4th elemnt of input is 0x2d="-"
   cmp    BYTE PTR [rax+0xc],0x2d   //0xd elemnt of input is 0x2d="-"
   jne    0x55555558c296
   cmp    BYTE PTR [rax],0x31       //first elemnt of input is 0x31="1"
   jne    0x55555558c296
   movsx  edx,BYTE PTR [rax+0x1]    //second elemnt of input is between
   sub    edx,0x30                  //0x30="0" and
   cmp    edx,0x9                   //0x39="9" 
   ja     0x55555558c296
   movsx  edx,BYTE PTR [rax+0x2]    // same for the third
   sub    edx,0x30
   cmp    edx,0x9
   jbe    0x55555558c2b8            // this jump should be taken if correct
   ...
   
   ...
   lea    r13,[rsp+0x80]           //jump here
   lea    rdi,[rsp+0x70]
   mov    QWORD PTR [rsp+0x70],r13
   movzx  eax,WORD PTR [rax+0xd]   //load the input from position 0xd
   lea    rsi,[rip+0x1bb5af]        # 0x555555747884  //loking at this position in gdb we find the string "78"
   mov    QWORD PTR [rsp+0x78],0x2  //argument of next call
   mov    WORD PTR [rsp+0x80],ax    //argument of next call 
   mov    BYTE PTR [rsp+0x82],0x0   //argument of next call
   call   0x55555557c130 <_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareEPKc@plt> 
   mov    rdi,QWORD PTR [rsp+0x70]
   mov    ebx,eax
   cmp    rdi,r13        //compare last 2 chr of input to "78"
   je     0x55555558c310 // if corret we will jump
   ...
   test   ebx,ebx  //here
   jne    0x55555558c296
   mov    rax,QWORD PTR [rsp+0x38]
   test   rax,rax
   je     0x55555558c5a7
   sub    rax,0x1
   lea    rbx,[rsp+0x60]
   mov    edx,0x1
   cmp    rax,0x0
   mov    QWORD PTR [rsp+0x10],rbx
   mov    QWORD PTR [rsp+0x50],rbx
   cmovbe rdx,rax
   je     0x55555558c351
   mov    rax,QWORD PTR [rsp+0x30]
   movzx  eax,BYTE PTR [rax+0x1]   // get second char of activation key
   mov    BYTE PTR [rsp+0x60],al
   mov    QWORD PTR [rsp+0x58],rdx
   mov    BYTE PTR [rsp+rdx*1+0x60],0x0  // terminate the string (did a substring)
   mov    r12,QWORD PTR [rsp+0x50]
   call   0x55555557c060 <__errno_location@plt>
   lea    rsi,[rsp+0x28]
   mov    edx,0xa
   mov    rbx,rax
   mov    eax,DWORD PTR [rax]
   mov    rdi,r12
   mov    QWORD PTR [rsp+0x8],rsi
   mov    DWORD PTR [rbx],0x0
   mov    DWORD PTR [rsp+0x1c],eax
   call   0x55555557c730 <strtol@plt>   // strtol of second char
   cmp    r12,QWORD PTR [rsp+0x28]
   mov    rsi,QWORD PTR [rsp+0x8]
   je     0x55555558c579
   mov    r12d,DWORD PTR [rbx]
   cmp    r12d,0x22
   je     0x55555558c553
   mov    edx,0x80000000
   add    rdx,rax
   shr    rdx,0x20
   jne    0x55555558c553
   test   r12d,r12d
   jne    0x55555558c3c8
   mov    ecx,DWORD PTR [rsp+0x1c]
   mov    DWORD PTR [rbx],ecx
   mov    r12d,ecx
   mov    rcx,QWORD PTR [rsp+0x38]
   add    eax,0x1                     // add 1 to result
   mov    DWORD PTR [rsp+0x1c],eax    // save to 0x1c
   cmp    rcx,0x1
   jbe    0x55555558c55f
   sub    rcx,0x2
   mov    eax,0x1
   mov    QWORD PTR [rsp+0x70],r13
   cmp    rcx,0x0
   cmovbe rax,rcx
   je     0x55555558c406
   mov    rdx,QWORD PTR [rsp+0x30]
   movzx  edx,BYTE PTR [rdx+0x2]     // get third char of activation key
   mov    BYTE PTR [rsp+0x80],dl
   mov    QWORD PTR [rsp+0x78],rax
   mov    edx,0xa
   mov    BYTE PTR [rsp+rax*1+0x80],0x0   // terminate the string (did a substring)
   mov    rcx,QWORD PTR [rsp+0x70]
   mov    DWORD PTR [rbx],0x0
   mov    rdi,rcx
   mov    QWORD PTR [rsp+0x8],rcx
   call   0x55555557c730 <strtol@plt>    // strtol of third char
   mov    rcx,QWORD PTR [rsp+0x8]
   cmp    rcx,QWORD PTR [rsp+0x28]
   je     0x55555558c5cb
   mov    ecx,DWORD PTR [rbx]
   cmp    ecx,0x22
   je     0x55555558c547
   mov    edx,0x80000000
   add    rdx,rax
   shr    rdx,0x20
   jne    0x55555558c547
   test   ecx,ecx
   jne    0x55555558c464
   mov    DWORD PTR [rbx],r12d
   mov    ebx,DWORD PTR [rsp+0x1c]  //load previus result
   mov    rdi,QWORD PTR [rsp+0x70]
   add    ebx,eax                   // add to new result
   cmp    rdi,r13
   je     0x55555558c485
   ....
   mov    rdi,QWORD PTR [rsp+0x50]
   cmp    rdi,QWORD PTR [rsp+0x10]
   je     0x55555558c49f
   ....
   cmp    ebx,0x9                    //compare result to 9
   jne    0x55555558c296
   xor    edx,edx
   mov    ecx,0x5
   lea    rsi,[rip+0x19ddab]        # 0x55555572a261  // this is the string "snake"
   mov    rdi,r15                   // our input is an argument of next call
   call   0x55555557c950 <_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4findEPKcmm@plt>  // function find
   cmp    rax,0xffffffffffffffff   // must NOT return -1
   je     0x55555558c296
   mov    rdi,QWORD PTR [rsp+0x30]
   cmp    rdi,r14
   je     0x55555558c4e0
   mov    rax,QWORD PTR [rsp+0x40]
   lea    rsi,[rax+0x1]
   call   0x55555557c4d0 <_ZdlPvm@plt>
   mov    rax,QWORD PTR [rsp+0x98]
   sub    rax,QWORD PTR fs:0x28
   jne    0x55555558c5c6
   add    rsp,0xa8
   pop    rbx
   pop    rbp
   pop    r12
   pop    r13
   pop    r14
   pop    r15
   ret
```

## Conclusion

In summary, we must find an action key that must:
* have length of 15
* have a "-" in positions 3 and 12
* start with 1
* second and third char are numerical
* end with "78"
* 1 + second char + third char == 9
* contains the string "snake"

one possible activation key is then 
`171-snakeaaa-78`, if we use it we get:

```[redacted]```

meaning that it was accepted, using it with the remote endpoint we are given will print the flag.

