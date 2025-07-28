# Bloom Bloom [_snakeCTF 2023_]

**Category**: crypto


### Analysis
The first thing to notice is the `add_user` method.
```python

users = 0b0

def add_user(username):
    global users

    cipher = AES.new(key, AES.MODE_ECB)
    enc_username = cipher.encrypt(pad(username.encode(), AES.block_size))
    for i in range(hash_functions_count):
        digest = mmh3.hash(enc_username, i) % size
        users = users | (0x1 << digest)
    
```

Every time a new user is registered to the system, the `users` variable is updated by setting some of its bits.

On the other hand, by analyzing the `check_user` method:
```python
def check_user(username):
    global users
    cipher = AES.new(key, AES.MODE_ECB)
    enc_username = cipher.encrypt(pad(username.encode(), AES.block_size))
    
    for i in range(hash_functions_count):
        digest = mmh3.hash(enc_username, i) % size
        if users & (0x1 << digest) == 0:
            return False
    
    return True
```

we can notice that a user exists within the `users` variable if and only if the bits are correctly set.
Moreover, it does not check that the other bits are set to `0`, then a user could be found even if it was not registered yet. For example, if the `users` variable is `011`, it would recognize as registered users `001`, `011`. `010`. 


### Solver
To exploit this issue, we can simply run a script that registers random users until the `Administrator` user is recognized as a valid user by the system. At that point, we can get the flag.

```python
r = remote(HOST, PORT)
r.recvuntil(b">")

attempts_counter = 0
while True:
    attempts_counter += 1

    username = "".join([random.choice(alphabet) for _ in range(20)])
    r.sendline(b"3")
    r.sendlineafter(b"Username: ", username.encode())
    r.sendlineafter(b">", b"2")

    response = r.recvuntil(b">")
    if b"Here is your flag:" in response:
        print(response)
        print(f"Flag found in {attempts_counter} attempts")
        break

```
### The flag

`snakeCTF{w3lc0me_to_cryp70_ch4ll3ng35}`
