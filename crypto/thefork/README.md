# The fork [_snakeCTF 2023_]

**Category**: crypto


### Analysis
The first thing to notice is that the cipher is a so-called fork cipher. In particular, it is a tweakable AES-based forkcipher that splits the state after 5 rounds. Fork-ciphers have got 3 main functions:
- encrypt
- decrypt
- compute_sibling

The attack involves the concepts of **differential cryptanalysis** and **reflective trails**. 
By searching on your favourite search engine you can find this [article](https://eprint.iacr.org/2019/289.pdf).

As for the attack, we suggest reading the full article, especially the part that involves reflective trail technique. Pay attention that, differently from the article, **you can use a tweak of 128 bits (it makes the attack easier)**.

If you want to learn something about differential cryptanalysis, these are some references:

- [Linear and differential cryptanalysis on SPN-like ciphers](http://www.cs.bc.edu/~straubin/crypto2017/heys.pdf)
- [Linear and differential cryptanalysis: general overview](https://summerschool-croatia.cs.ru.nl/2014/slides/Differential%20and%20Linear%20Cryptanalysis.pdf)


### Flag
Once you find the key, put it into the flag format.
`snakeCTF{7631c6e035b55f05b8e93b31c979a024}`

### Code

```python
from pwn import *
import multiprocessing as mp
from random import randrange
from copy import deepcopy
from forkaes import *
from AES.aes_utilities import *
from data import out_diff_for_tweak
import itertools

CORES = 8
EXP = 3

r = remote("crypto.snakectf.org", 1401)

text = r.recvuntil(b'>').decode().split("\n")
ref_plaintext = eval(text[2])
ref_tweak = eval(text[5])

ref_left_ciphertext = eval(text[8][6:])
ref_right_ciphertext = eval(text[9][7:])

r.close()

def get_key_scheduling_from_intermediate_key(key, from_index, max):
    keys = [ [0 for _ in range(16)] for i in range(max+1)]

    for i in range(16):
        keys[from_index][i] = key[i]


    # Compute Key schedule of block size for each round less than start_key_number (the round for which we know the intermediate key)
    for i in range(from_index,0, -1):
        keys[i-1][12] = keys[i][12]^keys[i][8]
        keys[i-1][13] = keys[i][13]^keys[i][9]
        keys[i-1][14] = keys[i][14]^keys[i][10]
        keys[i-1][15] = keys[i][15]^keys[i][11]

        keys[i-1][8] = keys[i][8]^keys[i][4]
        keys[i-1][9] = keys[i][9]^keys[i][5]
        keys[i-1][10] = keys[i][10]^keys[i][6]
        keys[i-1][11] = keys[i][11]^keys[i][7]

        keys[i-1][4] = keys[i][4]^keys[i][0]
        keys[i-1][5] = keys[i][5]^keys[i][1]
        keys[i-1][6] = keys[i][6]^keys[i][2]
        keys[i-1][7] = keys[i][7]^keys[i][3]
        
        temp = keys[i-1][12]
        keys[i-1][0] = SBOX[keys[i-1][13]]^keys[i][0]^Rcon[i]
        keys[i-1][1] = SBOX[keys[i-1][14]]^keys[i][1]
        keys[i-1][2] = SBOX[keys[i-1][15]]^keys[i][2]
        keys[i-1][3] = SBOX[temp]^keys[i][3]


    for i in range(from_index+1,max+1):
        temp = keys[i-1][12]
        keys[i][0] = SBOX[ keys[i-1][13] ] ^ keys[i-1][0] ^ Rcon[ i ]
        keys[i][1] = SBOX[ keys[i-1][14] ] ^ keys[i-1][1]
        keys[i][2] = SBOX[ keys[i-1][15] ] ^ keys[i-1][2] 
        keys[i][3] = SBOX[ temp ] ^ keys[i-1][3]
       
        keys[i][4] = keys[i-1][4] ^ keys[i][0]
        keys[i][5] = keys[i-1][5] ^ keys[i][1]
        keys[i][6] = keys[i-1][6] ^ keys[i][2]
        keys[i][7] = keys[i-1][7] ^ keys[i][3]
        
        keys[i][8] = keys[i-1][8] ^ keys[i][4]
        keys[i][9] = keys[i-1][9] ^ keys[i][5]
        keys[i][10] = keys[i-1][10] ^ keys[i][6]
        keys[i][11] = keys[i-1][11] ^ keys[i][7]

        keys[i][12] = keys[i-1][12] ^ keys[i][8]
        keys[i][13] = keys[i-1][13] ^ keys[i][9]
        keys[i][14] = keys[i-1][14] ^ keys[i][10]
        keys[i][15] = keys[i-1][15] ^ keys[i][11]

    return keys



def get_sibling(remote_instance, ciphertext: list, tweak: list, side="left"):
    remote_instance.sendline(b"1")
    remote_instance.sendlineafter(b'ciphertext : ', ",".join([str(a) for a in ciphertext]))
    remote_instance.sendlineafter(b'tweak : ', ",".join([str(a) for a in tweak]))
    remote_instance.sendlineafter(b'): ', side)
    result = eval(remote_instance.recvuntil(b'>').decode().split("\n")[1])
    
    return result





def attack_byte_thread( possible_t1_value, possible_t2_value, tweak1, tweak2, column, byte_number, key_bytes_possibilities_counter):
    tested_t1 = [0 for _ in range(16)]
    tested_t2 = [0 for _ in range(16)]
    
    for key in range(0,256):    
        for i in range(16):
            tested_t1[i] = deepcopy(possible_t1_value[i])
            tested_t2[i] = deepcopy(possible_t2_value[i])

        key0 = (key & 0xFF) % 256

        tested_t1[4*column+byte_number] ^= key0 
        tested_t2[4*column+byte_number] ^= key0 


        tested_t1 = inverse_sub_bytes(tested_t1)
        tested_t2 = inverse_sub_bytes(tested_t2)

        tested_t1 = add(tested_t1, tweak1)
        tested_t2 = add(tested_t2, tweak2)
        
        tested_t1 = inverse_round(tested_t1)
        tested_t2 = inverse_round(tested_t2)

        risultato = 1

        for i in range(16):
            if tested_t1[i]^tested_t2[i] > 0:
                risultato = 0
                break

        if risultato == 1:
            key_bytes_possibilities_counter[key0] += 1




def attack_byte(column, byte_number, start_side, key_number, key_bytes_possibilities_counter):
    # new instance
    r = remote("crypto.snakectf.org", 1401)
    r.recvuntil(b'>')

    key_bytes_counter = [0 for _ in range(256)]
    # maybe we need to launch a thread every 0.100 ms
    tweak_difference = randrange(0, 256)
    tweak1 = [ randrange(0,256) for _ in range(16)]
    tweak2 = deepcopy(tweak1)

    # putting the difference within tweak 2
    tweak2[4*column+byte_number] = tweak2[4*column+byte_number] ^ tweak_difference

    # the ciphertext we will use 
    base_c = [ randrange(0,256) for _ in range(16)]

    possible_t1_values = [ [0 for _ in range(16)] for _ in range(256) ]
    possible_t2_values = [ [0 for _ in range(16)] for _ in range(256) ]


    for possible_c1_value in range(0,256):
        c1_tilde = deepcopy(base_c)
        c1_tilde[4*column+byte_number] = possible_c1_value

        c1_tilde = shift_rows(c1_tilde)
        c1_tilde = mix_columns(c1_tilde)
        c1_tilde = add(c1_tilde, tweak1)
        c1_tilde = get_sibling(r, c1_tilde, tweak1, side=start_side)
        c1_tilde = add(c1_tilde, tweak1)
        c1_tilde = inverse_mix_columns(c1_tilde)
        c1_tilde = inverse_shift_row(c1_tilde)
        
        for i in range(0,16):
            possible_t1_values[possible_c1_value][i] = c1_tilde[i]
    
    for possible_c1_value in range(0,256):
        c1_tilde = deepcopy(base_c)
        c1_tilde[4*column+byte_number] = possible_c1_value

        c1_tilde = shift_rows(c1_tilde)
        c1_tilde = mix_columns(c1_tilde)
        c1_tilde = add(c1_tilde, tweak2)
        c1_tilde = get_sibling(r, c1_tilde, tweak2, side=start_side)
        c1_tilde = add(c1_tilde, tweak2)
        c1_tilde = inverse_mix_columns(c1_tilde)
        c1_tilde = inverse_shift_row(c1_tilde)
        
        for i in range(0,16):
            possible_t2_values[possible_c1_value][i] = c1_tilde[i]
 

    # finding a correct couple in order to find the key byte
    indext1 = -1
    indext2 = -1

    for i in range(0,256):
        for j in range(0,256):
            indext1 = -1
            indext2 = -1

            result = 1
            for byte in range(0,16):
                if byte != 4*column+byte_number:
                    if possible_t1_values[i][byte]^possible_t2_values[j][byte] > 0:
                        result = 0
                        break

            if result == 1:
                result = 0
                for poss in range(0,127):
                    if possible_t1_values[i][4*column+byte_number]^possible_t2_values[j][4*column+byte_number] == out_diff_for_tweak[tweak_difference-1][poss]:
                        result = 1
                        break

                if result == 1:
                    indext1 = i
                    indext2 = j
                    break

    if indext1 > -1 and indext2 > -1:
        attack_byte_thread(possible_t1_values[indext1], possible_t2_values[indext2], tweak1, tweak2, column, byte_number, key_bytes_counter )
    
    key_bytes_possibilities_counter[column*4+byte_number] = key_bytes_counter
    print(f"DONE column: {column}, byte_number: {byte_number}")
    r.close()



def compute_possibilities_for_key(key_bytes_possibilities_counter):
    number_of_keys = 0

    possibilities_for_byte = [ 0 for _ in range(16)]
    max_for_byte = [ 0 for _ in range(16)]

    values_for_byte = [ [] for _ in range(16) ]

    for j in range(0,16):
        counter = 0
        max = 0
        for i in range(0,256):
            if key_bytes_possibilities_counter[j][i] > max:
                max = key_bytes_possibilities_counter[j][i]

        if max > 0:
            for i in range(0, 256):
                if key_bytes_possibilities_counter[j][i] == max:
                    counter += 1
                    values_for_byte[j].append(i)

        possibilities_for_byte[j] = counter
        max_for_byte[j] = max

    column_possibilities = [ 0,0,0,0]

    for i in range(4):
        column_possibilities[i] = possibilities_for_byte[0+4*i]*possibilities_for_byte[1+4*i]*possibilities_for_byte[2+4*i]*possibilities_for_byte[3+4*i]


    

    return values_for_byte, column_possibilities[0]*column_possibilities[1]*column_possibilities[2]*column_possibilities[3]



multithreading = True

#### MAIN ####
manager = mp.Manager()
key_bytes_possibilities_counter = manager.list([ [] for _ in range(16)])

if multithreading:

    procs = []
    for column in range(0,4):
        for byte in range(0, 4, 16//CORES):
            proc1 = mp.Process(target=attack_byte, args=(column, byte, "right", 7, key_bytes_possibilities_counter ))
            proc2 = mp.Process(target=attack_byte, args=(column, byte+1, "right", 7, key_bytes_possibilities_counter ))
            procs.append(proc1)
            procs.append(proc2)
            proc1.start()
            proc2.start()

    # complete the processes
    for proc in procs:
        proc.join()
else:
    print("[+] Finding first column possibilities\n")
    attack_byte(0, 0, "right", 7)
    attack_byte(0, 1, "right", 7)
    attack_byte(0, 2, "right", 7)
    attack_byte(0, 3, "right", 7)

    print("[+] Finding second column possibilities\n")
    attack_byte(1, 0, "right", 7)
    attack_byte(1, 1, "right", 7)
    attack_byte(1, 2, "right", 7)
    attack_byte(1, 3, "right", 7)

    print("[+] Finding third column possibilities\n")
    attack_byte(2, 0, "right", 7)
    attack_byte(2, 1, "right", 7)
    attack_byte(2, 2, "right", 7)
    attack_byte(2, 3, "right", 7)

    print("[+] Finding fourth column possibilities\n")
    attack_byte(3, 0, "right", 7)
    attack_byte(3, 1, "right", 7)
    attack_byte(3, 2, "right", 7)
    attack_byte(3, 3, "right", 7)


key_values_for_byte, counter_possible_keys = compute_possibilities_for_key(key_bytes_possibilities_counter)
list_of_possible_keys = list(itertools.product(*key_values_for_byte))

print()
for kk in list_of_possible_keys:
    original_key = mix_columns(shift_rows(list(kk)))
    keys = get_key_scheduling_from_intermediate_key(original_key, 7, 9)
    k0 = keys[0]
    x,y = encrypt(ref_plaintext, k0, ref_tweak)
    if x == ref_left_ciphertext and y == ref_right_ciphertext:
        print("Key found")
        flag = bytes(k0).hex()
        print("snakeCTF{"+flag+"}")
        break
    
```


