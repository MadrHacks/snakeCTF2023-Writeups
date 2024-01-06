# snakeCTF 2023
## [crypto] little errors made it possible

### Analysis
We are supplied with:
- a prime `p`
- an error bound `error_bound`
- a list `b` of 50 values in $Z_p$
- a list `A` of 50 lists of 5 values each. The values are in $Z_p$

The description told us that `b` values are generated in the following way: `A*s + e = b`

This is a common problem which is called **Learning with errors**.
It is related to the use of lattices and in particular of the most famous **Shortest vector problem (SVP)**.

The problem is solvable only if errors are not so big, this is the reason why an error bound is supplied.

### Solution
- `A` is a matrix of dimension 50 x 5 
- `b` is a vector of dimension 50 x 1
- `e` must be a vector of dimension 50 x 1
- `s` must be a vector of dimension 5 x 1

There is more than one technique to solve this problem. The following we are presenting is the so-called **Kannan's Embedding technique** which works fine in our case because the `error_bound` is small. 

The idea is to define a lattice $L'$ which contains the short vector `e`. 
We know that $A\times s \approx b$ because `e` is very short. Our objective is to find a vector `b'` in the lattice closed to `b`. We can proceed in two ways: 
- finding `e`, then subtracting `e` from `b`
- directly finding `b'`

By using the embedding techinque we are going to find the error vector `e`. Call the error bound `M`.
Let's create the matrix $L$ in this way:

$$
\begin{bmatrix}
A^T & 0\\
pI_{50} & 0\\
b & M
\end{bmatrix}
$$

The given matrix has got dimension 56 x 51 and represents the basis for the lattice `L'`.

Apply the `LLL` algorithm to the basis matrix and obtain the reduced basis for the lattice `L'`. 
The sixth row (without the last element) is the vector `e` we were searching before. Of course, it has dimension 50 x 1.

Given `e`, we can compute `b'` by simply subtracting `e` from `b`.

The difficult part is done. Now we have got the linear equation `As = b'` which is easily solvable.

If you want to learn something else, you can read this document: [link](https://www.math.auckland.ac.nz/~sgal018/crypto-book/ch18.pdf)

### The flag
Once found the vector `s`, convert each value in the vector to bytes and concatenate the found strings to obtain the flag.

`snakeCTF{Learning_with_errors_is_a_mathematical_problem_that_is_widely_used_in_cryptography_to_create_secure_encryption_algorithms_It_is_based_on_the_idea_of_representing_secret_information_as_a_set_of_equations_with_errors}`

### Code

```python
from data import *
from copy import deepcopy
from Crypto.Util.number import long_to_bytes, bytes_to_long

vector_length = 5
number_of_couples = 50

## FIND e
A_new = deepcopy(A)
b_new = deepcopy(b)


rows = len(A_new)
for i in range(rows):
    temp = []
    for j in range(rows):
        if i == j:
            temp.append(p)
        else:
            temp.append(0)
    A_new[i] = A_new[i] + temp

A_new.append([0 for _ in range(vector_length+number_of_couples)])

M = Matrix(A_new)
M = M.transpose()

b_new.append(Integer(error_bound))
M = M.insert_row(vector_length+number_of_couples, vector(b_new))
M = M.LLL()
errors = M[5][:-1]
E = Matrix(GF(p), errors).transpose()

A_original = Matrix(GF(p), A)
B = Matrix(GF(p), b).transpose()
S = A_original.solve_right(B - E)

# check
found = True
for el in A_original*S-B:
    if el[0] > error_bound and el[0] < (p-error_bound):
        found = False
        break
if found:
    print(S)


flag = b''.join([long_to_bytes(int(el[0])) for el in S])
for el in S:
    print(long_to_bytes(int(el[0])))
print(flag)
```


