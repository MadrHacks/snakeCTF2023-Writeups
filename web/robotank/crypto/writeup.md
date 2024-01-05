# snakeCTF 2023
## [crypto] Robotank: reset token

### Analysis
In the `account` page, the service gives us:
- the generator of the group of the elliptic curve
- the public key (a point on the curve) `P = (x,y)`
- a challenge to sign in order to create the right token `challenge`

By analyzing the source code we can discover that:
- the chosen elliptic curve is `ED25519`.
- the given generator `G` is the common generator.
- the service stores a cookie named `secret` which is the encrypted private key.
- the private key is encrypted with a session key, which is unique for each account.
- the encrypted secret in the cookie is the `XOR` between the private key and the session key.

Summarizing:
- `aG = P`
- `secret = a XOR sess`

### Getting the session key
The first thing to do is obtaining the session key. We can notice, from the source code, that the account page uses the supplied cookie to compute the corresponding private key (by decryption). Then, it uses the computed private key to get the corresponding public key by multiplying it with the curve generator.

What happens when the cookie is set to `0`?

`0 = a XOR sess`

`a = 0 XOR sess`

`a = sess`

The private key becomes the session key.

> From this point, we will use a counter `i`. It starts from `0`. 

Now, what happens when we set to `1` only the `i_th` bit of the cookie?

`00000...00010000...000 = a XOR sess`

`a = 00000...00010000...000 XOR sess`

The private key becomes the session key except for one bit which is changed from `0` to `1` or viceversa.

Good! But... what happend to their corresponding public key?

$$PK_{sess} = sess\times G$$

$$PK_{sess'} = (sess \oplus 00000\dots 00010000\dots 000) \times G$$

The last equation can follow two directions:

- If the `i_th` bit of the session key was `0`, it would become `1`, then the last equation could be rewritten as: $$PK_{sess'} = (sess + 2^{i}) \times G = sess\times G + 2^i \times G = PK_{sess} + 2^i\times G$$
- If the `i_th` bit of the session key was `1`, it would become `0`, then the last equation could be rewritten as follow: $$PK_{sess'} = (sess - 2^{i}) \times G = sess\times G - 2^i \times G = PK_{sess} - 2^i\times G$$

**Algorithm**:
1) Save the public key corresponding to the session key (obtained by setting the cookie to `0`). We call it `REF_public_key`.
2) For `i` in `0..256` we can compute the public key obtained by setting the `i_th` bit of the cookie to `1` and the others to `0`. We call it `analyzed_public_key`. 
    - If `analyzed_public_key == REF_public_key + 2^i` then the `i_th` bit of the session key was `0`
    - `1` otherwise


By doing so, we can obtain the corresponding `session key`. 

### Getting the private key

If we saved the original encrypted private key (the original cookie), we can obtain the private key by computing the `XOR` between the saved cookie and the session key we got in the previous step.

### Signing the challenge

By having the private key, we can easily sign the given `challenge` to obtain the token and reset the account.

**Important**: if you are doing that in **python**, please use the following package to sign the challenge:
```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
```

### Code

Instead of using a common `ED25519` library, you can use the following simple implementation (Credits to **RedRocket**):
```python
import hashlib


def input_to_element(func):
    def cast_wrapper(self, arg, *args, **kwargs):
        if isinstance(arg, int):
            arg = FieldElement(self.field, arg)
        elif not isinstance(arg, FieldElement):
            raise ValueError("Can't cast type {} to FieldElement.".format(arg))
        elif self.field != arg.field:
            raise ValueError("Elements are in different fields!")
        return func(self, arg)
    return cast_wrapper


class PrimeField:
    def __init__(self, mod):
        self.mod = mod

    def __call__(self, *args, **kwargs):
        return FieldElement(self, args[0])

    def add(self, a, b):
        """
        Add two numbers in the field and return the reduced field element.
        """
        return a + b % self.mod

    def sub(self, a, b):
        """
        Subtract two numbers in the field and return the reduced field element.
        """
        return a - b % self.mod

    def mul(self, a, b):
        """
        Multiply two numbers in the field and return the reduced field element.
        """
        return a * b % self.mod

    def div(self, a, b):
        """
        Divide a by b
        """
        inverse = self.pow(b, -1)
        return a * inverse % self.mod

    def equiv(self, a, b):
        """
        Check if two numbers are equivalent in the field.
        """
        return a % self.mod == b % self.mod

    def pow(self, base, exponent):
        """
        Calculate the exponentiation base**exponent within the field.
        Uses square and multiply.
        """
        if isinstance(exponent, FieldElement):
            exponent = exponent.elem
        if not isinstance(exponent, int):
            raise ValueError("Only integers allowed as exponents.")
        # Work modulo the group order
        exponent %= (self.mod - 1)
        # Implement Square and Multiply?
        return pow(base, exponent, self.mod)

    def reduce(self, a):
        """
        Return the smallest representative of number a within the field.
        """
        return a % self.mod

    def __str__(self):
        return f"F_{self.mod}"

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        if not isinstance(other, PrimeField):
            return False
        return self.mod == other.mod


class FieldElement:
    def __init__(self, field, elem):
        if isinstance(elem, FieldElement):
            elem = elem.elem
        self.field = field
        self.elem = self.field.reduce(elem)

    @input_to_element
    def __add__(self, other):
        return FieldElement(
            self.field,
            self.field.add(self.elem, other.elem)
        )

    def __radd__(self, other):
        return self.__add__(other)

    @input_to_element
    def __sub__(self, other):
        return FieldElement(
            self.field,
            self.field.sub(self.elem, other.elem)
        )

    @input_to_element
    def __rsub__(self, other):
        return FieldElement(
            self.field,
            self.field.sub(other.elem, self.elem)
        )

    def __mul__(self, other):
        if isinstance(other, int):
            other = FieldElement(self.field, other)
        elif not isinstance(other, FieldElement):
            # Maybe the "other" has a working __rmul__ implementation
            return other.__rmul__(self.elem)

        return FieldElement(
            self.field,
            self.field.mul(self.elem, other.elem)
        )

    @input_to_element
    def __truediv__(self, other):
        return FieldElement(
            self.field,
            self.field.div(self.elem, other.elem)
        )

    def __rmul__(self, other):
        return self.__mul__(other)

    def __eq__(self, other):
        if isinstance(other, int):
            other = self.field(other)
        elif not isinstance(other, FieldElement):
            return False
        return self.field == other.field and self.field.equiv(self.elem, other.elem)

    def __pow__(self, power, modulo=None):
        return FieldElement(
            self.field,
            self.field.pow(self.elem, power)
        )

    def to_bytes(self, lenght, byteorder):
        return self.elem.to_bytes(lenght, byteorder)

    def __str__(self):
        return f"{self.elem}"

    def __repr__(self):
        return self.__str__()

class AffinePoint:

    def __init__(self, curve, x, y, order=None):
        self.curve = curve
        if isinstance(x, int) and isinstance(y, int):
            self.x = curve.field(x)
            self.y = curve.field(y)
        else:  # for POIF and field elements
            self.x = x
            self.y = y
        self.order = order

    def __add__(self, other):
        return self.curve.add(self, other)

    def __iadd__(self, other):
        return self.__add__(other)

    def __rmul__(self, scalar):
        return self.curve.mul(self, scalar)

    def __str__(self):
        return "Point({},{}) on {}".format(self.x, self.y, self.curve)

    def copy(self):
        return AffinePoint(self.curve, self.x, self.y)

    def __eq__(self, other):
        if not isinstance(other, AffinePoint):
            raise ValueError("Can't compare Point to {}".format(type(other)))
        if hasattr(self.curve, "poif") and self is self.curve.poif:
            if other is self.curve.poif:
                return True
            return False
        return self.curve == other.curve and self.x == other.x and self.y == other.y


class EllipticCurve:

    def invert(self, point):
        """
        Invert a point.
        """
        return AffinePoint(self, point.x, (-1 * point.y))

    def mul(self, point, scalar):
        """
        Do scalar multiplication Q = dP using double and add.
        """
        if isinstance(scalar, FieldElement):
            scalar = scalar.elem
        return self.double_and_add(point, scalar)

    def double_and_add(self, point, scalar):
        """
        Do scalar multiplication Q = dP using double and add.
        As here: https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add
        """
        if scalar < 1:
            raise ValueError("Scalar must be >= 1")
        result = None
        tmp = point.copy()

        while scalar:
            if scalar & 1:
                if result is None:
                    result = tmp
                else:
                    result = self.add(result, tmp)
            scalar >>= 1
            tmp = self.add(tmp, tmp)

        return result

class EdwardsCurve(EllipticCurve):

    def __init__(self, d, field, a=1):
        """
        General Edwards Curve.
        If a!=1, the curve is twisted.
        """
        self.field = field
        self.d = field(d)
        self.a = field(a)
        # By definition, so we can do the addition as below
        self.neutral_element = AffinePoint(self, 0, 1)

    def is_on_curve(self, P):
        x_sq = P.x**2
        y_sq = P.y**2
        return (self.a * x_sq + y_sq) == (1 + self.d * x_sq * y_sq)

    def add(self, P, Q):
        """
        Sum of points P and Q.
        https://en.wikipedia.org/wiki/Edwards_curve#The_group_law
        """
        if not (self.is_on_curve(P) and self.is_on_curve(Q)):
            raise ValueError("Points not on curve")
        den_x = 1 + (self.d * P.x * P.y * Q.x * Q.y)
        den_y = 1 - (self.d * P.x * P.y * Q.x * Q.y)

        nom_x = P.x * Q.y + Q.x * P.y
        nom_y = P.y * Q.y - self.a * Q.x * P.x

        return AffinePoint(
                self,
                nom_x * den_x**-1,
                nom_y * den_y**-1
        )

    def __str__(self):
        return "{}x^2 + y^2 = 1 + {}x^2y^2 mod {}".format(self.a, self.d, self.field.mod)


FIELD = PrimeField(2 ** 255 - 19)
CURVE = EdwardsCurve(37095705934669439343138083508754565189542113879843219016388785533085940283555, FIELD, -1)
B = AffinePoint(CURVE, 
            15112221349535400772501151409588531511454012693041857206046113283949847762202, 
            46316835694926478169428394003475163141307993866256225615783033603165251855960, 
            2 ** 252 + 27742317777372353535851937790883648493)
b = 256
n = 254


def calculate_secret_scalar(sk):
    h = bytearray(hashlib.sha512(sk).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return int.from_bytes(h, 'little')


def encode_point(P):
    y = P.y.elem
    x = P.x.elem

    if x & 1:
        y |= 1 << (32 * 8 - 1)
    else:
        y &= ~(1 << (32 * 8 - 1))

    return y.to_bytes(32, 'little')


def decode_point(P):
    y = FIELD(int.from_bytes(P, 'little') & ~(1 << (32 * 8 - 1)))

    u = y ** 2 - 1
    v = CURVE.d * y ** 2 + 1

    x = (u * v ** -1) ** ((FIELD.mod+3) * FIELD(8) ** -1)

    if v * x ** 2 == u * -1:
        x = x * FIELD(2) ** ((FIELD.mod-1) * FIELD(4) ** -1).elem
    elif v * x ** 2 != u:
        raise ValueError("Point can't be decoded")

    x_0 = (int.from_bytes(P, 'little') & 1 << (32 * 8 - 1)) >> (32 * 8 - 1)
    if x == 0 and x_0 == 1:
        raise ValueError("Point can't be decoded")
    if x_0 != x.elem % 2:
        x = x * -1

    return AffinePoint(CURVE, x, y)


def hash_digest(input_bytes):
    return hashlib.sha512(input_bytes).digest()


def bytes_to_int(input_bytes):
    return int.from_bytes(input_bytes, "little")


def int_from_hash(input_bytes):
    return bytes_to_int(
        hash_digest(input_bytes)
    )


class ED25519PublicKey:

    def __init__(self, pk_bytes):
        self.pk_bytes = pk_bytes
        self.pk = decode_point(pk_bytes)

    def verify(self, message, signature):
        R = decode_point(signature[:32])
        S = bytes_to_int(signature[32:])

        k = int_from_hash(signature[:32] + self.pk_bytes + message)
        return S * B == R + k * self.pk


class ED25519PrivateKey:

    def __init__(self, sk):
        if not (isinstance(sk, bytes) and len(sk) == 32):
            raise ValueError("Only 32B byte strings allowed as secret key.")
        self.sk_raw = sk
        self.sk = calculate_secret_scalar(sk)
    
    def public_key(self):
        pk_encoded = encode_point(self.sk * B)
        public_key = ED25519PublicKey(pk_encoded)
        return public_key

    def sign(self, message):
        prefix = hash_digest(self.sk_raw)[32:]

        r = int_from_hash(prefix + message)
        r = 1
        R = encode_point(r * B)
        k = int_from_hash(R + self.public_key().pk_bytes + message)
        S = (r + (k % B.order) * self.sk) % B.order
        return R + S.to_bytes(32, 'little')

    def serialize(self):
        return self.sk.to_bytes(32, "big")
    
    def unserialze(from_bytes):
        privkey = ED25519PrivateKey(b"mock" * 8)
        privkey.sk = int.from_bytes(from_bytes)
        return privkey
```

```python
from signature import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
import random
from bs4 import BeautifulSoup
import requests
from pwn import *
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SCHEMA = args.SCHEMA if args.SCHEMA else "https"
VERIFY_CERTIFICATE = args.VERIFY == "True" if args.VERIFY else True
HOST = args.HOST if args.HOST else "localhost"
PORT = args.PORT if args.PORT else 3000
BASE_URL = f"{SCHEMA}://{HOST}:{PORT}"
USER = args.USER if args.USER else "admin"
PASSWORD = args.PASSWORD if args.PASSWORD else "REDACTED"


LINK_REGISTER = "/auth/register"
LINK_LOGIN = "/auth/login"
LINK_ACCOUNT = ""

payload = {"username": USER, "password": PASSWORD}
headers  = {"sec-ch-ua": "\"Chromium\";v=\"119\", \"Not?A_Brand\";v=\"24\"", "Accept": "*/*", "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest", "sec-ch-ua-mobile": "?0", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.105 Safari/537.36", "sec-ch-ua-platform": "\"Linux\"", "Origin": "http://localhost:3000", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "http://localhost:3000/account/2", "Accept-Encoding": "gzip, deflate, br", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}


def get_public_key_from_cookie(s, cookie):
    s.cookies.pop('secret', None)
    s.cookies["secret"]= cookie
    
    r = s.get(f"{BASE_URL}{LINK_ACCOUNT}", verify=VERIFY_CERTIFICATE)
    soup = BeautifulSoup(r.text, "html.parser")
    try:
        container = soup.findAll("div", {"class": "card-body"})[1].findAll("p")
    except:
        print(r.text)
        exit(1)
    public_key = [int(c) for c in container[0].text[11:].split(",")]
    return public_key


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


s = requests.Session()
r = s.get(f"{BASE_URL}", verify=VERIFY_CERTIFICATE)

r = s.post(f"{BASE_URL}{LINK_LOGIN}", json=payload, headers=headers, verify=VERIFY_CERTIFICATE)
res = s.get(f"{BASE_URL}", verify = VERIFY_CERTIFICATE)
soup = BeautifulSoup(res.text, "html.parser")
LINK_ACCOUNT = soup.findAll("a", {"class": "nav-link"})[0]["href"]
r = s.get(f"{BASE_URL}{LINK_ACCOUNT}", verify = VERIFY_CERTIFICATE)

# getting original data
soup = BeautifulSoup(r.text, "html.parser")
container = soup.findAll("div", {"class": "card-body"})[1].findAll("p")
public_key = [int(c) for c in container[0].text[11:].split(",")]
generator = int(container[1].text[14:])
challenge = int(container[2].text[20:])

encrypted_secret_key = bytes.fromhex(s.cookies["secret"])

print(f'Challenge: {challenge}')


G = AffinePoint(CURVE, 
            15112221349535400772501151409588531511454012693041857206046113283949847762202, 
            46316835694926478169428394003475163141307993866256225615783033603165251855960)

PK = AffinePoint(CURVE, 
            public_key[0], 
            public_key[1])


aes_ctr_key = []

# riferimento PKZeros
public_key_zeros = get_public_key_from_cookie(s, "0"*64)
PK0 = AffinePoint(CURVE, 
            public_key_zeros[0], 
            public_key_zeros[1]
            )

# procedure to find the key
for i in range(1, 257):
    cookie = hex(int("0"*(256-i)+"1"+"0"*(i-1),2))[2:].zfill(64)
    public_key_temp = get_public_key_from_cookie(s, cookie)
    PK_temp = AffinePoint(CURVE, 
            public_key_temp[0], 
            public_key_temp[1]
            )
    if PK_temp == PK0 + (1<<(i-1))*G:
        aes_ctr_key.append(0)
    else:
        aes_ctr_key.append(1)
    time.sleep(0.05)


key = ("".join([str(x) for x in aes_ctr_key[::-1]]))
decrypted_private_key = byte_xor(bytes.fromhex(hex(int(key, 2))[2:].zfill(64)),bytes.fromhex(encrypted_secret_key.hex()))
priv_key = bytes_to_long(decrypted_private_key)

print(f"The session key: {hex(int(key, 2))[2:].zfill(64)}")
assert priv_key*G == PK
hex_private_key = hex(priv_key)[2:].zfill(64)
print(f'Private key: {hex(priv_key)[2:].zfill(64)}')


from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_private_key))
token = private.sign(long_to_bytes(challenge)).hex()
res = s.post(f"{BASE_URL}{LINK_ACCOUNT}/token", json={"token":token}, headers=headers, verify=VERIFY_CERTIFICATE)
print(res.text)
```


