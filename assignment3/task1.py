from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import secrets

def computeX(q: int) -> int:
    X = secrets.randbelow(q - 1) + 1
    return X

def computeY(X: int, q: int, alpha: int) -> int:
    Y = pow(alpha, X, q)
    return Y

def computeS(otherY: int, X: int, q: int) -> int:
    s = pow(otherY, X, q)
    return s

def computeKey(s: int) -> bytes:
    secret_bytes = s.to_bytes(max(1, (s.bit_length() + 7) // 8), "big")
    return SHA256.new(data=secret_bytes).digest()[:16]

def encrpytMessage(key: bytes, m: str) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=IV)
    ciphertext = cipher.encrypt(pad(m.encode("utf-8"), AES.block_size))

    return ciphertext

def decryptMessage(key: bytes, ciphertext: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv=IV)
    padded_message = cipher.decrypt(ciphertext)
    return unpad(padded_message, AES.block_size).decode("utf-8")

IV = bytes.fromhex("1ff32cc75a52b939a8eb6c4fae9592c7")

#Task 1 small group
print("Task 1 small group with q = 37 and alpha = 5")
q = 37
alpha = 5

X_alice = computeX(q)
Y_alice = computeY(X_alice, q, alpha)
print(f"Alice selected X = {X_alice}, Y = {Y_alice}")

X_bob = computeX(q)
Y_bob = computeY(X_bob, q, alpha)
print(f"Bob selected X = {X_bob}, Y = {Y_bob}")

print("Alice and Bob traded public keys")
s_alice = computeS(Y_bob, X_alice, q)
print("Alice computed S =", s_alice)
s_bob = computeS(Y_alice, X_bob, q)
print("Bob computed S =", s_bob)

key_alice = computeKey(s_alice)
print(f"Alice computed key = {key_alice.hex()}")
key_bob = computeKey(s_bob)
print(f"Bob computed key = {key_bob.hex()}")

if (key_alice == key_bob):
    print("They have the same key!")
else:
    print("They failed to create a shared key!")

m_alice = "Hi Bob!"
enc_alice = encrpytMessage(key_alice, m_alice)
print(f"Alice wrote \"{m_alice}\", encrypted to {enc_alice.hex()}")
dec_bob = decryptMessage(key_bob, enc_alice)
print(f"Bob recieved \"{dec_bob}\"")

m_bob = "Hi Alice!"
enc_bob = encrpytMessage(key_bob, m_bob)
print(f"Bob wrote \"{m_bob}\", encrypted to {enc_bob.hex()}")
dec_alice = decryptMessage(key_alice, enc_bob)
print(f"Alice recieved \"{dec_alice}\"")

#Task 1 large group
print("\nTask 1 large group")
q = int(
    "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
    "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
    "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
    "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
    "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
    "DF1FB2BC2E4A4371",
    16,
)
alpha = int(
    "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
    "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
    "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
    "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
    "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
    "855E6EEB22B3B2E5",
    16,
)

X_alice = computeX(q)
Y_alice = computeY(X_alice, q, alpha)
print(f"Alice selected X = ...{X_alice & 0xFFFFFFFF}, Y = ...{Y_alice & 0xFFFFFFFF}")

X_bob = computeX(q)
Y_bob = computeY(X_bob, q, alpha)
print(f"Bob selected X = ...{X_bob & 0xFFFFFFFF}, Y = ...{Y_bob & 0xFFFFFFFF}")

print("Alice and Bob traded public keys")
s_alice = computeS(Y_bob, X_alice, q)
print(f"Alice computed S = ...{s_alice & 0xFFFFFFFF}")
s_bob = computeS(Y_alice, X_bob, q)
print(f"Bob computed S = ...{s_bob & 0xFFFFFFFF}")

key_alice = computeKey(s_alice)
print(f"Alice computed key = {key_alice.hex()}")
key_bob = computeKey(s_bob)
print(f"Bob computed key = {key_bob.hex()}")

if (key_alice == key_bob):
    print("They have the same key!")
else:
    print("They failed to create a shared key!")

m_alice = "Hi Bob!"
enc_alice = encrpytMessage(key_alice, m_alice)
print(f"Alice wrote \"{m_alice}\", encrypted to {enc_alice.hex()}")
dec_bob = decryptMessage(key_bob, enc_alice)
print(f"Bob recieved \"{dec_bob}\"")

m_bob = "Hi Alice!"
enc_bob = encrpytMessage(key_bob, m_bob)
print(f"Bob wrote \"{m_bob}\", encrypted to {enc_bob.hex()}")
dec_alice = decryptMessage(key_alice, enc_bob)
print(f"Alice recieved \"{dec_alice}\"")
#
#task 2
#This use the task 1 fucntion to send and read both messages
#the fixes IV above is keep for this lab example only

def read_messages(s_alice, s_bob, s_mallory):
    #This make a key from each persons secret
    key_alice = computeKey(s_alice)
    key_bob = computeKey(s_bob)
    key_mallory = computeKey(s_mallory)

    print("Alice secret =", s_alice)
    print("Bob secret =", s_bob)
    print("Mallory predicted secret =", s_mallory)

    if key_alice == key_bob and key_alice == key_mallory:
        print("They all have the same key")
    else:
        print("Warning: the keys are different")

    #This encrypt both message
    m_alice = "Hi Bob!"
    m_bob = "Hi Alice!"
    enc_alice = encrpytMessage(key_alice, m_alice)
    enc_bob = encrpytMessage(key_bob, m_bob)

    print("Alice ciphertext =", enc_alice.hex())
    print("Bob ciphertext =", enc_bob.hex())

    #This let Alice and Bob read what they recieved
    dec_bob = decryptMessage(key_bob, enc_alice)
    dec_alice = decryptMessage(key_alice, enc_bob)
    print("Bob recieved:", dec_bob)
    print("Alice recieved:", dec_alice)

    #This let Mallory read both messages with her own key
    mallory_alice = decryptMessage(key_mallory, enc_alice)
    mallory_bob = decryptMessage(key_mallory, enc_bob)
    print("Mallory recieved from Alice:", mallory_alice)
    print("Mallory recieved from Bob:", mallory_bob)

    if dec_bob != m_alice or dec_alice != m_bob:
        print("Warning: Alice or Bob got the wrong message")
    if mallory_alice != m_alice or mallory_bob != m_bob:
        print("Warning: Mallory got the wrong message")
    
#Task 2 part 1
#This keep the private numbers
#Mallory change the public value each person recieved to q
Y_to_alice = q
Y_to_bob = q
s_alice = computeS(Y_to_alice, X_alice, q)
s_bob = computeS(Y_to_bob, X_bob, q)

#q to any positive power leave remainder 0 when divide by q
# This let Mallory know the secret without the private numbers
s_mallory = 0
read_messages(s_alice, s_bob, s_mallory)

#Task 2 part 2
# this change alpha before alice and bob make the public values

def change_alpha(q, new_alpha, X_alice, X_bob):
    print("\nTask 2 part 2")
    if new_alpha == 1:
        print("Mallory changed alpha to 1")
    elif new_alpha == q:
        print("Mallory changed alpha to q")
    else:
        print("Mallory changed alpha to q - 1")

    #This make new public values with the changed alpha
    Y_alice = computeY(X_alice, q, new_alpha)
    Y_bob = computeY(X_bob, q, new_alpha)
    s_alice = computeS(Y_bob, X_alice, q)
    s_bob = computeS(Y_alice, X_bob, q)

    #This find Mallory secret using only the public information
    if new_alpha == 1:
        s_mallory=1
    elif new_alpha == q:
        s_mallory=0
    else:
        #q-1 act like -1, so two odd powers give q-1
        #This check the public values instead of readding private numbers
        if Y_alice == q-1 and Y_bob == q-1:
            s_mallory = q-1
        else:
            s_mallory = 1

    read_messages(s_alice, s_bob, s_mallory)


# this try all three alpha values with the new random private numbers
for new_alpha in [1, q, q-1]:
    X_alice = computeX(q)
    X_bob = computeX(q)
    change_alpha(q, new_alpha, X_alice, X_bob)

#This use small private numbers just to show both q-1 outcomes
print("\nExtra q-1 check: both private numbers are odd")
change_alpha(q, q-1, 3, 5)

print("\nExtra q-1 check: one private number is even")
change_alpha(q, q-1, 4, 5)

#
#Task 3
#
#
#
from Crypto.Util.number import getPrime

def find_gcd(a, b):
    while b != 0:
        remainder = a % b
        a = b
        b = remainder

    return a


def find_inverse(e, phi):
    old_remainder = phi
    remainder = e
    old_number = 0
    number = 1

    while remainder != 0:
        divide = old_remainder // remainder
        next_remainder = old_remainder - divide * remainder
        old_remainder = remainder
        remainder = next_remainder

        next_number = old_number - divide * number
        old_number = number
        number = next_number

    d = old_number % phi
    return d

#This make the public and private numbers for RSA

def make_rsakey(prime_size):
    e = 65537
    p = getPrime(prime_size)
    rsa_q = getPrime(prime_size)
    phi = (p-1) * (rsa_q-1)

    #This gett he new primes so they match or e has no inverse
    while p == rsa_q or find_gcd(e, phi) != 1:
        p = getPrime(prime_size)
        rsa_q = getPrime(prime_size)
        phi = (p-1) * (rsa_q-1)
    n = p * rsa_q
    d = find_inverse(e, phi)
    return n, e, d


#Task 3 part 1
print("\nTask 3 part 1: make RSA keys")

#This is the size of each prime, change to 2048 for the large test
prime_size = 512
n, e, d = make_rsakey(prime_size)
print("Bits in each prime =", prime_size)
print("Bits in n =", n.bit_length())
print("Public e =", e)

for message in ["Hi Bob!", "Hi Alice!", "Hello!"]:
    #turn the text into bytes then a normal number
    message_bytes = message.encode("utf-8")
    message_number = int.from_bytes(message_bytes, "big")


    if message_number >= n:
        print("Warning: the message number must be smaller than n")

    #This encrypt with the public e and decrypt with the private d
    ciphertext = pow(message_number, e, n)
    decrypted_number = pow(ciphertext, d, n)

    message_length = len(message_bytes)
    decrypted_bytes = decrypted_number.to_bytes(message_length, "big")
    decrypted_message = decrypted_bytes.decode("utf-8")

    print("\nOriginal message:", message)
    print("RSA ciphertext =", ciphertext)
    print("Decrypted message:", decrypted_message)

    if decrypted_message != message:
        print("Warning: RSA got the wrong message")


#Task 3 part 2
print("\nTask 3 part 2: RSA key exchange")

#pick Bob secret so it is smaller than n and relatively prime to n
s_bob = secrets.randbelow(n-1)+1
while find_gcd(s_bob, n) != 1:
    s_bob = secrets.randbelow(n-1)+1

c = pow(s_bob, e, n)

#first check the exchange before Mallory changes anything
normal_secret = pow(c, d, n)
key_bob = computeKey(s_bob)
normal_key = computeKey(normal_secret)
if normal_secret != s_bob or normal_key != key_bob:
    print("Warning: the normal RSA exchange failed")

normal_ciphertext = encrpytMessage(normal_key, "Hi Bob!")
normal_message = decryptMessage(key_bob, normal_ciphertext)
print("Before the attack Bob recieved:", normal_message)
if normal_message != "Hi Bob!":
    print("Warning: Bob got the wrong message before the attack")

normal_reply = encrpytMessage(key_bob, "Hi Alice!")
normal_message = decryptMessage(normal_key, normal_reply)
print("Before the attack Alice recieved:", normal_message)
if normal_message != "Hi Alice!":
    print("Warning: Alice got the wrong reply before the attack")

#This replace c with 1 before Alice received it
#1 to any positive power is 1 so Mallory already know the secret
changed_c = 1
s_alice = pow(changed_c, d, n)
s_mallory = 1
key_alice = computeKey(s_alice)
key_mallory = computeKey(s_mallory)

print("\nBob original ciphertext =", c)
print("Mallory replacement ciphertext =", changed_c)
print("Alice secret after the change =", s_alice)
print("Mallory predicted secret =", s_mallory)

if s_alice != s_mallory or key_alice != key_mallory:
    print("Warning: Mallory predicted the wrong secret")

#This encrypt Alice message using the changed secret
enc_alice = encrpytMessage(key_alice, "Hi Bob!")
mallory_message = decryptMessage(key_mallory, enc_alice)
print("Alice AES ciphertext =", enc_alice.hex())
print("Mallory recieved:", mallory_message)
if mallory_message != "Hi Bob!":
    print("Warning: Mallory got the wrong RSA exchange message")

#Bob still has his original secret, this attack only fix Alice secret
#The  rare case where Bob already picked 1 also gives the same key
if key_alice == key_bob:
    print("Bob key also matches Alice key in this run")
else:
    print("Bob still has a different key from Alice")


#Another malleability example
print("\nAnother RSA malleability example")

#This is a made up system that trust a raw RSA encrypted amount
#The amount is small so doubling it stays below n 
amount = 50
amount_ciphertext = pow(amount, e, n)

#This multiply the ciphertext so the decrypted amount gets doubled
changed_amount_ciphertext = (amount_ciphertext*pow(2, e, n))%n
changed_amount = pow(changed_amount_ciphertext, d, n)

print("Original amount =", amount)
print("Amount after Mallory change =", changed_amount)
if changed_amount != 100:
    print("Warning: the changed amount is wrong")


#RSA signature question
print("\nRSA signature multiplication")

#This make two original signatures using Alice private d
m1 = 2
m2 = 3
signature1 = pow(m1 , d , n)
signature2 = pow(m2 , d , n)

#Mallory only use the signatures she saw and the public n
#Multiplying them gives a signature for m1*m2
m3 = m1*m2
signature3 = (signature1*signature2)%n

#This check the new signature with the public e
checked_message = pow(signature3, e, n)
print("Third message =", m3)
print("Forged signature =", signature3)
print("Signature gives back =", checked_message)
if checked_message == m3:
    print("The new signature is valid")
else:
    print("Warning: the signature is wrong")

print("\nAll the added task 1, task 2 and task 3 checks passed")
