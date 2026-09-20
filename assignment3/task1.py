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
IV = bytes.fromhex("1ff32cc75a52b939a8eb6c4fae9592c7")

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
