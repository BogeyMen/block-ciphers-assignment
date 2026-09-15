import argparse

from Crypto.Random import get_random_bytes
from urllib.parse import quote
import task1

prefix = "userid=456; userdata="
suffix = ";session-id=31337"

def submit(info: str, key, iv):
    url_parsed = quote(info, safe="=")
    before_encode = prefix + url_parsed + suffix

    encrypted_data, _, _ = task1.encrypt_data(before_encode, "CBC", key, iv)
    return encrypted_data


def verify(secret: bytes, key, iv):
    try:
        decrypted_data = task1.decrypt_data(secret, "CBC", key, iv)
    except (TypeError, ValueError):
        return False
    return b";admin=true;" in decrypted_data


def cbcInject(secret: bytes):
    modified_data = bytearray(secret)

    # Change the = before the user input into a ; in block 1.
    modified_data[4] ^= ord("=") ^ ord(";")

    return bytes(modified_data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--admin", action="store_true")
    args = parser.parse_args()

    key = get_random_bytes(16)
    iv = get_random_bytes(16)

    user_input = input("Enter User ID:\n")

    encrypted_data = submit(user_input, key, iv)
    if args.admin:
        encrypted_data = cbcInject(encrypted_data)

    print(verify(encrypted_data, key, iv))


if __name__ == "__main__":
    main()
