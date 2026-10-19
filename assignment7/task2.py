import argparse
import hashlib
from io import BytesIO
from pathlib import Path

import numpy as np
from PIL import Image


MAGIC = b"STEG"
HEADER_SIZE = 9
HEADER_BITS = HEADER_SIZE * 8


def seed_from_password(password: str) -> int:
    """Turn a password into the seed used to shuffle image channels."""
    password_hash = hashlib.sha256(password.encode("utf-8")).digest()
    return int.from_bytes(password_hash[:8], "big")


def bits_to_bytes(bits) -> bytes:
    """Convert most-significant-bit-first values into bytes."""
    bits = list(bits)

    # Pad the final byte if the number of bits is not a multiple of eight.
    while len(bits) % 8 != 0:
        bits.append(0)

    output = bytearray()
    for start in range(0, len(bits), 8):
        value = 0
        for bit in bits[start:start + 8]:
            value = (value << 1) | int(bit)
        output.append(value)

    return bytes(output)


def extract(stego_path, password: str):
    """Return ("text", str), ("image", bytes), or (None, None)."""
    with Image.open(stego_path) as image:
        image_array = np.array(image.convert("RGB"))

    height, width, channels = image_array.shape
    total_channels = height * width * channels

    # A valid payload must contain at least the complete 9-byte header.
    if total_channels < HEADER_BITS:
        return None, None

    rng = np.random.default_rng(seed_from_password(password))
    permutation = rng.permutation(total_channels)

    bits = []
    payload_type = None
    payload_length = None
    total_bits_needed = None

    for i in range(total_channels):
        channel_position = permutation[i]
        pixel = channel_position // 3
        channel = channel_position % 3
        y = pixel // width
        x = pixel % width

        bits.append(int(image_array[y, x, channel]) & 1)

        if len(bits) == HEADER_BITS:
            header = bits_to_bytes(bits)

            # A failed magic or type check means the password is wrong or the
            # image does not contain a payload made by the matching embedder.
            if header[:4] != MAGIC or header[4] not in (0, 1):
                return None, None

            payload_type = "text" if header[4] == 0 else "image"
            payload_length = int.from_bytes(header[5:9], "big")
            total_bits_needed = (HEADER_SIZE + payload_length) * 8

            # Reject a damaged header instead of reading beyond the image.
            if total_bits_needed > total_channels:
                return None, None

        if total_bits_needed is not None and len(bits) >= total_bits_needed:
            break

    if payload_length is None:
        return None, None

    payload_end = HEADER_BITS + payload_length * 8
    payload_bytes = bits_to_bytes(bits[HEADER_BITS:payload_end])

    if payload_type == "text":
        return "text", payload_bytes.decode("utf-8")

    with Image.open(BytesIO(payload_bytes)) as recovered_image:
        if recovered_image.format != "PNG":
            return None, None
        recovered_image.verify()

    return "image", payload_bytes


def main():
    parser = argparse.ArgumentParser(
        description="Extract a password-shuffled LSB payload from a stego PNG."
    )
    parser.add_argument("stego_path", help="stego PNG to read")
    parser.add_argument(
        "-p", "--password", default="secret", help="password (default: secret)"
    )
    args = parser.parse_args()

    payload_type, payload = extract(args.stego_path, args.password)

    if payload_type is None:
        print("No payload found (wrong password or invalid stego image).")
    elif payload_type == "text":
        print("Recovered text:", payload)
    else:
        stego_path = Path(args.stego_path)
        output_path = stego_path.with_name(stego_path.stem + "_recovered.png")
        output_path.write_bytes(payload)
        print("Recovered image saved to:", output_path)


if __name__ == "__main__":
    main()
