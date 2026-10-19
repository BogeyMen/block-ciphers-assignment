import hashlib
from io import BytesIO
from pathlib import Path

import numpy as np
from PIL import Image


#The functions below follow the order they get called for the first time
def main():
    #This use the folder of this file so running from another folder still work
    assignment_folder = Path(__file__).resolve().parent
    cover_path = assignment_folder / "inputs" / "apple_logo_cover.png"
    secret_image_path = assignment_folder / "inputs" / "laptop_secret.png"
    password = "secret"

    #This turn the message into bytes before we hide it
    message = "This is a secret"
    text_bytes = message.encode("utf-8")
    embed(
        cover_path,
        assignment_folder / "stego_text.png",
        "text",
        text_bytes,
        password,
    )

    #This turn the laptop into PNG bytes and use a fresh copy of the cover
    image_bytes = image_to_png_bytes(secret_image_path)
    embed(
        cover_path,
        assignment_folder / "stego_laptop.png",
        "image",
        image_bytes,
        password,
    )


def embed(cover_path, out_path, payload_type, payload_bytes, password):
    #This open the cover with red, green and blue values for each pixel
    with Image.open(cover_path) as cover_image:
        cover_array = np.array(cover_image.convert("RGB"))

    height, width, channels = cover_array.shape
    total_channels = height * width * channels

    #This add the label and size so task 2 know what it is readding
    framed_bytes = frame_payload(payload_type, payload_bytes)
    payload_bits = bytes_to_bits(framed_bytes)
    bits_needed = len(payload_bits)

    #This check the whole size including the header before changing any pixels
    if bits_needed > total_channels:
        raise ValueError(
            f"Payload too large for this cover: need {bits_needed} bits, "
            f"but only {total_channels} bits are available."
        )

    #This use the password to make the same shuffled order every time
    seed = seed_from_password(password)
    random_generator = np.random.default_rng(seed)
    channel_order = random_generator.permutation(total_channels)

    #This make a changeable copy and keep the original cover alone
    output_array = cover_array.copy()

    #This go through one secret bit at a time in the shuffled order
    for bit_number in range(bits_needed):
        channel_position = int(channel_order[bit_number])

        #Each pixel have 3 channels so this find the pixel and its color channel
        pixel_number = channel_position // 3
        channel_number = channel_position % 3
        row = pixel_number // width
        column = pixel_number % width

        #This clear the last bit then put our secret bit in its place
        original_value = int(output_array[row, column, channel_number])
        secret_bit = payload_bits[bit_number]
        new_value = (original_value & 0xFE) | secret_bit
        output_array[row, column, channel_number] = new_value

    #This save as PNG so the small changes stay exactly how we wrote them
    Image.fromarray(output_array).save(out_path, format="PNG")

    #This show how much space the header and the secret used together
    percent_used = bits_needed / total_channels * 100
    print(f"Created: {Path(out_path).name}")
    print(f"Payload: {payload_type}, {len(payload_bytes)} bytes")
    print(f"Header: {len(framed_bytes) - len(payload_bytes)} bytes")
    print(f"Cover: {width} x {height} RGB, {total_channels} usable bits")
    print(f"Space used: {bits_needed} bits ({percent_used:.3f}%)")
    print()


def frame_payload(payload_type, payload_bytes):
    #This mark the start so the extractor can check it found our data
    magic = b"STEG"

    #This tell task 2 if the hidden bytes should be text or an image
    if payload_type == "text":
        type_byte = b"\x00"
    elif payload_type == "image":
        type_byte = b"\x01"
    else:
        raise ValueError("Payload type must be 'text' or 'image'.")

    #This save the secret size in 4 bytes with the biggest place value first
    payload_length = len(payload_bytes).to_bytes(4, byteorder="big")

    #This put the 9 byte header before the actual secret
    return magic + type_byte + payload_length + payload_bytes


def bytes_to_bits(data):
    bits = []

    #This take each byte and read its bits from left to right
    for byte_value in data:
        for bit_position in range(7, -1, -1):
            bit = (byte_value >> bit_position) & 1
            bits.append(bit)

    return bits


def seed_from_password(password):
    #This turn the password into bytes and hash it with SHA256
    password_bytes = password.encode("utf-8")
    password_hash = hashlib.sha256(password_bytes).digest()

    #This use the first 8 bytes as a number to start the shuffle
    seed = int.from_bytes(password_hash[:8], byteorder="big")
    return seed


def image_to_png_bytes(image_path):
    #This make a place in memory to hold the PNG like a temporary file
    png_buffer = BytesIO()

    #This keep the laptop colors and transparency when making its PNG bytes
    with Image.open(image_path) as secret_image:
        secret_image.convert("RGBA").save(png_buffer, format="PNG")

    return png_buffer.getvalue()


#Python read the definitions above first, then this actually start main
if __name__ == "__main__":
    main()
