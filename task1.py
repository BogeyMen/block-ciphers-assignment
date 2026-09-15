from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def read_bmp_header(filename: str):
    #This open file for read in binary
    image_file = open(filename, "rb")

    #skip first 10 bites and start readding at position 11 in binary
    image_file.seek(10)

    #read position 11 -  14
    size_byte = image_file.read(4)

    #This the 4 bites we grab from the line above into normal number
    #This is basically the position of the image file now
    header_size = int.from_bytes(size_byte, "little")

    #jump back to read only header
    image_file.seek(0)
    header = image_file.read(header_size)

    #read image data
    pixels = image_file.read()
    image_file.close()

    return header, pixels

# iv is initialization vector here
def encrypt_image(filename: str, mode: str, key=None, iv=None):
    #turn the mode into uppercase so cbc -> CBC
    mode = mode.upper()

    #This call the first function to get the header and image data
    header, pixels = read_bmp_header(filename)

    #This call the encode function with the image data
    encrypt_data, key, iv = globals()["encrypt_data"](pixels, mode, key, iv)

    #put the BMP header at the start of the output
    combined_data = bytearray(header)

    #This add the encrypted image data after that
    combined_data.extend(encrypt_data)

    #This remove the file extension from the name
    file_start = os.path.splitext(filename)[0]
    output_filename= file_start + "_" + mode.lower() + ".bmp"

    #This open the output file for writing in binary
    output_file = open(output_filename, "wb")
    output_file.write(combined_data)
    output_file.close()

    return output_filename, key, iv
    

def decrypt_image(image_filename: str, mode: str, key: bytes, iv=None):
    #turn the mode into uppercase so cbc->CBC
    mode = mode.upper()

    #This get the header and the data after
    header, encrypt_data = read_bmp_header(image_filename)

    if mode == "CBC":
        if iv is None:
            raise ValueError("CBC decryption needs the IV returned by encrypt_image")
        if len(iv) != 16:
            raise ValueError("The CBC IV must be 16 bytes long")

    #check the data can fit into a 16 byte block
    if len(encrypt_data) == 0 or len(encrypt_data) % 16 != 0:
        raise ValueError("The encrypted data is incomplete") 

    #This set up AES with the same key from encryption
    aes_ciper = AES.new(key, AES.MODE_ECB)
    padd_pixel = bytearray()
    previous_block =  iv

    #This go through the encrypted data
    for block_star in range(0, len(encrypt_data), 16):
        encrypted_block = encrypt_data[block_star:block_star + 16]
        block = bytearray(aes_ciper.decrypt(encrypted_block)) 
        if mode == "CBC" and previous_block is not None:
            for position in range(16):
                block[position] = block[position]^previous_block[position]  

        #This add the result and save the encrypted block for next time
        padd_pixel.extend(block )
        previous_block = encrypted_block

    #last byte tell how much padding was added
    padd_size =padd_pixel[-1]
    if padd_size < 1 or padd_size > 16:
        raise ValueError("The padding is wrong")

    #check each padding byte hold the padding size
    for position in range(len(padd_pixel) - padd_size, len(padd_pixel)):
        if padd_pixel[position] != padd_size:
            raise ValueError("The padding is wrong")
    #This remove the padding from the end
    pixels = padd_pixel[:-padd_size] 

    #This make the name for the decrypted image

    file_start = os.path.splitext(image_filename)[0]
    output_filename = file_start + "_decrypted.bmp"

    #write the header then the image data into the new file
    output_file= open(output_filename, "wb")
    output_file.write(header)
    output_file.write(pixels)
    output_file.close() 

    return output_filename

#This is the general encyption data function 
def encrypt_data(pixels, mode: str, key=None, iv=None):
    #turn the mode into uppercase so cbc -> CBC
    mode = mode.upper()

    #This turn a string into bytes
    if isinstance(pixels, str):
        pixels = pixels.encode("utf-8")

    #If there is no key this make a random 16 byte key
    if key is None:
        key = get_random_bytes(16)
    
    #make the IV for CBC to mix with the first block
    if mode == "CBC":
        if iv is None:
            iv = get_random_bytes(16)
    else: 
        iv = None

    #add paddinglast block is full 
    padd_size = 16-len(pixels) % 16
    # make the image data changeable so we can add padding
    padd_pixel= bytearray(pixels)

    #This add padding at the end using the padding size as the value
    for position in range(padd_size):
        padd_pixel.append(padd_size)
    
    #This set up AES with the key to encrypt one block at a time
    aes_ciper = AES.new(key,AES.MODE_ECB)
    encrypt_data = bytearray()
    previous_block = iv

    #This go through image data
    for block_star in range(0, len(padd_pixel), 16):
        #This grab the next 16 bytes and make the block changeable
        block = bytearray(padd_pixel[block_star:block_star + 16])

        # check if we need to mix the block for CBC
        if mode =="CBC" and previous_block is not None:
            for position in range(16):
                block[position] = block[position] ^ previous_block[position]
        
        #This encrypt the block using AES
        encrypted_block = aes_ciper.encrypt(bytes(block))
        encrypt_data.extend(encrypted_block )
        previous_block = encrypted_block

    return bytes(encrypt_data), key, iv



if __name__ == "__main__":
    key = get_random_bytes(16)
    iv = get_random_bytes(16)

    encrypt_image("cp-logo.bmp", "ECB", key)
    encrypt_image("cp-logo.bmp", "CBC", key, iv)