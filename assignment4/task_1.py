import hashlib
import time
import sys

def computeHash(message):
    hash_object = hashlib.sha256(message)
    digest = hash_object.digest()
    return digest

def truncateHash(message, bits):
    #This keep the first bits, even when the size is not whole bytes
    digest = computeHash(message)
    hash_number = int(digest.hex(), 16)
    bits_to_remove = 256-bits
    truncated_hash = hash_number//(2**bits_to_remove)
    return truncated_hash


def countDifference(first, second):
    different_bits = 0
    different_bytes = 0
    for position in range(len(first)):
        first_byte = first[position]
        second_byte = second[position]
        if first_byte != second_byte:
            different_bytes = different_bytes+1

        #This compare one bit at a time using the remainder
        for bit in range(8):
            first_bit = first_byte%2
            second_bit = second_byte%2
            if first_bit != second_bit:
                different_bits = different_bits+1
            first_byte = first_byte//2
            second_byte = second_byte//2

    return different_bits, different_bytes


def compareMessages():
    print("\nTask 1 part b: change only one bit")
    for message in [b"Hi Bob!", b"Hi Alice!", b"Hello!", b"computer security", b"SHA256"]:
        #This change the last bit in the first byte
        changed_message = bytearray(message)
        #An even byte end in 0, an odd byte end in 1
        if changed_message[0]%2 == 0:
            changed_message[0] = changed_message[0]+1
        else:
            changed_message[0] = changed_message[0]-1
        changed_message = bytes(changed_message)

        first_hash = computeHash(message)
        second_hash = computeHash(changed_message)
        input_bits, input_bytes = countDifference(message, changed_message)
        output_bits, output_bytes = countDifference(first_hash, second_hash)

        print("\nOriginal message=", message)
        print("Changed message=", changed_message)
        print("First digest=", first_hash.hex())
        print("Second digest=", second_hash.hex())
        print("Different input bits=", input_bits)
        print("Different digest bits=", output_bits)
        print("Different digest bytes=", output_bytes)



def makeMessage(bits, number):
    #the size is in the message so each experiment have different inputs
    message = "hash-lab-"+str(bits)+":"+str(number)
    return message.encode("utf-8")


def findCollision(bits):
    print("\nSearching", bits, "bits", flush=True)
    start_time = time.perf_counter()
    seen_hashes = {}
    number = 0

    while True:
        message = makeMessage(bits, number)
        value = truncateHash(message, bits)

        #This check if we alreadyy recieved the same hash before
        if value in seen_hashes:
            seconds = time.perf_counter()-start_time
            first_number = seen_hashes[value]
            first_message = makeMessage(bits, first_number)

            #This remove the 0x at the start and add any missing zeros
            truncated_hex = hex(value)[2:]
            hex_length = (bits+3)//4
            while len(truncated_hex) < hex_length:
                truncated_hex = "0"+truncated_hex

            result = {
                "bits": bits,
                "inputs": number+1,
                "seconds": seconds,
                "message1": first_message.decode(),
                "message2": message.decode(),
                "truncated_hex": truncated_hex,
                "hash1": computeHash(first_message).hex(),
                "hash2": computeHash(message).hex(),
            }
            print("First message =", first_message)
            print("Second message =", message)
            print("Same truncated digest =", result["truncated_hex"])
            print("Inputs hashed =", number+1)
            print("Collision time =", round(seconds, 6), "seconds", flush=True)
            return result

        #This save the input number so we can make its message again
        seen_hashes[value] = number
        number = number+1

        if number%5000000 == 0:
            print("Tested", number, "inputs", flush=True)



def main():
    #This let you hash your own text from the terminal
    if len(sys.argv) > 1:
        message = sys.argv[1]
        for position in range(2, len(sys.argv)):
            message = message+" "+sys.argv[position]
        print(computeHash(message.encode("utf-8")).hex())
        return

    print("Task 1 part a: SHA256 in hexadecimal")
    for message in [b"Hi Bob!", b"Hi Alice!", b"Hello!"]:
        print("Message =", message)
        print("Digest =", computeHash(message).hex())

    compareMessages()
    print("\nTask 1 part c: find truncated collisions")
    results = []
    for bits in range(8, 51, 2):
        result = findCollision(bits)
        results.append(result)

    print("\nAll collision searches finished")
    print("\nDigest bits    Inputs hashed    Collision time (seconds)")
    for result in results:
        print(f"{result['bits']:<14} {result['inputs']:<16} {result['seconds']:.9f}")


if __name__ == "__main__":
    main()
