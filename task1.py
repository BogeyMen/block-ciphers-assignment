#This open file for read in binary
image_file = open("mustang.bmp", "rb")

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

