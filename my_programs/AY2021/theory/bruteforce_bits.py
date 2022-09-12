import math

count = 1
while count < pow(2, 256):
    print(str(count) + " = " + bin(count) + " length = " + "{:.0f}".format(math.floor(math.log(count, 2)+1)))
    count += 1
