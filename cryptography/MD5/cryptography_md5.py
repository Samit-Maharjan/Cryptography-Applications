'''
Author: Yu Mi
Create a class to implement MD5 hashing, the real hashing function is in __hash, 
while other functions and values would be supportive use.
Reference:https://en.wikipedia.org/wiki/MD5
'''

import os
import hashlib 

DEBUG_FLAG = 0  # Change to 0 for release
MAX_BITS = 32
CHUNK_SIZE = 512
class CryptographyMD5():

    def __init__(self):  # maxbits defines the bits a value could contain
        # Some magic numbers used in MD5
        self.__A = 0x67452301
        self.__B = 0xefcdab89
        self.__C = 0x98badcfe
        self.__D = 0x10325476
        self.__K = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391]
        self.__S = [7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
                    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
                    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
                    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21]
        self.__mask = 0
        for _ in range(MAX_BITS):
            self.__mask |= 0x1
            self.__mask <<= 1
        self.__mask >>= 1
        if DEBUG_FLAG:
            print('mask=',hex(self.__mask))

## public methods
    def encrypt(self, message):
        return self.__digest(message)

## private methods
    def __F(self,x,y,z):
        ''' linear function F'''
        return (x&y)|((~x)&z)

    def __G(self,x,y,z):
        '''linear function G'''
        return (x&z)|(y&(~z))
    
    def __H(self,x,y,z):
        '''linear function H'''
        return x^y^z

    def __I(self,x,y,z):
        '''linear function I'''
        return y^(x|(~z))

    def __pad(self,message):
        ''' First step of hashing, pad 1 and length to the end of message'''
        padded = ''
        message_length = len(message)
        if DEBUG_FLAG:
            print('message_length=',message_length)
        message += '1' # append 1 to mark end of message

        while (len(message) % 512 != 448):
            message += '0' 
        #bring the length of the message up to 64 bits fewer than a multiple of 512
        if DEBUG_FLAG:
            print('padlength=',self.__padlength(message_length))
        return message + self.__padlength(message_length)
        # rewrite message with 1 and the ending length

    def __padlength(self,length):
        ''' The remaining bits are filled up with 64 bits representing 
            the length of the original message, modulo 2^64'''
        binLength = bin(length).replace('b','0')
        if len(binLength) > 64:
            binLength = binLength[len(binLength) - 64 : ] # cut through       
        padded = ''
        padded = "0" * (64 - len(binLength))
        padded += binLength[::-1] # reverse length byte first to preserve correct order

        return padded[::-1]

    def __splitIntoBlocks(self,message,n):
        ''' This function is used to split the message into blocks according to the 
        assigned length 'n' '''
        return [message[i:i+n] for i in range(0,len(message),n)]

    def __splitIntoWords(self, message, message_length, finalBlock):
        ''' Split the chunks into 16 32-bit words'''
        message = self.__splitIntoBlocks(message, 32)
        if DEBUG_FLAG:
            print('message in word=',message)
            print('message in length=',message_length)
        wordArray = [0] * 16

        wordIndex = 0
        for word in message:
            bytes = self.__splitIntoBlocks(word, 8)
            tempByte = 0
            powers = 0

            for byte in bytes:
                tempByte = wordArray[wordIndex]
                tempByte = tempByte | int(byte, 2) << powers
                powers += 8
                wordArray[wordIndex] = tempByte
            
            wordIndex += 1
            powers = 0

        ## correct last two bytes if we're on the final block
        if finalBlock:
            wordArray[-2] = message_length << 3
            wordArray[-1] = message_length >> 29
        if DEBUG_FLAG:
            print('wordArray=',wordArray)

        return wordArray

    def __toBinaryString(self,message):
        ''' Converts a given string into a binary form'''
        return ''.join("{:08b}".format(byte) 
            for byte in bytearray(message.encode('utf-8') ) )

    def __leftrotate(self,num,s):
        return ( (num << s) | (num >> (MAX_BITS - s) ) ) & self.__mask

    def __hash(self,message):
        '''The main hashing function'''
        message_length = len(message.encode('utf-8'))
        chunks = self.__splitIntoBlocks(
                 self.__pad(
                 self.__toBinaryString(message))
                 ,512)
        if DEBUG_FLAG:
            print('chunks=',chunks)

        for chunk in chunks:
            words = self.__splitIntoWords(chunk, message_length, chunks.index(chunk) == len(chunks) - 1)
            if DEBUG_FLAG:
                print('words=',words)
            a = self.__A
            b = self.__B
            c = self.__C
            d = self.__D

            if DEBUG_FLAG:
                print('a=',hex(a),'b=',hex(b),'c=',hex(c),'d=',hex(d))
            F = 0
            g = 0
            for i in range(64):
                if i<=15 :
                    F = self.__F(b, c, d)
                    g = i
                elif i<=31:
                    F = self.__G(b, c, d)
                    g = (5 * i + 1) % 16
                elif i<=47:
                    F = self.__H(b, c, d)
                    g = (3 * i + 5) % 16
                elif i<=63:
                    F = self.__I(b, c, d)
                    g = (7 * i) % 16
                else:
                    raise NotImplementedError
                F = (F + a + self.__K[i] + words[g]) & self.__mask
                F = (self.__leftrotate(F,self.__S[i]) + b) & self.__mask
                a = d
                d = c
                c = b
                b = F
                if DEBUG_FLAG:
                    print(print('a=',hex(a),'b=',hex(b),'c=',hex(c),'d=',hex(d)))

            # add masks to suppress upper bits
            self.__A = (a + self.__A) & 0xffffffff
            self.__B = (b + self.__B) & 0xffffffff
            self.__C = (c + self.__C) & 0xffffffff
            self.__D = (d + self.__D) & 0xffffffff
            if DEBUG_FLAG:
                print('SELF','a=',hex(self.__A),'b=',hex(self.__B),'c=',hex(self.__C),'d=',hex(self.__D))

    def __digest(self, message):
        self.__hash(message)
        
        if DEBUG_FLAG:
            print("A=",self.__A,"digest=",self.__hexdigest(self.__A))
            print("B=",self.__B,"digest=",self.__hexdigest(self.__B))
            print("C=",self.__C,"digest=",self.__hexdigest(self.__C))
            print("D=",self.__D,"digest=",self.__hexdigest(self.__D))
        digestMessage = self.__littleHexDigest(self.__A) + self.__littleHexDigest(self.__B) + self.__littleHexDigest(self.__C) + self.__littleHexDigest(self.__D)
        digestMessage = digestMessage.upper()

        return digestMessage

    def __littleHexDigest(self,number:int)->str:
        '''returns little endian hex digest'''
        res = b''
        numList = [];
        bufferbytes = []
        b = bin(number).replace('b', '0')
        b = "0" * (34 - len(b) ) + b # pad leading zero if missing

        bufferbytes.append(int(b[ 2:10],2))
        bufferbytes.append(int(b[10:18],2))
        bufferbytes.append(int(b[18:26],2))
        bufferbytes.append(int(b[26:34],2))

        res += bytes([bufferbytes[3]])
        res += bytes([bufferbytes[2]])
        res += bytes([bufferbytes[1]])
        res += bytes([bufferbytes[0]])

        return ''.join(["{:02x}".format(byte) for byte in bytearray(res)])

    def __hexdigest(self,number:int)-> str:
        ''' returns hex form of an integer value, for example:
        >>>hexdigest(65535)
        'FFFF'
        NOTE: this function only takes int, you may need to call it mutiple times when
        dealing with larger numbers
        '''
        temp = '';
        while number >0:
            this_num = number %16
            number = int(number /16)
            this_hex = hex(this_num)
            temp = this_hex[2].upper() + temp 
        return temp

    def filedigest(self, src:str, fname:str):
        os.umask(0)
        hash = hashlib.md5()
        # File to be hashed
        file = os.path.join(src, fname)
        with open(file, "rb") as f:
            # Message as chunks each of size 512
            chunk = f.read(CHUNK_SIZE)
            while chunk:
                hash.update(chunk)
                chunk = f.read(CHUNK_SIZE)
        
        # Checksum file
        folder = src + "/checksum"
        if not os.path.exists(folder):
            os.makedirs(folder, mode = 0o777)

        checksum = os.path.join(folder + "/", fname[:fname.rindex(".")]
                + "_" + "checksum.txt")
        with open(checksum, "w") as f:
            f.write(hash.hexdigest() )

    def fileverify(self, src:str, fname:str, checkSum:str):
        import filecmp
        hash = hashlib.md5()
        file = os.path.join(src, fname)
        with open(file, "rb") as f:
            chunk = f.read(CHUNK_SIZE)
            while chunk:
                hash.update(chunk)
                chunk = f.read(CHUNK_SIZE)

        folder = checkSum[:checkSum.rindex("/") + 1]
        checksum = os.path.join(folder, "Verifying_Checksum.txt")
        with open(checksum, "w") as f:
            f.write(hash.hexdigest() )
        
        result = filecmp.cmp(checkSum, checksum)
        os.remove(checksum)
        return result

if __name__ =='__main__':

    '''
    Create tests for this file
    '''
    import time
    message = input('Please type the message you want to hash:')
    md5 = CryptographyMD5()
    start = time.time()
    digest = md5.encrypt(message)
    print('MD5 by our function:',digest)
    end = time.time()
    print("Running Time: {:3f}".format(end-start))
    hashlibMD5 = hashlib.md5()
    start = time.time()
    hashlibMD5.update(message.encode('utf-8'))
    print('MD5 by hashlib: ',hashlibMD5.hexdigest())
    end = time.time()
    print("Running Time: {:3f}".format(end-start))
    md5.filedigest("test", "ReversedBliss.jpg")



