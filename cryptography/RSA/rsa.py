import random
import os
import subprocess
import argparse
import pyperclip

private, public, n = 0, 0, 0
ciphertext = []

CUR_USER = os.getlogin()
PRIV_SSH_DIR = "/home/%s/.ssh/" % (CUR_USER)

def _gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def _extended_gcd(a, b):
    lastRem, rem = abs(a), abs(b)
    x, y, lastx, lasty = 0, 1, 1, 0
    
    while rem:
        lastRem, (quotient, rem) = rem, divmod(lastRem, rem)
        x, lastx = lastx - quotient * x, x
        y, lasty = lasty - quotient * y, y
    return lastRem, lastx * (-1 if a < 0 else 1), lasty * (-1 if b < 0 else 1)

def _multiplicative_inverse(e, phi):
    g, x, _ = _extended_gcd(e, phi)
    if g != 1:
        raise ValueError
    return x % phi

def _is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(2, int(num ** 0.5) + 1, 1):
        if num % n == 0:
            return False
    return True


def generate_key_pair(p, q, auto):
    global public, private, n
    if auto == 1:
        folder = os.getcwd()
        lines = open(folder + '/cryptography/primes.txt').read().splitlines()
        p = random.choice(lines)
        q = random.choice(lines) 
        while p == q:
            q = random.choice(lines)
    p = int(p)
    q = int(q)
    n = p * q

    # Phi is the Euler Totient of n
    phi = (p - 1) * (q - 1)
    # Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)

    # Use Euclid's Algorithm to verify that e and phi(n) are coprime
    g = _gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = _gcd(e, phi)

    # Use Extended Euclid's Algorithm to generate the private key
    d = _multiplicative_inverse(e, phi)

    # Return public and private key_pair
    # Public key is (e, n) and private key is (d, n)
    public  = e
    private = d;
    return (p, q)


def encrypt(plaintext):
    global public, ciphertext, n
    # Unpack the key into it's components
    key = public

    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
    ciphertext = [pow(ord(char), key, n) for char in plaintext]
    
    # Return the array of bytes
    return ciphertext

def decrypt(cipher):
    global private, ciphertext, n
    # Unpack the key into its components
    key = int(private)
    # Generate the plaintext based on the ciphertext and key using a^b mod m
    aux = [str(pow(char, key, n) ) for char in ciphertext]

    # Return the array of bytes as a string
    plain = [chr(int(char2)) for char2 in aux]
    return ''.join(plain)

def gen_SSHKey():
    os.chdir(PRIV_SSH_DIR)
    if not "id_rsa" in os.listdir(PRIV_SSH_DIR):
        subprocess.call('ssh-keygen -t rsa', shell = True)

    file = PRIV_SSH_DIR + "id_rsa.pub"
    if not os.path.exists(file):
        return
    lines = []
    with open(file) as f:
        lines = f.readlines()
    pubKey = ''.join(x for x in lines)
    
    file = PRIV_SSH_DIR + "id_rsa"
    if not os.path.exists(file):
        return
    lines = []
    with open(file) as f:
        lines = f.readlines()
    priKey = ''.join(x for x in lines[1:-1])
    return pubKey, priKey


def get_SSHKey():
    file = PRIV_SSH_DIR + "id_rsa.pub"
    if not os.path.exists(file):
        return
    lines = []
    with open(file) as f:
        lines = f.readlines()
    pubKey = ''.join(x for x in lines)
    pyperclip.copy(pubKey)

if __name__ == '__main__':
    p = int(input() )
    q = int(input() )

    p, q = generate_key_pair(p, q, 0)
    print(p, q)

    message = input() 
    encrypted_msg = encrypt(message)
    print(encrypted_msg)
    print(decrypt(encrypted_msg) )
