#!/usr/bin/python
# I wanted to learn how rsa cryptography worked so I wrote this quick program
# It does not do any sort of padding, tranmsits simple characters
# Do not use for any sensitive materials
# Guaranteed this code is not efficient and suseptible to side channel attacks
#
# 2015-07-07
# sverasch
# 

import random
import math
import binascii

def factors(n):
    """returns factors of a number, took this from the internet"""
    return set(reduce(list.__add__, ([i, n//i] for i in range(1, int(n**0.5) + 1) if n % i == 0)))

def isprime(n):
    """took this code from internets"""
    '''check if integer n is a prime'''
    # make sure n is a positive integer
    n = abs(int(n))
    # 0 and 1 are not primes
    if n < 2:
        return False
    # 2 is the only even prime number
    if n == 2:
        return True
    # all other even numbers are not primes
    if not n & 1:
        return False
    # range starts with 3 and only needs to go up the squareroot of n
    # for all odd numbers
    for x in range(3, int(n**0.5)+1, 2):
        if n % x == 0:
            return False
    return True

class User(object):
    def __init__(self):
        self.p = None           # first prime
        self.q = None           # second prime
        self.n = None           # p * q
        self.phi = None         # totient of n phi(n)
        self.phi_factors = None # phi_factors
        self.e = None           # coprime
        self.d = None           # multiplecative inverse of e
        self.public_key = (self.n, self.e)
        self.private_key = (self.d)

    def set_primes(self, p, q):
        self.p = p
        self.q = q
        self.n = p * q

    def calculate_totient(self):
        """calculates the totient of p and q
        also factors phi"""
        self.phi = (self.p - 1)*(self.q - 1)
        self.phi_factors = factors(self.phi)
        return self.phi

    def calculate_coprime(self, coprime_number=None):
        """sets coprime, if coprime is None, sets and returns
        return a number between 1 and the totient that is coprime to the totient

        note that this function is not efficient whatsoever"""

        if coprime_number is None:
            self.e = random.randrange(1, self.phi)
            print 'checking if ' + str(self.phi) + 'is coprime with' 
            while True:
                if isprime(self.e):
                    if self.iscoprime(self.e):
                        print '\t'+ str(self.e) + '\tis coprime'
                        break
                print '\t' + str(self.e) + '\tis not coprime'
                self.e = random.randrange(1, self.phi)
        else:
            if self.iscoprime(coprime_number):
                self.e = coprime_number
            else:
                raise Exception("%s is not a coprime of %s" % (coprime_number, self.phi))

        # once we have calculated our coprime, we have our public key
        self.public_key = (self.n, self.e)
        return self.e
            
    def iscoprime(self, n):
        """checks to see if the two numbers are coprime,
        make sure that n is not a factor of the totient

        https://en.wikipedia.org/wiki/Coprime"""
        return n not in self.phi_factors

    def calculate_modular_multiplicative_inverse(self):
        """https://en.wikipedia.org/wiki/Modular_multiplicative_inverse"""
        self.d = pow(self.e, self.phi -1, self.phi)
        return self.d

    def encrypt(self, plaintext, public_key):
        modulo, exponent = public_key
        print "encypting %s^%s %% %s" % (plaintext,exponent,modulo)
        #pow does plaintext^exponent % modulo
        return pow(plaintext, exponent, modulo)
        
    def decrypt(self, ciphertext):
        #pow does ciphertext^self.d % self.n
        return  pow(ciphertext, self.d, self.n)

    def generate_keys(self):
        self.calculate_totient()
        self.calculate_coprime()
        self.calculate_modular_multiplicative_inverse()
    
if __name__ == '__main__':
    alice = User()
    bob = User()

# alice key generation
    #1 calculate prime number,
    #2 and n (n = p * q)
    alice.set_primes(61,53)

    #3 calculate totient (p - 1)(q - 1)
    alice.calculate_totient()
        
    #4 choose coprime in thie case we're going to just use a hard coded value
    alice.calculate_coprime(17)

    #5 compute multiplicative inverse
    alice.calculate_modular_multiplicative_inverse()
    #alice.d = 2753

# bob key generation
    bob.set_primes(23,91)
    bob.generate_keys()

# data transfer
    # 1 alice gives bob her public key
    alice_public_key = alice.public_key
    print "Bob, here is my public key: %s" % str(alice_public_key)
    # 2 bob gives alice his public key
    bob_public_key = bob.public_key
    print "Alice, here is my public key: %s" % str(bob_public_key)

    # 3 alice wants to say hello to bob, so she uses bob's public key to encrypt her message
    # HiB in ascii is 4869
    alice_plaintext = 65
    alice_ciphertext = alice.encrypt(alice_plaintext, bob_public_key)
    # 4 alice sends the ciphertext to bob and he decrypts it using his private key 
    print "Alice says here is my encrypted message: %s" % alice_ciphertext
    decrypted_ciphertext = bob.decrypt(alice_ciphertext)
    print "Bob decrypts from alice: %s" % decrypted_ciphertext

    
    # 5 bob wants to say hello alice
    # HiA in ascii is 486941
    bob_plaintext = 66
    bob_ciphertext = bob.encrypt(bob_plaintext, alice_public_key)

    print "Bob says here is my encrypted message: %s" % bob_ciphertext
    # 6 bob sends the ciphertext to alice, and she decrypts it using her private key
    decrypted_ciphertext = alice.decrypt(bob_ciphertext)
    print "Alice decrypts from bob: %s" % decrypted_ciphertext
