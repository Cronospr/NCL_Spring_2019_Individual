import sys
import string
from Crypto.Cipher import ARC4
import numpy
import itertools


#Cyber Command
#Our officers have obtained an encrypted message. See if you can decode it. We believe it's using an RC4 with a 4-character password.
#1:57:15 pm

#Cyber Command
#What is the plaintext of the message: 6fce38f8836e82d446c3af46eb3a945a97bb8088256751e47f73a02943883165? (75 pts)
#1:57:15 pm

#ALPHABET = string.digits
#ALPHABET = string.ascii_lowercase
ALPHABET = string.ascii_uppercase
#ALPHABET = string.letters
#ALPHABET = string.letters + string.digits
#ALPHABET = string.letters + string.digits + string.punctuation
#ALPHABET = string.printable
KEY_LENGTH = 4


def gen():
	for i in ALPHABET:
		yield tuple([i])


def check(key, data):
	decr = ARC4.new(key).decrypt(data)
	int_array = numpy.frombuffer(decr, dtype = numpy.uint8)
	count = numpy.bincount(int_array)
	prob = count / float(numpy.sum(count))
	prob = prob [numpy.nonzero(prob)]
	entropy = -sum(prob * numpy.log2(prob))
	if entropy < 4.4:
		print('\nKey       = {0}\nPlaintext = {1}\nEntropy   = {2}\n'.format(key, decr, entropy))
		#sys.exit()


def worker(base):
	data = "\x6f\xce\x38\xf8\x83\x6e\x82\xd4\x46\xc3\xaf\x46\xeb\x3a\x94\x5a\x97\xbb\x80\x88\x25\x67\x51\xe4\x7f\x73\xa0\x29\x43\x88\x31\x65"
	for i in itertools.product(ALPHABET, repeat = KEY_LENGTH - len(base)):
		check(''.join(base + i), data)


def serial():
	worker(tuple())


if __name__ == "__main__":
	serial()

print len(ALPHABET)**KEY_LENGTH, "iterations"
