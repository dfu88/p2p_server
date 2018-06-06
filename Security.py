""" 
	Security.py

    COMPSYS302 - Software Design
    Author: Dylan Fu

	Security functions handling the encryption, decryption, and hashing of messages or files
"""

import hashlib
import urllib
import urllib2
import binascii
from Crypto.Cipher import AES
from Crypto.Cipher import XOR
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Hash import SHA512
from passlib.hash import bcrypt
from passlib.hash import scrypt
from Crypto import Random

def XOREncrypt(data):
	key = XOR.new('01101001')
	return binascii.hexlify(key.encrypt(data))

def XORDecrypt(data):
	key = XOR.new('01101001')
	return key.decrypt(binascii.unhexlify(data))

def generateAESKey():
	return binascii.hexlify(Random.new().read(16))

def AESEncrypt(enc, AESKey):
	# key = binascii.unhexlify(AESKey)
	enc = str(enc)
	enc = enc + ((16 - len(enc) % 16) * ' ')
	iv = enc[:16]
	cipher = AES.new(AESKey, AES.MODE_CBC, iv)
	enc = cipher.encrypt(enc)
	return binascii.hexlify(iv + enc)

def AESDecrypt(enc, AESKey):
	# key = binascii.unhexlify(AESKey)
	enc = binascii.unhexlify(enc)
	iv = enc[:16]
	cipher = AES.new(AESKey, AES.MODE_CBC, iv)
	return cipher.decrypt(enc[16:]).rstrip(' ')

def generateRSAKey():
	random_generator = Random.new().read
	return RSA.generate(1024, random_generator)

def RSAEncrypt(data, publicKey):
	pubKey = RSA.importKey(binascii.unhexlify(publicKey))
	for key in data:
	    if key != 'encryption' or key != 'destination' or key != 'sender' or key != 'hashing' or key != 'hash':
	        data[key] = binascii.hexlify(pubKey.encrypt(data[key], 32)[0])        
	data['encryption'] = 3
	return data

def RSAEncryptKey(enc, publicKey):
	pubKey = RSA.importKey(binascii.unhexlify(publicKey))
	return binascii.hexlify(pubKey.encrypt(enc, 32)[0])

def RSADecrypt(data, privateKey):
	for key in data:
		if key != 'encryption' or key != 'destination' or key != 'sender' or key != 'hashing' or key != 'hash':
			data[key] = privateKey.decrypt(binascii.unhexlify(data[key])).encode('utf-8')
	return data

def RSADecryptKey(enc, privateKey):
	return privateKey.decrypt(binascii.unhexlify(enc)).encode('utf')


def encryptMessagesFiles(data, publicKey, enc):
	if 'message' in data:
		data['message'] = data['message'].encode('utf-8')
		data['hashing'] = '0'
		data['hash'] = ''

	if enc == 1:
		data['encryption'] = '1'
		for key in data:
			if key == 'encryption' or key == 'destination' or key == 'sender' or key == 'hashing' or key == 'hash':
				pass
			else:
				data[key] = XOREncrypt(data[key])
	if enc == 2:
		data['encryption'] = '2'
		for key in data:
			if key == 'encryption' or key == 'destination' or key == 'sender' or key == 'hashing' or key == 'hash':
				pass
			else:
				data[key] = AESEncrypt(data[key], '41fb5b5ae4d57c5ee528adb078ac3b2e')
	if enc == 3 and (len(data['message']) < 128):
		data['encryption'] = '3'
		data = RSAEncrypt(data, publicKey)
	if enc == 4:
		data['encryption'] = '4'
		AESKey = generateAESKey()
		data['decryptionKey'] = RSAEncryptKey(AESKey, publicKey)
		for key in data:
			if key == 'encryption' or key == 'destination' or key == 'sender' or key == 'hashing' or key == 'hash' or key == 'decryptionKey':
				pass
			else:
				data[key] = AESEncrypt(data[key], AESKey)
	return data

def decryptMessagesFiles(data, privateKey):
	if 'encryption' not in data:
		data['encryption'] = '0'
	if int(data['encryption']) == 1:
		for key in data:
			if key == 'encryption' or key == 'sender' or key == 'destination' or key == 'hashing' or key == 'hash':
				pass
			else:
				data[key] = XORDecrypt(data[key])
	if int(data['encryption']) == 2:
		for key in data:
			if key == 'encryption' or key == 'sender' or key == 'destination' or key == 'hashing' or key == 'hash':
				pass
			else:
				data[key] = AESDecrypt(data[key], '41fb5b5ae4d57c5ee528adb078ac3b2e')
	if int(data['encryption']) == 3:
		data = RSADecrypt(data, privateKey)
	if int(data['encryption']) == 4:
		data['decryptionKey'] = RSADecryptKey(data['decryptionKey'], privateKey)
		for key in data:
			if key == 'encryption' or key == 'sender' or key == 'destination' or key == 'hashing' or key == 'hash' or key == 'decryptionKey':
				pass
			else:
				data[key] = AESDecrypt(data[key], data['decryptionKey'])

	salt = data['sender'].encode('ascii')
	text = ''
	if 'message' in data:
		text = data['message'].encode('utf-8')
	if 'file' in data:
		text = data['file']

	if 'hashing' not in data:
		data['hashing'] = 0
	if 'hash' not in data:
		data['hash'] = ''
	if data['hash'] == None:
		data['hash'] = ''

	if int(data['hashing']) == 0:
		return data
	if int(data['hashing']) == 1:
		if SHA256.new(text).hexdigest() == data['hash']:
			return data
	if int(data['hashing']) == 2:
		if SHA256.new(text + salt).hexdigest() == data['hash']:
			return data
	if int(data['hashing']) == 3:
		if SHA512.new(text + salt).hexdigest() == data['hash']:
			return data
	if int(data['hashing']) == 4:
		if bcrypt.verify(text + salt, data['hash']):
			return data
	if int(data['hashing']) == 5:
		if scrypt.verify(text + salt, data['hash']):
			return data

	return "7: Hash doesn't match"