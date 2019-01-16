#!/usr/bin/python3
import os
import getpass

#Input user password to generate keyfile
response = getpass.getpass("Please enter a password: ")

#Input file to encrypt:
fileInput = input("Enter a file to encrypt. (If blank, uses provided input.txt): ")

if (fileInput == ""):
    fileInput = 'input.txt'

#Install the Bitstring library
print("Checking for Python bitstring library...")
os.system('pip install bitstring')

#Install the PyCryptodomex library. This replaces the older pycrypto but can still exist alongside it.
print("Checking for Python Cryptodome library...")
os.system('pip install pycryptodomex')

print('Libraries installed, proceeding...')

#Generate a keyfile
print("Generating keyfile with 3Des keys at keyfile.txt...")
os.system('python 3Des.py genkey ' + response + ' keyfile.txt')

print("Proceeding with encryption:")

#Encrypt 3 different times, with each of the 3 different modes
print("Encrypting input with 3DES in ECB Mode and outputting to cipher_ecb.txt...")
os.system('python 3Des.py encrypt ' + fileInput + ' keyfile.txt cipher_ecb.txt ECB')

print("Encrypting input with 3DES in CBC Mode and outputting to cipher_cbc.txt...")
os.system('python 3Des.py encrypt ' + fileInput + ' keyfile.txt cipher_cbc.txt CBC')

print("Encrypting input with 3DES in OFB Mode and outputting to cipher_ofb.txt...")
os.system('python 3Des.py encrypt ' + fileInput + ' keyfile.txt cipher_ofb.txt OFB')

print("Encryption complete, proceeding to decryption:")

#Decrypt 3 different times, with each of the 3 different modes
print("Decrypting cipher_ecb.txt and outputting to clear_ecb.txt...")
os.system('python 3Des.py decrypt cipher_ecb.txt keyfile.txt clear_ecb.txt ECB')

print("Decrypting cipher_cbc.txt and outputting to clear_cbc.txt...")
os.system('python 3Des.py decrypt cipher_cbc.txt keyfile.txt clear_cbc.txt CBC')

print("Decrypting cipher_ofb.txt and outputting to clear_ofb.txt...")
os.system('python 3Des.py decrypt cipher_ofb.txt keyfile.txt clear_ofb.txt OFB')

print("Done!")