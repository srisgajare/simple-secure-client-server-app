#!/usr/bin/env python
# coding: utf-8

import time
import socket
import pickle
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

print("\nWaiting to be connected to the server...\n")
time.sleep(1)

# Socket instance for connection oriented TCP protocol
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Ip address of the client/host
host = "192.168.86.38"  # Changes according to where the code is running
#host = input("Enter host IP address:")
port = int(input("Enter port number:"))

# Connect to server using IP and port number
print("\nTrying to connect to ", host, "(", port, ")\n")
time.sleep(1)
s.connect((host, port))
print("Connected...\n")

# Since I am using AES CTR mode, fetching the counter value from the file
with open("aes_counter", "rb") as aes_counter_file:
    counter = aes_counter_file.read()
    # print(counter)

# Read AES session key from the file
with open("aeskey", "rb") as aeskey_file:
    aeskey = aeskey_file.read()
    # print(aeskey)

# Read the public key generated by RSA algorithm, client has the public key
public_key = RSA.importKey(open("public.pem").read())

# Encrypt the AES session key with the public RSA key
start_time = time.time()
cipher_rsa = PKCS1_OAEP.new(public_key)
enc_aes_key = cipher_rsa.encrypt(aeskey)

# Prints time taken by RSA algorithm to encrypt the aes session key.
print("---RSA encryption - %.2f milliseconds ---" %
      ((time.time() - start_time) * 1000))

# AES session key encrypted with client's public key is sent to the server.
s.send(enc_aes_key)

# Instantiating a crypto object called AESKey to encrypt the messages and send to server
AESKey = AES.new(aeskey, AES.MODE_CTR, counter=lambda: counter)

# These messages are printed once the client is connected to server
print(
    "\nWelcome to ABC Hospital Online Portal for booking Covid tests!\nKindly provide your login details\n"
)
print(
    "\nExisting users login, new users can register by providing username and password\n"
)

# Input UserName
response = s.recv(2048)
name = input(response.decode())
# Send response to server
s.send(str.encode(name))

# Input Password
response = s.recv(2048)
password = input(response.decode())

# Encrypt the password with AES crypto object and send to the server
start_time = time.time()
e_password = AESKey.encrypt(str.encode(password))

# Prints the time taken by AES algorithm at the client to encrypt and send a response to server
print(
    "\n--- AES encryption - %.2f milliseconds ---" % (
        (time.time() - start_time) * 1000)
)
# Send the encrypted password to server
s.send(e_password)

# Password hash using SHA256 to determine the time taken for hashing at client
start_time = time.time()
password = SHA256.new(str.encode(password)).hexdigest()

# Prints time taken for hashing password at the client
print(
    "---Client side hashing - %.2f milliseconds ---\n"
    % ((time.time() - start_time) * 1000)
)

# Receive response from the server based on username and password given
response = s.recv(2048)
response = response.decode()
print(response)
# If the password hash do not match, login is failed terminate the code
if response == "Login Failed":
    quit()

# Send client response to server
s.send(str.encode("Client received response"))
time.sleep(3)

# Answer a set a questions to book an appointment
response = s.recv(2048)

# Encrypt the message using AES cryto object and send to server
pname = input(response.decode())
e_pname = AESKey.encrypt(str.encode(pname))
print(e_pname)
s.send(e_pname)

response = s.recv(2048)
# Encrypt the message using AES cryto object and send to server
page = input(response.decode())
e_page = AESKey.encrypt(str.encode(page))
s.send(e_page)

response = s.recv(2048)
# Encrypt the message using AES cryto object and send to server
pcon = input(response.decode())
e_pcon = AESKey.encrypt(str.encode(pcon))
s.send(e_pcon)

response = s.recv(2048)
# Encrypt the message using AES cryto object and send to server
paddr = input(response.decode())
e_paddr = AESKey.encrypt(str.encode(paddr))
s.send(e_paddr)

response = s.recv(2048)
# Encrypt the message using AES cryto object and send to server
econ = input(response.decode())
e_econ = AESKey.encrypt(str.encode(econ))
s.send(e_econ)

response = s.recv(2048)
# Encrypt the message using AES cryto object and send to server
pemail = input(response.decode())
e_pemail = AESKey.encrypt(str.encode(pemail))
s.send(e_pemail)

response = s.recv(2048)
# Encrypt the message using AES cryto object and send to server
pappoint = input(response.decode())
e_pappoint = AESKey.encrypt(str.encode(pappoint))
s.send(e_pappoint)

# Receive ack data
data = s.recv(2048)

# De-serialize the received data
data = pickle.loads(data)
# print(data)

# Receive the digital signature from server
digital_sign = s.recv(2048)

# Hash the received ack data
h = SHA256.new(data)
try:
    start_time = time.time()
    # Verify the digital signature using client side public key
    PKCS1_v1_5.new(public_key).verify(h, digital_sign)
    print(
        "\n--- Digital Signature verification - %.2f milliseconds ---\n"
        % ((time.time() - start_time) * 1000)
    )
    print("The signature is valid.\n")
    # Print the ack data if the digital sign verfification is successful
    print(data.decode())
except (TypeError, ValueError):
    print("The signature is not valid.\n")
s.close()
