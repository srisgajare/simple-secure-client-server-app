#!/usr/bin/env python
# coding: utf-8
import time
import socket
import random
import pickle
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5

print("\nInitiating the server...\n")
time.sleep(1)

# Socket instance for connection oriented TCP protocol
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# To get the hostname
host = socket.gethostname()

# To retrieve IP from the hostname
ip = socket.gethostbyname(host)

# To bind to a given port number
port = int(input("Enter port number:"))
s.bind((host, port))
print(host, "(", ip, ")\n")

s.listen(1)
print("\nWaiting for incoming connections...\n")
conn, addr = s.accept()
print("Received connection from ", addr[0], "(", addr[1], ")\n")
print("\nWaiting for users to login/register\n")

# Dictionary to store user credentials, ie username and password hash
# Added one user by default
userCred = {
    "srishti": "ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae"
}

# Generate random number for acknowledgment
ack = random.randint(100000, 999999)

# Receive the encrypted aes session key from the client, which is later used to initiate the AES crypto object
# The aes session key is encrypted with Client's public RSA key
enc_aes_key = conn.recv(2048)

# Import RSA private key
private_key = RSA.importKey(open("private.pem").read())

# Decrypt the AES session key with the private RSA key that is available at the server
start_time = time.time()
cipher_rsa = PKCS1_OAEP.new(private_key)
aes_key = cipher_rsa.decrypt(enc_aes_key)

# Prints time taken for RSA decryption
print(
    "--- RSA decryption - %.2f milliseconds ---" % (
        (time.time() - start_time) * 1000)
)

# Since I am using AES CTR mode, fetching the counter value from the file
with open("aes_counter", "rb") as aes_counter_file:
    counter = aes_counter_file.read()
    # print(counter)

# Instantiating a crypto object called AESKey to decrypt the messages received from client
AESKey = AES.new(aes_key, AES.MODE_CTR, counter=lambda: counter)

# Request Username from client
conn.send(str.encode("ENTER USERNAME : "))
name = conn.recv(2048)
name = name.decode()

# Request Password from client
conn.send(str.encode("ENTER PASSWORD : "))

# Receive and decrypt the password using AES crypto object
passwd = conn.recv(2048)
start_time = time.time()
password = AESKey.decrypt(passwd)

# Prints the time taken by AES algorithm at the server to decrypt the password
print(
    "\n--- AES decryption - %.2f milliseconds ---" % (
        (time.time() - start_time) * 1000)
)
password = password.decode()

# Hash the received password using SHA256 so that later it can be compared with the existing hash
start_time = time.time()
password = SHA256.new(str.encode(password)).hexdigest()

# Prints the time taken for hashing password at server
print(
    "--- Server side hashing - %.2f milliseconds ---"
    % ((time.time() - start_time) * 1000)
)


def receive_details():
    # Check the username and password hash received from the client, if the hash matches with the available hash in userCred Dict
    # then a list of questions required to book an appointment is sent and once all the action items are received
    # an acknowledgment is sent.
    if userCred[name] == password:
        # Response Code for Connected Client
        conn.send(str.encode("Login Successful! Welcome\n"))
        print("\nLogged in successfully", name)

        # Receive client response confirmation
        response = conn.recv(2048)
        print(response.decode())

        conn.send(str.encode("ENTER YOUR NAME : "))
        # Receive and decrypt the message from the client using AES cryto object
        pname = AESKey.decrypt(conn.recv(2048))
        print("Received Name.", pname.decode())

        # Receive and decrypt the customer/patient age
        conn.send(str.encode("ENTER YOUR AGE : "))
        p_age = AESKey.decrypt(conn.recv(2048))
        print("Received Patient age.", p_age.decode())

        # Receive and decrypt the customer/patient contact number
        conn.send(str.encode("ENTER YOUR CONTACT NUMBER : "))
        pcon = AESKey.decrypt(conn.recv(2048))
        print("Received Patient contact number.", pcon.decode())

        # Receive and decrypt the customer/patient address
        conn.send(str.encode("ENTER ADDRESS : "))
        paddr = AESKey.decrypt(conn.recv(2048))
        print("Received Patient address.", paddr.decode())

        # Receive and decrypt the customer/patient Emergency contact number
        conn.send(str.encode("ENTER PATIENT EMERGENCY CONTACT : "))
        pecon = AESKey.decrypt(conn.recv(2048))
        print("Received Patient emergency contact.", pecon.decode())

        # Receive and decrypt the customer/patient email id
        conn.send(str.encode("ENTER EMAILID : "))
        pemail = AESKey.decrypt(conn.recv(2048))
        print("Received Patient emailid.", pemail.decode())

        # Receive and decrypt the customer/patient Appointment date and time
        conn.send(str.encode("ENTER PREFERRED APPOINTMENT DATE AND TIME : "))
        pappoint = AESKey.decrypt(conn.recv(2048))
        print("Received Patient appointment date and time.", pappoint.decode())

        # Acknowledgement data to be sent to the client
        data = (
            "This is an acknowledgement to confirm your appointment is booked at your preferred date and time! The appointment number is:"
            + str(ack)
        )

        # Encode the data for it to be hashed
        new_data = str.encode(data)

        # Hash the data
        h = SHA256.new(new_data)

        # Sign the hashed data with RSA private key available at the server
        start_time = time.time()
        digital_sign = PKCS1_v1_5.new(private_key).sign(h)
        print(
            "\n--- Digital Signature - %.2f milliseconds ---\n"
            % ((time.time() - start_time) * 1000)
        )
        # print(digital_sign)

        # Serialize and send the ack data
        final_data = pickle.dumps(new_data)
        conn.sendall(final_data)
        print("\nAcknowledgement sent!\n")

        # Send the digital signature to be verified by the client
        conn.sendall(digital_sign)
        print("Digital Signature sent")

    else:
        # Response code if user login failed, when the password hash doesnt match hash present in the Dict
        conn.send(str.encode("Login Failed"))
        print("Login failed,Connection denied : ", name)
    while True:
        break
    conn.close()


# To register new users and add their password hashes to the dictionary
if name not in userCred:
    userCred[name] = password
    conn.send(
        str.encode(
            "Registration Successful. Please donot forget to update your profile"
        )
    )
    print("Registered : ", name)
    print("{:<8} {:<20}".format("USER", "PASSWORD"))
    for k, v in userCred.items():
        label, num = k, v
        # Prints the user name and password hashes stored in the userCred Dict
        print("{:<8} {:<20}".format(label, num))
    # Call the function to send and receive user details from the client
    receive_details()
else:
    # Call the function to send and receive user details from the client
    # if the user is existing user
    receive_details()
