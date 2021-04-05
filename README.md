# Simple secure client server application

A simple client server application to demostrate the working of various cryptographic algorithms namely,
1. Public key cryptography - RSA algorithm
2. Private key cryptography - AES algorithm in CTR mode
3. Digital signature - RSA algorithm
4. Hash function - SHA256

All the above functions are implemented using Python built in libraries and functions.

## What does the application do?

- The application lets the user schedule COVID-19 test appointment.
- The application has an existing user by default. New users can register and book an appointment too.
- Once the login is successful, the user is prompted with a set a questions to book an appointment.
- An acknowledgement(Appointment number) is sent once the booking is successfully scheduled.

## How are the various algorithms implemented?
- The AES session key which is encrypted using RSA public key at the client is sent to the server.  
- When the existing user logs in the hash of the password is encrypted using AES crypto object at the client and sent to server <br> the server 
decrypts this using the AES crypto object.
- Once the login is successful the server sends a couple of questions for the user to book an appointment.
- Each of the user details is encypted and decrypted using AES crypto object.
- Once all the details are received by the server, the server sends an acknowledgment to the user. <br> This acknowledgment is digitally signed by the server and sent to client which is then verified.

Also time specifics is added to determine the time taken by each of the algorithms.

## How to run the code

First run the rsa.py code to generate the RSA public private key pair.
```
python3 rsa.py
```

Next run aes.py code to generate AES session key.
```
python3 aes.py
```

Finally on separate terminal windows run both server and client programs simultaneously.
```
python3 server.py
python3 client.py
```
