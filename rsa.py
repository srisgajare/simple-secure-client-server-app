import time
from Crypto.PublicKey import RSA

# Generate RSA key pair
start_time = time.time()
key = RSA.generate(2048)

# Prints the time taken for RSA key pair generation
print(
    "\n--- RSA key pair generation time - %.2f milliseconds ---\n"
    % ((time.time() - start_time) * 1000)
)

# Export RSA private key and write to file
private_key = key.exportKey()
file_out = open("private.pem", "wb")
file_out.write(private_key)
file_out.close()

# Export RSA public key and write to a file
public_key = key.publickey().exportKey()
file_out = open("public.pem", "wb")
file_out.write(public_key)
file_out.close()
