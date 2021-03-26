import time
from Crypto.Random import get_random_bytes

# Generate a random AES session key and store it in a file.
start_time = time.time()
aes_key = get_random_bytes(32)

# Prints time taken for AES session key generation
print(
    "\n--- AES session key generation time - %.2f milliseconds ---\n"
    % ((time.time() - start_time) * 1000)
)

# Save the aes session key in a file
aeskey = open("aeskey", "wb")
aeskey.write(aes_key)
aeskey.close()

# Generate random counter required for AES_CTR mode and store it in a file.
counter = get_random_bytes(16)
aes_counter = open("aes_counter", "wb")
aes_counter.write(counter)
aes_counter.close()
