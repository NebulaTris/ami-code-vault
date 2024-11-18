# Program Codes

## Experiment 1: To understand the principles of monoalphabetic ciphers through the Caesar Cipher and perform cryptanalysis using frequency analysis.
```py
#Caesar Cipher Encryption , Decryption and Cryptanalysis
def encrypt_caesar(plaintext, shift):
    ciphertext=""
    for char in plaintext:
        if char.isalpha():
            shift_start = ord('A') if char.isupper() else ord('a')
            ciphertext+=chr((ord(char) - shift_start + shift) % 26 + shift_start)
        else:
            ciphertext+=char
    return ciphertext

def decrypt_caesar(ciphertext,shift):
    plaintext=""
    for char in ciphertext:
        if char.isalpha():
            shift_start = ord('A') if char.isupper() else ord('a')
            plaintext+=chr((ord(char) - shift_start - shift) % 26 + shift_start)
        else:
            plaintext+=char
    return plaintext

def frequency_analysis(ciphertext):
    freq={}
    for char in ciphertext:
        if char.isalpha():
            if char in freq:
                freq[char] += 1
            else:
                freq[char] = 1
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    return sorted_freq


plaintext = "HELLO WORLD"
shift_key = 3

ciphertext = encrypt_caesar(plaintext, shift_key)
print("Encrypted text:", ciphertext)
print("Decrypted text:", decrypt_caesar(ciphertext, shift_key))
print("Frequency Analysis of ciphertext:", frequency_analysis(ciphertext))

```
____
## Experiment 2: To understand the basics of OpenSSL, its cryptographic capabilities, and an introduction to the Federal Information Processing Standards (FIPS) as they relate to cryptographic security.
Basic OpenSSL Commands:
```bash
openssl genpkey #Generate private keys.
openssl rsautl #Encrypt and decrypt messages using RSA.
openssl enc #Encrypt and decrypt data with symmetric algorithms (e.g., AES).
openssl dgst #Generate hash values for files/messages.
```
1. Generate an RSA Private Key:
```bash
openssl genpkey -algorithm RSA -out private_key.pem -aes256
```
2. Encrypt a Message Using the RSA Key:
```bash
opensaal rsautl -encrypt -inkey public_key.pem -pubin -in message.txt -out
```
3. Decrypt a Message Using the RSA Key:
```bash
openssl rsautl -decrypt -inkey private_key.pem -in encrypted_message.bin
```
4. Generate a SHA-256 Hash of a File:
 ```bash
openssl dgst -sha256 filename.text
 ```
5. Checking FIPS Mode in OpenSSL (If Supported):
 ```bash
openssl version -fips
 ```
_____
## Experiment 3: To understand symmetric key cryptography by generating pseudo-random numbers, creating a DES key, performing encryption and decryption using DES, and verifying file integrity using an MD5 hash.

Here are the OpenSSL commands for generating pseudo-random numbers, creating DES keys, performing DES encryption and decryption, and generating MD5 hashes for file integrity.

1. Generate a Pseudo-Random DES Key:
```bash
openssl rand -hex 8 > des_key.key
```
This command generates a pseudo-random 64-bit (8-byte) key suitable for DES.

2. Encrypt a File Using DES:
```bash
openssl enc -des -in plaintext.txt -out encrypted_des.bin -K $(cat des_key) -iv $(cat des_key.key)
```
plaintext.txt is the file to be encrypted, and encrypted_des.bin is the output encrypted file. We use the generated DES key and an IV (initialization vector) of 64 bit.

3. Decrypt a File Using DES:
```bash
openssl enc -des -d -in encrypted_des.bin -out decrypted.txt -K $(cat des_key) -iv <des_key.key>
```
This command decrypts encrypted_des.bin back to its original form, saving it as decrypted.txt.

4. Generate an MD5 Hash for File Integrity:
```bash
openssl dgst -md5 plaintext.text
```
This command generates an MD5 hash of plaintext.txt. The hash can later be compared to verify that the file remains unchanged.
_____
## Experiment 4: To understand symmetric key cryptography by generating pseudo-random numbers, creating a DES key, performing encryption and decryption using DES, and verifying file integrity using an MD5 hash.

1. Symmetric Key Distribution Using NetCat:
```bash
nc -l -p 12345 > received_key.key
```
This command opens NetCat on port 12345 and saves incoming data to received_key.key.
```bash
nc <reciever_IP> 12345 <des_key.key
```
This command sends the contents of des_key.key (symmetric key) to the specified IP address and port, initiating the key transfer.

2. Symmetric Key Distribution Using Apache:
Step 1 : Place the key file (des_key.key) in a secured directory on the Apache server with restricted permissions.

Step 2 : Configure Apache to enable HTTPS (to encrypt the connection and protect the key during transfer).

Step 3 : The client can download the key file securely over HTTPS using:
```bash
wget https://<server_IP>/path/to/des_key.key
```
This ensures the key is transmitted over an encrypted channel

3. Key Compromise Analysis Using Wireshark:
Step 1 : Start a Wireshark capture on the network interface used for communication.

Step 2 : Monitor the traffic between the sender and receiver while the key is transmitted via NetCat (without encryption).

Step 3 : Examine the captured packets in Wireshark to see if the symmetric key appears in plaintext. This highlights the vulnerability of unencrypted channels.

Step 4 : Repeat the key transfer over HTTPS (with Apache) and capture the packets. Verify that the key is not visible in plaintext, showing how HTTPS secures the key exchange.
_____
## Experiment 5: To understand and implement Message Authentication Codes (MAC) to verify data integrity and authenticity, ensuring that the message is unaltered and from a legitimate sender.

HMAC Code
```python
import hmac
import hashlib

#Function to generate HMAC
def generate_hmac(key, message):
    #Create HMAC object with the key and SHA-256 hash function
    mac = hmac.new(key.encode(), message.encode(), hashlib.sha256)
    return mac.hexdigest()

# Function to verify HMAC
def verify_hmac(key, message, received_mac):
    #Generate MAC for comparison
    mac = hmac.new(key.encode(), message.encode(), hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), received_mac)

# Example usage
key = "supersecretkey"
message = "This is a confidential message."

# Generate HMAC for the message
mac = generate_hmac(key, message)
print("Generated MAC:", mac)

#Verify HMAC by simulating receiver's process
is_valid = verify_hmac(key, message, mac)
print("Is the message valid?", is_valid)
```
______
## Experiment 6: To understand the concept of digital signatures and implement the generation of a digital signature for a message, ensuring data integrity, authenticity, and non-repudiation.

```python
pip install cryptography

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

#Step 1: Generate RSA Private and Public Keys
private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
public_key = private_key.public_key()

#Step 2: Save the Private Key in PEM Format (optional)
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

with open("private_key.pem", "wb") as key_file:
    key_file.write(private_pem)

#Step 3: Save the Public Key in PEM Format (optional)
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open("public_key.pem", "wb") as key_file:
    key_file.write(public_pem)

# Step 4: Message to Sign
message = b"This is a secure message."

#Step 5: Generate the Digital Signature
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print("Digital Signature (in hex):", signature.hex())

#Step 6: Verify the Digital Signature
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("Signature is valid. Message authenticity and integrity verified.")
except Exception as e:
    print("Signature verification failed:", e)

```
______

## Experiment 7: To understand password auditing and cracking techniques using hashing algorithms and dictionary-based attacks, demonstrating the vulnerabilities of weak passwords.
```python
import hashlib
# Simulated hashed password (e.g., hash of "password123")
hashed_password = hashlib.sha256("password123".encode()).hexdigest()

# Dictionary of possible passwords
dictionary = ["password", "123456", "password123", "qwerty", "letmein"]

#Function to perform dictionary attack
def dictionary_attack(hashed_password, dictionary):
    for password in dictionary:
        #Hash each password in the dictionary and compare
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        print(f"Trying password: {password} -> Hash: {password_hash}")
    if password_hash == hashed_password:
        print("Password found:", password)
        return password
    print("Password not found in dictionary.")
    return None

#Running the dictionary attack
cracked_password = dictionary_attack(hashed_password, dictionary)
if cracked_password:
    print("Cracked Password:", cracked_password)
else:
    print("Failed to crack the password.")
```
____
## Experiment 8: To understand and simulate the basics of intrusion detection, learning how network-based intrusion detection systems (NIDS) detect suspicious activity and help protect systems from unauthorized access.

Procedure

1. Installing Snort (if not already installed):
- On a Linux system, install Snort using the following command:
```bash
sudo apt-get install snort
```
- Configure Snort by editing the configuration file (typically located at
/etc/snort/snort.conf).

2. Running Snort for Intrusion Detection:
- Run Snort in network intrusion detection mode to monitor real-time traffic:
```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
```
- The -A console option outputs alerts to the console, -q runs in quiet mode, -c specifies the configuration file, and -i specifies the network interface (replace eth0 with your
active network interface).

3. Simulating an Intrusion for Testing:
- To test Snort, you can simulate network traffic that triggers predefined Snort rules. For
example:
```bash
ping -c 4 www.example.com
```
- Snort rules can be added or modified to detect specific traffic patterns, such as ICMP (ping) requests or suspicious TCP packets.
  
4. Analysing Snort Alerts:
- Review Snort’s alert messages in the console to see if any activity has been flagged as suspicious or malicious.
- Check Snort’s log file (usually located in /var/log/snort/alert) to review details of each
detected intrusion.
____
## Experiment 9: To understand and implement steganography by hiding a secret message within an image file, demonstrating how data can be concealed within multimedia content for secure communication.
```python
from PIL import Image

# Function to encode a message into an image
def encode_message(image_path, message, output_path):
    try:
        # Load the image
        image = Image.open(image_path)
        encoded_image = image.copy()
        width, height = image.size
        
        # Add a delimiter to mark the end of the message
        message += "###"  # Add delimiter to end the message
        message_bits = ''.join([format(ord(char), '08b') for char in message])  # Convert message to bits
        data_index = 0

        # Loop through each pixel and modify the LSB to hide the message
        for y in range(height):
            for x in range(width):
                pixel = list(encoded_image.getpixel((x, y)))
                for n in range(3):  # Loop over RGB channels
                    if data_index < len(message_bits):
                        pixel[n] = pixel[n] & ~1 | int(message_bits[data_index])  # Modify LSB
                        data_index += 1
                encoded_image.putpixel((x, y), tuple(pixel))
                if data_index >= len(message_bits):  # Stop when the entire message is encoded
                    break
            if data_index >= len(message_bits):  # Stop when the entire message is encoded
                break

        # Save the encoded image
        encoded_image.save(output_path)
        print(f"Message encoded and saved as {output_path}")

    except Exception as e:
        print(f"Error encoding the message: {e}")

# Function to decode a message from an image
def decode_message(image_path):
    try:
        image = Image.open(image_path)
        width, height = image.size
        message_bits = []

        # Loop through each pixel to extract the LSB of the RGB values
        for y in range(height):
            for x in range(width):
                pixel = image.getpixel((x, y))
                for n in range(3):  # Loop over RGB channels
                    message_bits.append(pixel[n] & 1)  # Extract the LSB

        # Convert the bits to characters
        message = ''.join(chr(int(''.join(map(str, message_bits[i:i+8])), 2)) for i in range(0, len(message_bits), 8))

        # Extract the message before the delimiter
        message = message.split("###")[0]  # Extract the message up to the delimiter
        print("Decoded message:", message)

    except Exception as e:
        print(f"Error decoding the message: {e}")

# Example usage
image_path = "input_image.png"  # Path to input image
output_path = "encoded_image.png"  # Path to save encoded image
message = "Secret message here"

# Encode and decode the message
encode_message(image_path, message, output_path)
decode_message(output_path)
```
______
## Experiment 10: The aim of this experiment is to implement and understand the process of text encryption using popular cryptographic algorithms such as Caesar Cipher, RSA, and AES. This will help in understanding how cryptographic algorithms are applied in securing text data.

#### Caesar Cipher Implementation (Symmentric Key)
# Caesar Cipher Implementation (Symmetric Encryption)

```python
def caesar_cipher_encrypt(plain_text, shift):
    cipher_text = ""
    for char in plain_text:
        if char.isalpha():  # Encrypt only alphabetic characters
            shift_base = 65 if char.isupper() else 97
            cipher_text += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            cipher_text += char  # Non-alphabetic characters remain unchanged
    return cipher_text

def caesar_cipher_decrypt(cipher_text, shift):
    return caesar_cipher_encrypt(cipher_text, -shift)

# Example usage
message = "Hello World!"
shift_value = 3

encrypted_message = caesar_cipher_encrypt(message, shift_value)
decrypted_message = caesar_cipher_decrypt(encrypted_message, shift_value)

print("Original Message:", message)
print("Encrypted Message:", encrypted_message)
print("Decrypted Message:", decrypted_message)
```
### RSA Implementation (Asymmetric Encryption)

```python
# Install pycryptodome if not already installed (run this in a Jupyter cell)
# !pip install pycryptodome

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# Generate RSA keys (public and private)
def generate_rsa_keys():
    key = RSA.generate(2048)  # Generate RSA keys with 2048 bits
    private_key = key.export_key()  # Export the private key
    public_key = key.publickey().export_key()  # Export the public key
    return private_key, public_key

# Encrypt message using RSA public key
def rsa_encrypt(public_key, message):
    key = RSA.import_key(public_key)  # Import public key
    cipher = PKCS1_OAEP.new(key)  # Create cipher using public key
    encrypted_message = cipher.encrypt(message.encode())  # Encrypt the message
    return encrypted_message

# Decrypt message using RSA private key
def rsa_decrypt(private_key, encrypted_message):
    key = RSA.import_key(private_key)  # Import private key
    cipher = PKCS1_OAEP.new(key)  # Create cipher using private key
    decrypted_message = cipher.decrypt(encrypted_message)  # Decrypt the message
    return decrypted_message.decode()  # Decode back to string

# Example usage
private_key, public_key = generate_rsa_keys()  # Generate RSA keys
message = "Hello RSA Encryption!"  # The message to be encrypted
encrypted_message = rsa_encrypt(public_key, message)  # Encrypt the message
decrypted_message = rsa_decrypt(private_key, encrypted_message)  # Decrypt the message

# Output the results
print("Original Message:", message)
print("Encrypted Message:", encrypted_message)  # This will show as a byte object
print("Decrypted Message:", decrypted_message)  # This should match the original message
```
### AES Implementation (Symmetric Encryption)

```python
# Install pycryptodome if it's not already installed
# !pip install pycryptodome

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# AES encryption with CBC mode
def aes_encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    # Pad the plain text to make it a multiple of 16 bytes (AES block size)
    plain_text_padded = plain_text + (16 - len(plain_text) % 16) * ' '
    cipher_text = cipher.encrypt(plain_text_padded.encode())
    # Return the IV and ciphertext encoded in base64
    return base64.b64encode(cipher.iv + cipher_text).decode()

# AES decryption
def aes_decrypt(cipher_text, key):
    cipher_data = base64.b64decode(cipher_text)  # Decode base64 to get the cipher data
    iv = cipher_data[:16]  # Extract the IV
    cipher_text = cipher_data[16:]  # Extract the encrypted message
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Recreate cipher using IV
    decrypted_text = cipher.decrypt(cipher_text).decode().strip()  # Decrypt and remove padding
    return decrypted_text

# Example usage
key = get_random_bytes(16)  # AES key (128 bits, 16 bytes)
message = "Hello AES Encryption!"  # Original message

# Encrypt and decrypt the message
encrypted_message = aes_encrypt(message, key)
decrypted_message = aes_decrypt(encrypted_message, key)

# Output the results
print("Original Message:", message)
print("Encrypted Message:", encrypted_message)  # Encrypted message in base64
print("Decrypted Message:", decrypted_message)  # Decrypted message should match the original message
```
