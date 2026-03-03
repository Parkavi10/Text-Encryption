import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import os
import sys

def sha512_hash(file_path):
    h = hashlib.sha512()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()

def hybrid_encrypt(input_file, rsa_pub_path, encrypted_file):
    # Load RSA public key
    with open(rsa_pub_path, "rb") as f:
        recipient_key = RSA.import_key(f.read())

    # Generate random AES key and cipher
    aes_key = os.urandom(32)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    # AES GCM encryption
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    with open(input_file, "rb") as f:
        plaintext = f.read()
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

    # Write encrypted data
    with open(encrypted_file, "wb") as f:
        for x in (enc_aes_key, cipher_aes.nonce, tag, ciphertext):
            f.write(x)

    # Compute SHA512 of original file
    sha_value = sha512_hash(input_file)
    print(f"\n✅ Encryption successful!")
    print(f"Encrypted file saved as: {encrypted_file}")
    print(f"SHA512 hash of original file: {sha_value}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python encrypt_pdf_rsa_hybrid.py <input_file> <rsa_public.pem> <encrypted_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    rsa_pub_path = sys.argv[2]
    encrypted_file = sys.argv[3]
    hybrid_encrypt(input_file, rsa_pub_path, encrypted_file)
