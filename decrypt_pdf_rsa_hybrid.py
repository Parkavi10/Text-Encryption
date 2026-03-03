import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import sys

def sha512_hash(file_path):
    h = hashlib.sha512()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()

def hybrid_decrypt(encrypted_file, rsa_priv_path, out_file):
    # Load encrypted data
    with open(encrypted_file, "rb") as f:
        data = f.read()

    # Compute SHA512 of encrypted file (always printed)
    enc_sha = sha512_hash(encrypted_file)
    print(f"\nSHA512 hash of encrypted file: {enc_sha}")

    try:
        # Extract parts based on known lengths
        enc_aes_key = data[:256]
        nonce = data[256:272]
        tag = data[272:288]
        ciphertext = data[288:]

        # Load RSA private key
        with open(rsa_priv_path, "rb") as f:
            rsa_priv = RSA.import_key(f.read())
        cipher_rsa = PKCS1_OAEP.new(rsa_priv)

        # Decrypt AES key
        aes_key = cipher_rsa.decrypt(enc_aes_key)

        # AES-GCM decryption
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

        # Write decrypted content
        with open(out_file, "wb") as f:
            f.write(plaintext)

        dec_sha = sha512_hash(out_file)
        print(f"\n✅ Decryption successful!")
        print(f"Decrypted file saved as: {out_file}")
        print(f"SHA512 hash of decrypted file: {dec_sha}")

    except Exception as e:
        print(f"\n❌ Decryption failed: {e}")
        print("File may have been modified or encrypted with a different key. decrypted file hash value is:")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python decrypt_pdf_rsa_hybrid.py <encrypted_file> <rsa_private.pem> <output_file>")
        sys.exit(1)

    hybrid_decrypt(sys.argv[1], sys.argv[2], sys.argv[3])


