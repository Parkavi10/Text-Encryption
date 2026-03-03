from Crypto.PublicKey import RSA

def generate_keys(bits=2048, privfile="rsa_private.pem", pubfile="rsa_public.pem"):
    key = RSA.generate(bits)
    private_pem = key.export_key()
    public_pem = key.publickey().export_key()
    with open(privfile, "wb") as f:
        f.write(private_pem)
    with open(pubfile, "wb") as f:
        f.write(public_pem)
    print(f"Generated {bits}-bit RSA keys: {privfile}, {pubfile}")

if __name__ == "__main__":
    generate_keys()
