from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import plistlib

# Number of key pairs to generate
num_key_pairs = 2000

# Generate key pairs
key_pairs = []
for _ in range(num_key_pairs):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    key_pairs.append((private_key, public_key))

# Generate C source code for public keys
c_code = ""
for idx, (_, public_key) in enumerate(key_pairs):
    serialized_key = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    c_code += f"const unsigned char pubkey{idx + 1}[] = {serialized_key.hex()};\n"

# Generate .plist file for private keys
private_keys_plist = []
for idx, (private_key, _) in enumerate(key_pairs):
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_keys_plist.append({'id': idx + 1, 'private_key': private_key_pem.decode()})

# Write C source code to a file
with open('public_keys.c', 'w') as f:
    f.write(c_code)

# Write .plist file for private keys
with open('private_keys.plist', 'wb') as f:
    plistlib.dump(private_keys_plist, f)