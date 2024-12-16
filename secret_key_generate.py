import secrets

# Generate a random 32-byte hexadecimal string
secret_key = secrets.token_hex(32)

print(f"Generated Secret Key: {secret_key}")
