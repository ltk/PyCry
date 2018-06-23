import secrets

def encrypt(plaintext, key):
    print("Encrypting:", plaintext)
    print("Using key:", key)
    expanded_key = _expand_key(key)
    print("expanded key length:", len(expanded_key))

def decrypt(ciphertext, key):
    print("Decrypting:", ciphertext)
    print("Using key:", key)

def _expand_key(initial_key):
    required_bytes = 240
    # TODO: expand the key
    print("starting key length", len(initial_key))
    print("type of key", type(initial_key))
    key_bytes = bytearray.fromhex(initial_key)
    print(key_bytes)
    print("Bytes in provided key:", len(key_bytes))

    provided_key_length = len(key_bytes)
    if (provided_key_length > required_bytes):
        return key_bytes[0:required_bytes]
    else:
        return key_bytes + secrets.token_bytes(required_bytes - provided_key_length)
