import binascii
import secrets

# For debugging:
# import code; code.interact(local=dict(globals(), **locals()))

def encrypt(plaintext, key):
    
    print("Encrypting:", plaintext)
    plaintext_bytes = bytearray.fromhex(plaintext.encode('utf-8').hex())
    expanded_key = _expand_key(key)
    print("Expanded key length:", len(expanded_key))
    print("Expanded key:", binascii.hexlify(expanded_key))
    block_length = 16
    state_blocks = []
    while len(plaintext_bytes) > 0:
        block = bytearray()
        for n in range(block_length):
            if len(plaintext_bytes) > 0:
                block.append(plaintext_bytes.pop(0))
        state_blocks.append(block)
    
    # Cryptographic Message Syntax padding
    if len(state_blocks[-1]) < block_length:
        num_padding_bytes = block_length - len(state_blocks[-1])
        for n in range(num_padding_bytes):
            state_blocks[-1].append(num_padding_bytes)

    print(state_blocks)

    i = 0
    while i < len(state_blocks):
        state_block = state_blocks[i]

        # Do all the things.

        # Rounds 2 - 15
        for round in range(0, 15):
            round_key = _round_key(expanded_key, round)

            if round > 0:
                # Byte Substitution
                state_block = bytearray(map(_s_box, state_block))

                # Row Transposition
                state_block = _row_transposition(state_block)

                if round != 14:
                    print('not last round')
                    # Column Mixing (not performed on the last round)
                
            # Key Block XOR
            state_block = bytearray(a ^ b for a, b in zip(state_block, round_key))
            

        # Finish doing all the things.

        state_blocks[i] = state_block
        i = i + 1
    
    print("Round", round, "key", binascii.hexlify(round_key))

def decrypt(ciphertext, key):
    print("Decrypting:", ciphertext)
    print("Using key:", key)

def _expand_key(initial_key):
    required_key_bytes = 32
    required_expansion_bytes = 240

    key_bytes = bytearray.fromhex(initial_key)
    print("Initial key:", binascii.hexlify(key_bytes))
    print("Initial key length:", len(key_bytes))
    if len(key_bytes) < required_key_bytes:
        # TODO: make this a custom exception, and rescue with friendly error message.
        raise ValueError("Need a longer key! Provided key was " + str(len(key_bytes)) + " bytes. " + str(required_key_bytes) + " bytes required.")

    key_bytes = key_bytes[0:required_key_bytes]

    i = 1
    while len(key_bytes) < required_expansion_bytes:
        # Generate 32 more bytes
        last_4 = key_bytes[-4:] 
        new_bytes = last_4
        new_bytes = _key_schedule_core(new_bytes, i)
        i = i + 1
        new_bytes = _four_byte_xor(key_bytes, new_bytes, required_key_bytes)
        key_bytes = key_bytes + new_bytes

        # Create 4 bytes 3 times for 12 more bytes
        for n in range(3):
            last_4 = key_bytes[-4:]
            new_bytes = last_4
            key_bytes = key_bytes + _four_byte_xor(key_bytes, new_bytes, required_key_bytes)

        # then add 4 more bytes
        last_4 = key_bytes[-4:]
        new_bytes = bytearray(map(_s_box, last_4))
        key_bytes = key_bytes + _four_byte_xor(key_bytes, new_bytes, required_key_bytes)

    return key_bytes[0:required_expansion_bytes]

def _key_schedule_core(word, i):
    # Rotate the output eight bits to the left
    word.append(word.pop(0))

    # Perform s-box substitution for each byte
    word = bytearray(map(_s_box, word))

    # xor the first byte with the rcon value for the current iteration
    word[0] = _rcon(i) ^ word[0]

    return word

def _s_box(byte):
    sbox = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]

    return sbox[byte]

def _rcon(i):
    rcon_table = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d]

    return rcon_table[i]

def _four_byte_xor(key, new_bytes, num_bytes_ago):
    start_index = (len(key) - num_bytes_ago)
    end_index = start_index + 4
    other_bytes = key[start_index:end_index]
    return bytearray(a ^ b for a, b in zip(new_bytes, other_bytes))

def _round_key(full_key, round):
    round_key_length = 16
    start_index = round * round_key_length
    end_index = start_index + round_key_length
    return full_key[start_index:end_index]

def _row_transposition(block):
    print("Pre trans", binascii.hexlify(block))
    rows = [bytearray(), bytearray(), bytearray(), bytearray()]
    for i in range(len(block)):
        row_index = i % 4
        rows[row_index].append(block[i])
    
    for row_index in range(len(rows)):
        row = rows[row_index]
        for rotations in range(row_index):
            row.append(row.pop(0))

    output = bytearray([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
    
    row_index = 0
    while row_index < len(rows):
        row = rows[row_index]
        byte_index = 0
        while byte_index < len(row):  
            byte = row[byte_index]          
            output[4 * byte_index + row_index] = byte
            byte_index = byte_index + 1
        row_index = row_index + 1

    print("Post trans", binascii.hexlify(output))
    return output

    # 1st row: 0 bytes to the left
    # 2nd row: 1 byte to the left
    # 3rd row: 2 bytes to the left
    # 4th row: 3 bytes to the left

    # fd 5a 07 d0 
    # aa 18 c6 de 
    # cb 5c 50 36 
    # c8 b7 73 f4

    # fd 5a 07 d0 
    # 18 c6 de aa 
    # 50 36 cb 5c 
    # f4 c8 b7 73

# Key Expansion Test Cases from http://www.samiam.org/key-schedule.html
# 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00:
# 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
# 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
# 62 63 63 63 62 63 63 63 62 63 63 63 62 63 63 63 
# aa fb fb fb aa fb fb fb aa fb fb fb aa fb fb fb 
# 6f 6c 6c cf 0d 0f 0f ac 6f 6c 6c cf 0d 0f 0f ac 
# 7d 8d 8d 6a d7 76 76 91 7d 8d 8d 6a d7 76 76 91 
# 53 54 ed c1 5e 5b e2 6d 31 37 8e a2 3c 38 81 0e 
# 96 8a 81 c1 41 fc f7 50 3c 71 7a 3a eb 07 0c ab 
# 9e aa 8f 28 c0 f1 6d 45 f1 c6 e3 e7 cd fe 62 e9 
# 2b 31 2b df 6a cd dc 8f 56 bc a6 b5 bd bb aa 1e 
# 64 06 fd 52 a4 f7 90 17 55 31 73 f0 98 cf 11 19 
# 6d bb a9 0b 07 76 75 84 51 ca d3 31 ec 71 79 2f 
# e7 b0 e8 9c 43 47 78 8b 16 76 0b 7b 8e b9 1a 62 
# 74 ed 0b a1 73 9b 7e 25 22 51 ad 14 ce 20 d4 3b 
# 10 f8 0a 17 53 bf 72 9c 45 c9 79 e7 cb 70 63 85

# ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff:
# ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
# ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
# e8 e9 e9 e9 17 16 16 16 e8 e9 e9 e9 17 16 16 16 
# 0f b8 b8 b8 f0 47 47 47 0f b8 b8 b8 f0 47 47 47 
# 4a 49 49 65 5d 5f 5f 73 b5 b6 b6 9a a2 a0 a0 8c 
# 35 58 58 dc c5 1f 1f 9b ca a7 a7 23 3a e0 e0 64 
# af a8 0a e5 f2 f7 55 96 47 41 e3 0c e5 e1 43 80 
# ec a0 42 11 29 bf 5d 8a e3 18 fa a9 d9 f8 1a cd 
# e6 0a b7 d0 14 fd e2 46 53 bc 01 4a b6 5d 42 ca 
# a2 ec 6e 65 8b 53 33 ef 68 4b c9 46 b1 b3 d3 8b 
# 9b 6c 8a 18 8f 91 68 5e dc 2d 69 14 6a 70 2b de 
# a0 bd 9f 78 2b ee ac 97 43 a5 65 d1 f2 16 b6 5a 
# fc 22 34 91 73 b3 5c cf af 9e 35 db c5 ee 1e 05 
# 06 95 ed 13 2d 7b 41 84 6e de 24 55 9c c8 92 0f 
# 54 6d 42 4f 27 de 1e 80 88 40 2b 5b 4d ae 35 5e

# 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f:
# 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 
# 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 
# a5 73 c2 9f a1 76 c4 98 a9 7f ce 93 a5 72 c0 9c 
# 16 51 a8 cd 02 44 be da 1a 5d a4 c1 06 40 ba de 
# ae 87 df f0 0f f1 1b 68 a6 8e d5 fb 03 fc 15 67 
# 6d e1 f1 48 6f a5 4f 92 75 f8 eb 53 73 b8 51 8d 
# c6 56 82 7f c9 a7 99 17 6f 29 4c ec 6c d5 59 8b 
# 3d e2 3a 75 52 47 75 e7 27 bf 9e b4 54 07 cf 39 
# 0b dc 90 5f c2 7b 09 48 ad 52 45 a4 c1 87 1c 2f 
# 45 f5 a6 60 17 b2 d3 87 30 0d 4d 33 64 0a 82 0a 
# 7c cf f7 1c be b4 fe 54 13 e6 bb f0 d2 61 a7 df 
# f0 1a fa fe e7 a8 29 79 d7 a5 64 4a b3 af e6 40 
# 25 41 fe 71 9b f5 00 25 88 13 bb d5 5a 72 1c 0a 
# 4e 5a 66 99 a9 f2 4f e0 7e 57 2b aa cd f8 cd ea 
# 24 fc 79 cc bf 09 79 e9 37 1a c2 3c 6d 68 de 36