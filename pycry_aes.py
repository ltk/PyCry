import base64
import binascii
import codecs
import secrets

# For debugging:
# import code; code.interact(local=dict(globals(), **locals()))

def string_to_bytearray(string):
    return bytearray(ord(character) for character in string)

def decrypt(ciphertext_bytes, key_bytes):
    # print("Decrypting:", ciphertext)
    block_length = 16
    # ciphertext_bytes = bytearray.fromhex(ciphertext)
    # key_bytes = string_to_bytearray(key)
    expanded_key = expand_key(key_bytes)

    state_blocks = []
    while len(ciphertext_bytes) > 0:
        block = bytearray()
        for n in range(block_length):
            if len(ciphertext_bytes) > 0:
                block.append(ciphertext_bytes.pop(0))
        state_blocks.append(block)

    # print("NEED TO BE STATE BLOCKS", [bytearray(b'\x0f\xa4\xff\x1fP$Mw\x83\x917\xc1\x19\xba\x1f2'), bytearray(b'\xe2)\n\xe4\xa4\x8b\x96\xdc\xbc\x17y\xe7\xfd\xa0Nj')])
    # print("DEC STATE BLOCKS", state_blocks)
    # DEC STATE BLOCKS: [bytearray(b'0fa4ff1f50244d77'), bytearray(b'839137c119ba1f32'), bytearray(b'e2290ae4a48b96dc'), bytearray(b'bc1779e7fda04e6a')]
    # ENC STATE BLOCKS: [bytearray(b'\x0f\xa4\xff\x1fP$Mw\x83\x917\xc1\x19\xba\x1f2'), bytearray(b'\xe2)\n\xe4\xa4\x8b\x96\xdc\xbc\x17y\xe7\xfd\xa0Nj')]

    # Get to this
    # state_blocks = [bytearray(b'\x0f\xa4\xff\x1fP$Mw\x83\x917\xc1\x19\xba\x1f2'), bytearray(b'\xe2)\n\xe4\xa4\x8b\x96\xdc\xbc\x17y\xe7\xfd\xa0Nj')]

    i = 0
    while i < len(state_blocks):
        state_block = state_blocks[i]

        # Do all the things.

        for round in range(14, -1, -1):
            # print("DEC ROUND", round)
            round_key = _round_key(expanded_key, round)
            # print("DEC ROUND KEY", round_key)

             # Key Block XOR
            state_block = bytearray(a ^ b for a, b in zip(state_block, round_key))

            # In the last round, we only xor
            if round > 0:
                if round != 14:
                    # print('not last round')
                    # Column Mixing (not performed on the last round)
                    state_block = inverse_mix_columns(state_block)

                # Row Transposition
                state_block = inverse_row_transposition(state_block)

                # Byte Substitution
                state_block = bytearray(map(inverse_s_box, state_block))

        # Finish doing all the things.

        state_blocks[i] = state_block
        i = i + 1
    
    # Remove padding
    last_block = state_blocks[-1]
    last_byte = last_block[-1]
    if int(last_byte <= 16):
        # print("last byte is", int(last_byte))
        for _ in range(int(last_byte)):
            last_block.pop()
    # print("last block len", len(last_block))
    # print("last block", state_blocks[-1])

    return bytearray([byte for block in state_blocks for byte in block])

#     out = m.xor_round_key(keys,10)
#   out = out.shift_rows_inv
#   out = out.sub_bytes_inv
#   9.times {|i|
#     out = out.xor_round_key(keys,9-i)
#     out = out.mix_cols_inv
#     out = out.shift_rows_inv
#     out = out.sub_bytes_inv
#   }
#   out = out.xor_round_key(keys,0)




def encrypt(plaintext, key_bytes):
    block_length = 16

    # print("Encrypting:", plaintext)
    # plaintext_bytes = bytearray(plaintext, encoding="utf-8")

    # OLD OLD
    # plaintext_bytes = bytearray.fromhex(plaintext.encode("utf-8").hex())
    plaintext_bytes = plaintext
    # if type(plaintext) is bytearray:
    # else:
    #     plaintext_bytes = string_to_bytearray(plaintext)
    # plaintext_bytes = bytearray(codecs.encode(plaintext.encode("ascii"), "hex"))

    # OLD
    # key_bytes = bytearray.fromhex(key.encode("utf-8").hex())
    # key_bytes = string_to_bytearray(key)
    # key_bytes = bytearray(key, encoding="utf-8")
    # key_bytes = bytearray(codecs.encode(key.encode("ascii"), "hex"))

    # New
    # key_bytes = base64.decodebytes(key)
    # key_bytes = base64.b64encode(key)

    expanded_key = expand_key(key_bytes)
    # print("Expanded key length:", len(expanded_key))
    # print("Expanded key:", binascii.hexlify(expanded_key))



    # print("PRE PADDING bytes are", binascii.hexlify(plaintext_bytes))
    padding_needed = (block_length - (len(plaintext_bytes) % block_length)) % block_length
    # print("padding needed", padding_needed)
    # Block padding, learnt from https://asecuritysite.com/encryption/padding
    for _ in range(padding_needed):
        # zero padding
        # plaintext_bytes.append(0)

        # Cryptographic message syntax padding
        plaintext_bytes.append(padding_needed)
    # print("POST PADDING bytes are", binascii.hexlify(plaintext_bytes))

    state_blocks = []
    while len(plaintext_bytes) > 0:
        block = bytearray()
        for n in range(block_length):
            if len(plaintext_bytes) > 0:
                block.append(plaintext_bytes.pop(0))
        state_blocks.append(block)

    i = 0
    while i < len(state_blocks):
        state_block = state_blocks[i]

        # Do all the things.

        for round in range(0, 15):
            # print("ENC ROUND", round)
            round_key = _round_key(expanded_key, round)
            # print("DEC ROUND KEY", round_key)

            # In the first round, we only xor
            if round > 0:
                # Byte Substitution
                state_block = bytearray(map(s_box, state_block))

                # Row Transposition
                state_block = row_transposition(state_block)

                if round != 14:
                    # print('not last round')
                    # Column Mixing (not performed on the last round)
                    state_block = mix_columns(state_block)
                
            # Key Block XOR
            state_block = bytearray(a ^ b for a, b in zip(state_block, round_key))
            

        # Finish doing all the things.

        state_blocks[i] = state_block
        i = i + 1

    # print("ENC STATE BLOCKS", state_blocks)
    
    return bytearray([byte for block in state_blocks for byte in block])

def expand_key(key_bytes):
    required_key_bytes = 32
    required_expansion_bytes = 240

    # key_bytes = bytearray.fromhex(initial_key)
    # print("Initial key:", binascii.hexlify(key_bytes))
    # print("Initial key length:", len(key_bytes))
    if len(key_bytes) < required_key_bytes:
        # TODO: make this a custom exception, and rescue with friendly error message.
        raise ValueError("Need a longer key! Provided key was " + str(len(key_bytes)) + " bytes. " + str(required_key_bytes) + " bytes required.")

    # Ignore extra key bytes
    key_bytes = key_bytes[0:required_key_bytes]

    i = 1
    while len(key_bytes) < required_expansion_bytes:
        # Generate 32 more bytes

        # First add 4 more bytes
        last_4 = key_bytes[-4:] 
        new_bytes = last_4
        new_bytes = key_schedule_core(new_bytes, i)
        i = i + 1
        new_bytes = _four_byte_xor(key_bytes, new_bytes, required_key_bytes)
        key_bytes = key_bytes + new_bytes
        # print("key bytes after " + str(i) + " iteration: " + str(binascii.hexlify(key_bytes)))

        # then create 4 bytes 3 times for 12 more bytes
        for n in range(3):
            last_4 = key_bytes[-4:]
            new_bytes = last_4
            key_bytes = key_bytes + _four_byte_xor(key_bytes, new_bytes, required_key_bytes)

        # then add 4 more bytes
        last_4 = key_bytes[-4:]
        new_bytes = bytearray(map(s_box, last_4))
        key_bytes = key_bytes + _four_byte_xor(key_bytes, new_bytes, required_key_bytes)

        # then create 4 bytes 3 times for 12 more bytes 
        for n in range(3):
            last_4 = key_bytes[-4:]
            new_bytes = last_4
            new_bytes = _four_byte_xor(key_bytes, new_bytes, required_key_bytes)
            key_bytes = key_bytes + new_bytes


    return key_bytes[0:required_expansion_bytes]

def key_schedule_core(word, i):
    if (len(word) != 4):
        raise ValueError("Words provided to `key_schedule_core` must be 4 bytes. Provided word was " + str(len(word)) + " bytes.")

    # Rotate the output eight bits to the left
    word.append(word.pop(0))

    # Perform s-box substitution for each byte
    word = bytearray(map(s_box, word))

    # xor the first byte with the rcon value for the current iteration
    word[0] = _rcon(i) ^ word[0]

    return word

def inverse_s_box(byte):
    # Learnt from http://www.samiam.org/s-box.html
    inverse_sbox = [0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d]

    return inverse_sbox[byte]

def s_box(byte):
    # Learnt from http://www.samiam.org/s-box.html
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

def inverse_row_transposition(block):
    # Learnt from https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#/media/File:AES-ShiftRows.svg
    # print("Pre trans", binascii.hexlify(block))
    rows = [bytearray(), bytearray(), bytearray(), bytearray()]
    for i in range(len(block)):
        row_index = i % 4
        rows[row_index].append(block[i])
    
    for row_index in range(len(rows)):
        row = rows[row_index]
        for _ in range(row_index):
            row.insert(0, row.pop())

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

    # print("Post trans", binascii.hexlify(output))
    return output

def row_transposition(block):
    # Learnt from https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#/media/File:AES-ShiftRows.svg
    # print("Pre trans", binascii.hexlify(block))
    rows = [bytearray(), bytearray(), bytearray(), bytearray()]
    for i in range(len(block)):
        row_index = i % 4
        rows[row_index].append(block[i])
    
    for row_index in range(len(rows)):
        row = rows[row_index]
        for _ in range(row_index):
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

    # print("Post trans", binascii.hexlify(output))
    return output

def mix_columns(block):
    columns = []
    while len(block) > 0:
        columns.append(block[0:4])
        
        for _ in range(4):
            block.pop(0)
     
    return bytearray([byte for column in map(mix_single_column, columns) for byte in column])

def inverse_mix_columns(block):
    columns = []
    while len(block) > 0:
        columns.append(block[0:4])
        
        for _ in range(4):
            block.pop(0)
     
    return bytearray([byte for column in map(inverse_mix_single_column, columns) for byte in column])

def inverse_mix_single_column(column):
    if (len(column) != 4):
        raise ValueError("Column provided to `inverse_mix_single_column` must be 4 bytes. Provided column was " + str(len(column)) + " bytes.")

    column = [int(byte) for byte in column]
    output = [None, None, None, None]
    a = [None, None, None, None]

    for c in range(4):
        a[c] = column[c]
    
    output[0] = gmul(a[0],14) ^ gmul(a[3],9) ^ gmul(a[2],13) ^ gmul(a[1],11)
    output[1] = gmul(a[1],14) ^ gmul(a[0],9) ^ gmul(a[3],13) ^ gmul(a[2],11)
    output[2] = gmul(a[2],14) ^ gmul(a[1],9) ^ gmul(a[0],13) ^ gmul(a[3],11)
    output[3] = gmul(a[3],14) ^ gmul(a[2],9) ^ gmul(a[1],13) ^ gmul(a[0],11)

    return [(value % 256) for value in output]

# def old_mix_single_column(column):
#     print("OLD")
#     # Learnt from http://www.samiam.org/mix-column.html
#     if (len(column) != 4):
#         raise ValueError("Column provided to `mix_single_column` must be 4 bytes. Provided column was " + str(len(column)) + " bytes.")

#     column = [int(byte) for byte in column]
#     output = [None, None, None, None]
#     a = [None, None, None, None]
#     b = [None, None, None, None]
#     h = None

#     for c in range(4):
#         a[c] = column[c]
#         h = column[c] & 0x80
#         b[c] = column[c] << 1
#         if h == 0x80:
#             b[c] ^= 0x1b
    
#     output[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]
#     output[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]
#     output[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]
#     output[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]

#     return [(value % 256) for value in output]

def mix_single_column(column):
    # Learnt from http://www.samiam.org/mix-column.html
    if (len(column) != 4):
        raise ValueError("Column provided to `mix_single_column` must be 4 bytes. Provided column was " + str(len(column)) + " bytes.")

    column = [int(byte) for byte in column]
    output = [None, None, None, None]
    a = [None, None, None, None]

    for c in range(4):
        a[c] = column[c]
    
    output[0] = gmul(a[0],2) ^ gmul(a[3],1) ^ gmul(a[2],1) ^ gmul(a[1],3)
    output[1] = gmul(a[1],2) ^ gmul(a[0],1) ^ gmul(a[3],1) ^ gmul(a[2],3)
    output[2] = gmul(a[2],2) ^ gmul(a[1],1) ^ gmul(a[0],1) ^ gmul(a[3],3)
    output[3] = gmul(a[3],2) ^ gmul(a[2],1) ^ gmul(a[1],1) ^ gmul(a[0],3)

    return [(value % 256) for value in output]

def gmul(a, b):
    # Learnt from http://www.samiam.org/galois.html
    p = 0
    h = None
    for c in range(8):
        if b & 1:
            p ^= a
        h = a & 0x80
        a <<= 1
        if h == 0x80:
            a ^= 0x1b
        b >>= 1
    return p