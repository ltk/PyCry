import unittest
import base64
import binascii

from simple_aes import decrypt, encrypt, expand_key, inverse_mix_single_column, inverse_row_transposition, inverse_s_box, key_schedule_core, mix_single_column, row_transposition, s_box, string_to_bytearray

class TestSimpleAES(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None

    def test_decrypt(self):
        # Test vectors generated from my own Ruby script that performs encryption using OpenSSL (AES 256 - ECB mode)
        test_vectors = [
            ("1234561234561234561234561234561212345612345612345612345612345612", "12345612345612345612345612345612", "22dee2138884d55896336b4934afb46dcafc29cb65a05e813049c5de5d471d95246bd46cf63bd5e847a3befc03db1ab5"),
            ("1234561234561234561234561234561212345612345612345612345612345612", "hey", "3051fababce44080cd02d9d4f8999f96"),
            ("0000000000000000000000000000000000000000000000000000000000000000", "0", "41fba101d9c03aab56553372b31300b3"),
        ]

        for (key, plaintext, ciphertext) in test_vectors:
            self.assertEqual(decrypt(ciphertext, bytearray.fromhex(key)), bytearray(plaintext, encoding="utf-8"))

    def test_encrypt(self):
        # Test vectors generated from my own Ruby script that performs encryption using OpenSSL (AES 256 - ECB mode)
        test_vectors = [
            ("1234561234561234561234561234561212345612345612345612345612345612", "12345612345612345612345612345612", "22dee2138884d55896336b4934afb46dcafc29cb65a05e813049c5de5d471d95246bd46cf63bd5e847a3befc03db1ab5"),
            ("1234561234561234561234561234561212345612345612345612345612345612", "hey", "3051fababce44080cd02d9d4f8999f96"),
            ("0000000000000000000000000000000000000000000000000000000000000000", "0", "41fba101d9c03aab56553372b31300b3"),
        ]

        for (key, plaintext, ciphertext) in test_vectors:
            print("Expected:", bytearray.fromhex(ciphertext))
            print("Received:", encrypt(bytearray(plaintext, encoding="utf-8"), bytearray.fromhex(key))),
            self.assertEqual(encrypt(bytearray(plaintext, encoding="utf-8"), bytearray.fromhex(key)), bytearray.fromhex(ciphertext))

    def test_sbox_inversability(self):
        b = 0xc1
        self.assertEqual(inverse_s_box(s_box(b)), b)

    def test_row_transposition_inversability(self):
        b = bytearray([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
        self.assertEqual(inverse_row_transposition(row_transposition(b)), b)

    def test_string_to_bytearray(self):
        provided_string = "This is some text."
        expected_bytearray = bytearray(b"This is some text.")
        self.assertEqual(string_to_bytearray(provided_string), expected_bytearray)

    def test_expand_key_length(self):
        key = bytearray.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
        self.assertEqual(len(expand_key(key)), 240)

    def test_key_schedule_core(self):
        self.assertRaises(ValueError, key_schedule_core, b"000", 1)
        self.assertRaises(ValueError, key_schedule_core, b"00000", 1)
        self.assertEqual(key_schedule_core(bytearray(b"0000"), 1), bytearray(b'\x05\x04\x04\x04'))
        self.assertEqual(key_schedule_core(bytearray(b"0000"), 2), bytearray(b'\x06\x04\x04\x04'))
        self.assertEqual(key_schedule_core(bytearray(b"0000"), 3), bytearray(b'\x00\x04\x04\x04'))
        self.assertEqual(key_schedule_core(bytearray(b"0000"), 4), bytearray(b'\x0c\x04\x04\x04'))
        self.assertEqual(key_schedule_core(bytearray(b"fedc"), 1), bytearray(b'LC\xfb3'))
        self.assertEqual(key_schedule_core(bytearray(b"fedc"), 2), bytearray(b'OC\xfb3'))
        self.assertEqual(key_schedule_core(bytearray(b"fedc"), 3), bytearray(b'IC\xfb3'))
        self.assertEqual(key_schedule_core(bytearray(b"fedc"), 4), bytearray(b'EC\xfb3'))

    def test_expand_key(self):
        # Test vectors from http://www.samiam.org/key-schedule.html
        test_vectors = [
            ("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 62 63 63 63 62 63 63 63 62 63 63 63 62 63 63 63 aa fb fb fb aa fb fb fb aa fb fb fb aa fb fb fb 6f 6c 6c cf 0d 0f 0f ac 6f 6c 6c cf 0d 0f 0f ac 7d 8d 8d 6a d7 76 76 91 7d 8d 8d 6a d7 76 76 91 53 54 ed c1 5e 5b e2 6d 31 37 8e a2 3c 38 81 0e 96 8a 81 c1 41 fc f7 50 3c 71 7a 3a eb 07 0c ab 9e aa 8f 28 c0 f1 6d 45 f1 c6 e3 e7 cd fe 62 e9 2b 31 2b df 6a cd dc 8f 56 bc a6 b5 bd bb aa 1e 64 06 fd 52 a4 f7 90 17 55 31 73 f0 98 cf 11 19 6d bb a9 0b 07 76 75 84 51 ca d3 31 ec 71 79 2f e7 b0 e8 9c 43 47 78 8b 16 76 0b 7b 8e b9 1a 62 74 ed 0b a1 73 9b 7e 25 22 51 ad 14 ce 20 d4 3b 10 f8 0a 17 53 bf 72 9c 45 c9 79 e7 cb 70 63 85"),
            ("ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff", "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff e8 e9 e9 e9 17 16 16 16 e8 e9 e9 e9 17 16 16 16 0f b8 b8 b8 f0 47 47 47 0f b8 b8 b8 f0 47 47 47 4a 49 49 65 5d 5f 5f 73 b5 b6 b6 9a a2 a0 a0 8c 35 58 58 dc c5 1f 1f 9b ca a7 a7 23 3a e0 e0 64 af a8 0a e5 f2 f7 55 96 47 41 e3 0c e5 e1 43 80 ec a0 42 11 29 bf 5d 8a e3 18 fa a9 d9 f8 1a cd e6 0a b7 d0 14 fd e2 46 53 bc 01 4a b6 5d 42 ca a2 ec 6e 65 8b 53 33 ef 68 4b c9 46 b1 b3 d3 8b 9b 6c 8a 18 8f 91 68 5e dc 2d 69 14 6a 70 2b de a0 bd 9f 78 2b ee ac 97 43 a5 65 d1 f2 16 b6 5a fc 22 34 91 73 b3 5c cf af 9e 35 db c5 ee 1e 05 06 95 ed 13 2d 7b 41 84 6e de 24 55 9c c8 92 0f 54 6d 42 4f 27 de 1e 80 88 40 2b 5b 4d ae 35 5e"),
            ("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f", "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f a5 73 c2 9f a1 76 c4 98 a9 7f ce 93 a5 72 c0 9c 16 51 a8 cd 02 44 be da 1a 5d a4 c1 06 40 ba de ae 87 df f0 0f f1 1b 68 a6 8e d5 fb 03 fc 15 67 6d e1 f1 48 6f a5 4f 92 75 f8 eb 53 73 b8 51 8d c6 56 82 7f c9 a7 99 17 6f 29 4c ec 6c d5 59 8b 3d e2 3a 75 52 47 75 e7 27 bf 9e b4 54 07 cf 39 0b dc 90 5f c2 7b 09 48 ad 52 45 a4 c1 87 1c 2f 45 f5 a6 60 17 b2 d3 87 30 0d 4d 33 64 0a 82 0a 7c cf f7 1c be b4 fe 54 13 e6 bb f0 d2 61 a7 df f0 1a fa fe e7 a8 29 79 d7 a5 64 4a b3 af e6 40 25 41 fe 71 9b f5 00 25 88 13 bb d5 5a 72 1c 0a 4e 5a 66 99 a9 f2 4f e0 7e 57 2b aa cd f8 cd ea 24 fc 79 cc bf 09 79 e9 37 1a c2 3c 6d 68 de 36")
        ]

        for (key, expansion) in test_vectors:
            self.assertEqual(expand_key(bytearray.fromhex(key)), bytearray.fromhex(expansion))

    def test_inverse_mix_single_column(self):
        self.assertRaises(ValueError, inverse_mix_single_column, b"000")
        self.assertRaises(ValueError, inverse_mix_single_column, b"00000")

        # Test vectors from http://www.samiam.org/mix-column.html
        test_vectors = [
            ("db 13 53 45", "8e 4d a1 bc"),
            ("f2 0a 22 5c", "9f dc 58 9d"),
            ("01 01 01 01", "01 01 01 01"),
            ("d4 d4 d4 d5", "d5 d5 d7 d6"),
            ("2d 26 31 4c", "4d 7e bd f8")
        ]

        for (word, mixed) in test_vectors:
            word_ints = [int(byte) for byte in bytearray.fromhex(word)]
            self.assertEqual(inverse_mix_single_column(bytearray.fromhex(mixed)), word_ints)

    def test_mix_single_column(self):
        self.assertRaises(ValueError, mix_single_column, b"000")
        self.assertRaises(ValueError, mix_single_column, b"00000")

        # Test vectors from http://www.samiam.org/mix-column.html
        test_vectors = [
            ("db 13 53 45", "8e 4d a1 bc"),
            ("f2 0a 22 5c", "9f dc 58 9d"),
            ("01 01 01 01", "01 01 01 01"),
            ("d4 d4 d4 d5", "d5 d5 d7 d6"),
            ("2d 26 31 4c", "4d 7e bd f8")
        ]


        for (word, mixed) in test_vectors:
            mixed_ints = [int(byte) for byte in bytearray.fromhex(mixed)]
            self.assertEqual(mix_single_column(bytearray.fromhex(word)), mixed_ints)

if __name__ == '__main__':
    unittest.main()
