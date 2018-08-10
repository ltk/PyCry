# PyCry
A just-for-fun, please-god-don't-actually-use-this command-line encryption/decryption program using a from-scratch implementation of AES-256-ECB in Python!

Also known as Lawson Kurtz's final project for CSCI 1300.

## Running the Project
Install the following dependencies:

- Python 3 👉 `brew install python`
- inquirer 👉 `pip install inquirer`

Then, to run the program, `cd` into this directory and run `./pycry`. Follow the command line prompts.

## Main Notes
This program is essentially the complete version of the program I proposed. The one exception is that I excluded the automatic removal of plaintext files after the encryption process and encrypted files after the decryption process because it felt annoying after using it a few times.

One obvious area for improvement is error handling. Right now if an incorrect decryption key is provided, the user is usually shown a string encoding error. Also if a bad parameters are provided to the program (like a non-existant file path), the errors are currently not very informative to the user.

## Other Notes
Unit tests for pycry_aes.py can be foundin pycry_aes_test.py. I originally had no plans to dive into automated testing for this project, but it ended up being absolutely critical for the development of the not-so-easily understood underlying AES functions.

For developing the main encrypt/decrypt tests, I wrote a little ruby script (reference-aes.rb)  to generate test cases (key, plaintext, ciphertext combinations) directly from OpenSSL.

One recurring challenge was that many example test cases/ AES calculators that I found online were not actually correct. In a couple cases I could actually replicate the results of data sets I found elsewhere by knowing introducing an error into the encryption process. 😬

## Project Description
This program is a text/file encryption tool with a from-scratch implementation of AES-256 ECB encryption and decryption.

This project is just for me and me alone to satisfy a longstanding curiosity. It’s a bad idea to use self-implemented crypto, so the only goal here is to learn more about how AES works through the from-scratch implementation.

### Scope
The PyCry program consists of the following features:

#### Encrypting
##### Select a File, Directory, or Message
A command line interface allows the user to enter a secret message to encrypt, or choose a file or directory of files to encrypt.

##### Enter or Generate an Encryption Key
The user will enter their own symmetric encryption key, or allow the program to generate a random key which will be temporarily provided to the user for secure storage elsewhere.

##### Prepare Plaintext(s)
If a message was selected for encryption, start the encryption process (described below), otherwise, If a file or directory was chosen for encryption, zip the file(s) and proceed to the next step.

##### Key Expansion 
Expand the provided/generated encryption key via the Rijndael key schedule until we have a 240 bytes key.

##### Message Preparation
Split plaintext into 128 bit blocks, organized into 4 byte x 4 byte arrays.

##### Initial Key Block XOR
XOR each byte of the plaintext blocks with a 128 bit block of the expanded key.

##### Substitution and Permutation: (14 Rounds)
###### Byte Substitution
Substitute each individual byte with another from a lookup table (the Rijndael S-box).

###### Row Transposition
Cyclically shift each byte in each 4 byte x 4 byte state block to the left according to the following schedule.
- 1st row: 0 bytes to the left
- 2nd row: 1 byte to the left
- 3rd row: 2 bytes to the left
- 4th row: 3 bytes to the left

###### Column Mixing
Not performed on the 14th (last) round.

For each column of each 4 byte x 4 byte state block, combine all 4 bytes of the column using a [mathematical transformation](https://en.wikipedia.org/wiki/Rijndael_MixColumns) and replace the original 4 bytes with the 4 output bytes.

###### Key Block XOR
XOR each byte of the state blocks with the next 128 bit block of the expanded key.

##### Output Ciphertext
When the substitution and permutation rounds are complete, output the resulting ciphertext to the user if they provided a message for encryption, or write an encrypted version of the chosen files if a file or directory was chosen for encryption.

#### Decrypting
##### Select a File, Directory, or Message
A command line interface will allow the user to enter a secret message to decrypt, or choose a file or directory of files to decrypt.

##### Enter the Encryption Key
The user is prompted to enter a key to be used for decryption.

##### Decryption
The encryption process described above is reversed to recover the plaintext.

##### Output Plaintext
When the decryption is complete, output the resulting plaintext to the user if they provided a message for encryption, or write a decrypted version of the chosen files if a file or directory was chosen for decryption.
