# PyCry
A just-for-fun, please-god-don't-actually-use-this encryption/decryption library using a from-scratch implementation of AES-256-ECB in Python! Also known as Lawson's final project for CS1300.

## TODOs
- clean up / comment pycry_aes.py
- Fix file path issue for file encryption/decryption
- Add project overview text here

## Running the Project

```
# Install Pipenv
brew install pipenv

# Install project dependencies
pipenv install

# Use the correct dependencies
pipenv shell

# Run the project
./pycry

```

## Various Notes
Unit tests for pycry_aes.py can be foundin pycry_aes_test.py. I originally had no plans to dive into automated testing for this project, but it ended up being absolutely critical for the development of the not-so-easily understood underlying AES functions.

For developing the main encrypt/decrypt tests, I wrote a little ruby script (reference-aes.rb)  to generate test cases (key, plaintext, ciphertext combinations) directly from OpenSSL.

One recurring challenge was that many example test cases/ AES calculators that I found online were not actually correct. In a couple cases I could actually replicate the results of data sets I found elsewhere by knowing introducing an error into the encryption process. 😬

### Challenges
encodings! Opting for hex most places

## Project Overview
TODO

## Project Notes
TODO