# This script allows for the easy production cipher and plain texts using
# OpenSSL, to serve as a reference to build against.
# Particularly useful for setting up examples in pycry_aes_test.py.

require "openssl"

puts("Enter plaintext:")
plaintext = gets.chomp

puts("Enter key:")
key = [gets.chomp].pack("H*")

cipher = OpenSSL::Cipher.new("AES-256-ECB")
cipher.encrypt
cipher.key = key
cipher.padding = 1
encrypted = cipher.update plaintext
encrypted += cipher.final

puts ("Key (hex): #{key}")
puts ("Plaintext: #{plaintext}")
puts ("Encrypted (hex): #{encrypted.unpack('H*').first}")
