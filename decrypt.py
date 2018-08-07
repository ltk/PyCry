import base64
import binascii
import click
import os
from zipfile import ZipFile
from simple_aes import decrypt

@click.command()
@click.option('-p', '--path', type=click.Path(exists=False), default="", prompt="Enter path to .enc file decrypt. Leave blank to decrypt a string ciphertext.", hide_input=False, help="Full filepath to the file to decrypt")
@click.option('-m', '--message', default="", prompt="Enter the ciphertext to decrypt. Leave blank to operate on a file.", hide_input=False, help="Full ciphertext decrypt")
@click.option('-k', '--key', prompt="Enter a hex-encoded decryption key", hide_input=True, help="A key for encryption/decryption")

def main(path, message, key):
    try:
        key = bytearray.fromhex(key)
    except ValueError:
        raise Exception("Provided key must be hexadecimal encoded.")

    if len(key) < 32:
        raise Exception("Provided key must be 32 bytes. (" + str(len(key)) + " byte key provided)")

    if path:
        if path[-4:] != ".enc":
            raise Exception("Provided path must be an encrypted archive (a file with a .enc extension).")

        decrypted_file_name = os.path.basename(path)[0:-4] # Remove the `.enc`
        zip_file_name = decrypted_file_name + ".zip"
        encrypted_file = open(path, "rb")
        ciphertext = bytearray(encrypted_file.read())
        plaintext = decrypt(ciphertext, key)
        zip_file = open(zip_file_name, "xb")
        zip_file.write(plaintext)
        zip_file.close()

        with ZipFile(zip_file_name, "r") as zip:
            zip.extractall()

        os.remove(zip_file_name)
        encrypted_file.close()
        print("Decryption complete.")
    elif message:
        plaintext = decrypt(bytearray.fromhex(message), key)
        print("Decryption complete. Plaintext is:")
        print(str(plaintext, encoding="utf-8"))
    else:
        raise Exception("You must provide either a filepath or a ciphertext for decryption.")

if __name__ == '__main__':
    main()