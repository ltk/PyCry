import base64
import binascii
import click
import os
import secrets
import sys
from zipfile import ZipFile
from simple_aes import encrypt

@click.command()
@click.option('-p', '--path', type=click.Path(exists=False), default="", prompt="Enter path to file or directory to encrypt/decrypt. Leave blank to operate on a message", hide_input=False, help="Full filepath to the file or directory to encrypt")
@click.option('-m', '--message', default="", prompt="Enter a plaintext message to encrypt. Leave blank to operate on a file", hide_input=False, help="Full message to encrypt")
@click.option('-k', '--key', default="random", prompt="Enter a 32-byte hex-encoded encryption key, or press Enter to generate a random key", hide_input=True, help="A key for encryption (hex encoded)")

def main(path, message, key):
    if path == "" and message == "":
        raise Exception("You must provide either a filepath or a message for encryption.")

    if key == "random":
        # User has selected to have a key generated, so generate one!
        key = secrets.token_hex(32)
        input("Generated key is: `" + key + "`. Hit enter to hide key and continue with encryption.\r")
        # Move cursor up one line.
        sys.stdout.write("\033[F")
        # Clear line to remove key.
        sys.stdout.write("\033[K")
    # else:
        # TODO: error if not hex key
        # TODO: HEX encoding only
        # key = key.encode("utf-8").hex()

    key = bytearray.fromhex(key)

    print("Encrypting...")

    if path:
        zip_file_name = os.path.basename(path) + ".zip"
        encrypted_file_name = os.path.basename(path) + ".enc"
        paths = []

        if os.path.isdir(path):
            for root, directories, files in os.walk(path):
                for filename in files:
                    paths.append(os.path.join(root, filename))
        else:
            paths.append(path)

        with ZipFile(zip_file_name, "w") as zip_file:
            for file in paths:
                zip_file.write(file)

        zip_file = open(zip_file_name, "rb")
        plaintext = bytearray(zip_file.read())
        zip_file.close()
        os.remove(zip_file_name)

        ciphertext = encrypt(plaintext, key)
        encrypted_file = open(encrypted_file_name, "xb")
        encrypted_file.write(ciphertext)
        encrypted_file.close()

        print("Encryption complete: Encrypted file written to", encrypted_file_name)
    elif message:
        ciphertext = encrypt(bytearray(message, encoding="utf-8"), key)
        print("Encryption complete. Ciphertext is:")
        print(str(binascii.hexlify(ciphertext), encoding="utf-8"))
        
    # else:
    #     key = key.encode('utf-8').hex()

    # # ciphertext = encrypt(path_or_message, key)
    # print(base64.encodebytes(ciphertext))






    # print(ciphertext)
    # print(str(ciphertext, encoding="base64"))
    # print(binascii.hexlify(ciphertext))
    # print(binascii.b2a_base64(ciphertext))

if __name__ == '__main__':
    main()