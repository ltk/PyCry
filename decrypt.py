import base64
import binascii
import click
import os
from zipfile import ZipFile
from simple_aes import decrypt

@click.command()
@click.option('-p', '--path', type=click.Path(exists=False), default="", prompt="Enter path to file or directory to encrypt/decrypt. Leave blank to operate on a message.", hide_input=False, help="Full filepath to the file or directory to encrypt or decrypt")
@click.option('-m', '--message', default="", prompt="Enter a plaintext message to encrypt, or a ciphertext to decrypt. Leave blank to operate on a file.", hide_input=False, help="Full filepath to the file or directory to encrypt or decrypt")
@click.option('-k', '--key', default="random", prompt="Enter a key", hide_input=True, help="A key for encryption/decryption")

def main(path, message, key):
    # print("key is", key)
    # path_or_message = ' '.join(path_or_message)

    if not key or key == "":
       print("ERROR! Provide a key for decryption.") 

    key = bytearray.fromhex(key)

    if path:
        print("File mode: Path is", path)
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
        # Open and write zip file
        # Unzip
        # Remove zip file
        os.remove(zip_file_name)
        encrypted_file.close()
        print("Decription complete.")
    elif message:
        print("Message mode: Message is", message)
        plaintext = decrypt(message, key)
        print("Decryption complete:")
        print(plaintext)
    else:
        print("ERROR! Nothing provided.")

if __name__ == '__main__':
    main()