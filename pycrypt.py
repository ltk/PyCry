import binascii
import click
import secrets
from simple_aes import encrypt, decrypt

@click.argument('path_or_message', nargs=-1)
@click.command()
@click.option('-k', '--key', default="random", prompt="Enter a key or press Enter to use a random key", hide_input=True, help="A key for encryption/decryption")

def main(path_or_message, key):
    path_or_message = ' '.join(path_or_message)

    if key == "random":
        key = secrets.token_hex(32)
    else:
        key = key.encode('utf-8').hex()

    ciphertext = encrypt(path_or_message, key)
    print(binascii.hexlify(ciphertext))
    print(binascii.b2a_base64(ciphertext))

if __name__ == '__main__':
    main()