import click
import secrets

@click.command()
@click.option('-k', '--key', default="random", prompt="Enter a key or press Enter to use a random key", hide_input=True, help="A key for encryption/decryption")

def main(key):
    click.echo('Welcome to PyCrypt!')
    if key == "random":
        key = secrets.token_bytes(32)

    click.echo("Key is: " + str(key))


if __name__ == '__main__':
    main()