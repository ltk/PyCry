import click
import secrets

@click.argument('path_or_message', nargs=-1)
@click.command()
@click.option('-k', '--key', default="random", prompt="Enter a key or press Enter to use a random key", hide_input=True, help="A key for encryption/decryption")

def main(path_or_message, key):
    click.echo('Welcome to PyCrypt!')
    path_or_message = ' '.join(path_or_message)
    if key == "random":
        key = secrets.token_hex(32)

    click.echo('Encrypting: ' + path_or_message)
    click.echo("Using key: " + str(key))


if __name__ == '__main__':
    main()