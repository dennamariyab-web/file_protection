import os
from pathlib import Path
from getpass import getpass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


# Generate a 256-bit encryption key using PBKDF2
def generate_key(password, salt):

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000
    )

    return kdf.derive(password.encode())


# Encrypt a file
def encrypt_file(filename, password):

    try:
        with open(filename, "rb") as file:
            data = file.read()

        salt = os.urandom(16)
        nonce = os.urandom(12)

        key = generate_key(password, salt)

        aes = AESGCM(key)

        encrypted_data = aes.encrypt(nonce, data, None)

        output_file = str(filename) + ".enc"

        with open(output_file, "wb") as file:
            file.write(b"FPU1" + salt + nonce + encrypted_data)

        print("\nFile encrypted successfully!")
        print("Encrypted file:", output_file)

    except OSError as e:
        print("File error:", e)


# Decrypt a file
def decrypt_file(filename, password):

    try:
        with open(filename, "rb") as file:
            content = file.read()

        if len(content) < 48 or content[:4] != b"FPU1":
            print("Invalid encrypted file!")
            return

        salt = content[4:20]
        nonce = content[20:32]
        encrypted_data = content[32:]

        key = generate_key(password, salt)

        aes = AESGCM(key)

        decrypted_data = aes.decrypt(
            nonce,
            encrypted_data,
            None
        )

        output_file = str(filename)[:-4] + "_decrypted"

        with open(output_file, "wb") as file:
            file.write(decrypted_data)

        print("\nFile decrypted successfully!")
        print("Restored file:", output_file)
        print("Integrity verification: SUCCESS")

    except InvalidTag:
        print("Decryption failed!")
        print("Wrong password or file has been modified.")

    except OSError as e:
        print("File error:", e)


# Main program
def main():

    print("================================")
    print("     FILE PROTECTION UTILITY")
    print("================================")

    print("1. Encrypt File")
    print("2. Decrypt File")

    choice = input("\nEnter your choice: ")

    filename = input("Enter file path: ")

    password = getpass("Enter password: ")

    if not password:
        print("Password cannot be empty!")
        return

    if choice == "1":
        encrypt_file(filename, password)

    elif choice == "2":
        decrypt_file(filename, password)

    else:
        print("Invalid choice!")


main()
