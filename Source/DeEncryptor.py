import base64
import sys
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def cls():
    print("\n\n\n\n\n")


class EncryptDecrypt:

    @staticmethod
    def KeyGenkdf():
        password_provided = input("\n\n please input the password!!! : ")
        password = password_provided.encode()
        salt = b'\x0b{kv\xef\xd1^_ikhd\xb3\xd0\xabQ'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=899765,
            backend=default_backend()
        )

        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def encfile(self):
        file_name = input("\n\n please enter a file name along with its path from current directory: ")

        if os.path.isfile(file_name):

            ukey = self.KeyGenkdf()
            f = Fernet(ukey)
            with open(file_name, 'rb') as fi:
                data = fi.read()
            enc_data = f.encrypt(data)

            enc_file_name = input("\n\n please enter a new file name to save the encoded file! Tip: use enc.(original "
                                  "file name): ")

            with open(enc_file_name, 'wb') as fo:
                fo.write(enc_data)

            fi.close()
            fo.close()

            print("\n\nfile successfully encoded and saved as: " + enc_file_name)

        else:
            decision = input("\n\nthe file does not exist!!! type \"exit\" to exit the program or any other key to "
                             "try again: ")
            if decision == "exit":
                sys.exit()
            else:
                self.encfile()

    def decfile(self):
        file_name = input("\n\n please enter a file name along with its path from current directory: ")

        if os.path.isfile(file_name):

            ukey = self.KeyGenkdf()
            f = Fernet(ukey)
            with open(file_name, 'rb') as fi:
                data = fi.read()
            dec_data = f.decrypt(data)

            dec_file_name = input("\n\n please enter a new file name to save the encoded file! Tip: use dec.(original "
                                  "file name): ")

            with open(dec_file_name, 'wb') as fo:
                fo.write(dec_data)

            fi.close()
            fo.close()

            print("\n\nfile successfully decoded and saved as: " + dec_file_name)

        else:
            decision = input("\n\nthe file does not exist!!! type \"exit\" to exit the program or any other key to "
                             "try again: ")
            if decision == "exit":
                cls()
                sys.exit()
            else:
                self.encfile()


def main():
    cls()
    print("\n\n Hello! Welcome to the DeEnCryptor by Dhwanil Thakkar. ")
    while True:
        print("\n please choose from the menu and  press the corresponding number: ")
        print("\n 1. Encrypt a File \n 2. Decrypt a File \n 3. Exit the program")
        choice = input("\n\nwhat do you wanna do? ")
        choice = str(choice)
        if choice == "1":
            EncytorDecryptor = EncryptDecrypt()
            EncytorDecryptor.encfile()
        elif choice == "2":
            EncytorDecryptor = EncryptDecrypt()
            EncytorDecryptor.decfile()
        elif choice == "3":
            cls()
            sys.exit(3)
        else:
            print("\n invalid input! please try again from (1-3) \n")


if __name__ == "__main__":
    main()
