import bcrypt
from passlib import pwd
from cryptography.fernet import Fernet, InvalidToken
import base64
from cs50 import SQL
import sys
import re
import cowsay
import random
from tabulate import tabulate
import hashlib


class PasswordManager:
    """This is the password manager class """
    # the sql data base for the password manager
    db = SQL("sqlite:///passManager.db")
    # password and salt inisializing
    _password = ""
    _salt = ""

    @classmethod
    def register(cls)-> None:
        """
        Class method that registers the user in the database and assigns the password and salt
        :param: it takes just the cls parameter
        :return: None
        """
        while True:
            inputPass = input("Register\nEnter the master password: ").strip()
            if re.search(r"[^@]+.+[^@]+", inputPass):
                cls._password = inputPass.encode()
                break
            else:
                print("Invalid Password")

        hash = cls.master_pass_hash()
        while True:
            cls._salt = input("Enter the Salt, chars of letters and numbers: ")
            if re.search("^[a-zA-Z0-9]+$", cls._salt):
                cls._salt = cls._salt.encode()
                break
            else:
                print("Invalid salt!")
                continue
        cls.db.execute("INSERT INTO user(hash) VALUES (?)", hash)

    @classmethod
    def master_pass_hash(cls)-> bytes:
        """
        Hashes the master password by using bcrypt
        :retrun: the hashed password
        :rtype: bytes
        """
        normal_hash: bytes = bcrypt.hashpw(cls._password, bcrypt.gensalt())
        return normal_hash

    @classmethod
    def sign_in(cls):
        """Signs in the user to the password manager"""
        user = cls.db.execute("SELECT * FROM user")
        row = user[0]
        user_hash = row["hash"]

        password = input("Sign in\nEnter password: ").encode()

        if not bcrypt.checkpw(password, user_hash):
            sys.exit("Wrong password!")
        else:
            cls._password = password

            while True:
                cls._salt = input("Enter the Salt, chars of letters and numbers: ")

                if re.search("^[a-zA-Z0-9]+$", cls._salt):
                    cls._salt = cls._salt.encode()
                    break
                else:
                    print("Invalid salt!")
                    continue

    @classmethod
    def add_pass(cls):
        """ Adds a password to the data base after it encrypt it"""
        while True:
            try:
                name = input("Enter the name of the password: ")
                site_password = input(
                    "Enter the password, if nothing provided we'll generate one for you: ")

                if site_password == "":
                    site_password = cls.generate_pass()
                    site_password = cls.encrypt(site_password)
                else:
                    site_password = cls.encrypt(site_password)

                cls.db.execute("INSERT INTO passwords (name, password) VALUES (?, ?)",
                               name, site_password)
                print("Password added")
            except KeyboardInterrupt:
                print()
                break
            else:
                print("Enter another password or press CTRL + C: ")

    @classmethod
    def get_pass(cls):
        """retrive a password from the data base and decrypt it"""
        while True:
            try:
                name = input("Enter the Account name: ")
                passwords = cls.db.execute(
                    "SELECT * FROM passwords WHERE name LIKE ?", "%" + name + "%")

                if len(passwords) == 0:
                    print("NO MATCH FOUND!")
                    continue

                try:
                    password = cls.decrypt(passwords[0]["password"])
                except InvalidToken:
                    print("YOU DIDN'T ENTER THE RIGHT SALT!")
                    continue
                except KeyboardInterrupt:
                    print("\n")
                    break
                else:
                    getattr(cowsay, random.choice(cowsay.char_names))(f"Account: {passwords[0]['name']}\nPassword: {password}")

            except KeyboardInterrupt:
                print()
                break
            else:
                print("Get another password or press CTRL + C: ")

    @classmethod
    def encrypt(cls, plain: str) -> bytes:
        """Encrypts the password
        :param name: the plain text of the password
        :type name: str
        :return: The encrypyed password
        :rtype: bytes
        """
        key = cls.get_key()
        f = Fernet(key)

        cipher: bytes = f.encrypt(plain.encode())

        return cipher

    @classmethod
    def decrypt(cls, cipher: bytes) -> str:
        """
        Dectypts the ciphered password
        :param cipher: the encrypted password
        :type cipher: bytes
        :return: the decrypted password
        :rtype: string
        """
        key = cls.get_key()
        f = Fernet(key)
        plain = f.decrypt(cipher).decode()
        return plain

    @classmethod
    def get_key(cls) -> bytes:
        """ generates the encryption and decryption key
        :return: key
        :rtype: bytes
        """
        hash = cls.master_pass_key_hash()
        key: bytes = hash[:32].encode()
        key = base64.urlsafe_b64encode(key)
        return key

    @classmethod
    def master_pass_key_hash(cls) -> str:
        """
        Hashes the master password but returns the same hash every time so it will be used to extract the key
        :return: the hashed password
        :rrype: string
        """
        data = cls._password + cls._salt
        hash_object = hashlib.sha256()
        hash_object.update(data)
        hash = hash_object.hexdigest()

        return hash

    @staticmethod
    def generate_pass() -> str:
        """Generates random password"""
        password = pwd.genword(entropy="secure", length=20, charset="ascii_72")
        return password

    @classmethod
    def passwords_list(cls) -> list:
        """Returns a list of the names of the passwords in the database"""
        list = cls.db.execute("SELECT name FROM passwords")
        names = [site["name"] for site in list]
        return names

    @classmethod
    def delete_password(cls) -> None:
        """Deletes a password from the database"""
        while True:
            try:
                password = input("Enter the name of the password you want to delete OR press CTRL + C to stop: ")
                cls.db.execute("DELETE FROM passwords WHERE name LIKE ?", "%" + password + "%")
                print("Password Deleted")

            except KeyboardInterrupt:
                print()
                break


def main():
    db = SQL("sqlite:///passManager.db")

    user = db.execute("SELECT * FROM user")

    # if there was no user in the data base then register one
    if len(user) == 0:
        PasswordManager.register()
    else:
        # else then sign in
        PasswordManager.sign_in()

    # sort the list of passwords in the database
    data: list = sorted([[password] for password in PasswordManager.passwords_list()])
    # print a formated table of   the passwords
    print(tabulate(data, headers=["ALL PASSWORDS"], tablefmt="grid"))

    # Keep taking argument for the user until he inturrpet the program
    while True:
        try:
            argument = input("Add password --add\nOR Get password --get\nOR --del for Deleting password\nOR press CTRL + C to exit: ").strip().lower()
        except KeyboardInterrupt:
            print()
            break
        else:
            if argument == "--add":
                PasswordManager.add_pass()
                # print the passwords table
                data = sorted([[password] for password in PasswordManager.passwords_list()])
                print(tabulate(data, headers=["ALL PASSWORDS"], tablefmt="grid"))
            elif argument == "--get":
                PasswordManager.get_pass()
                # print the passwords table
                data = sorted([[password] for password in PasswordManager.passwords_list()])
                print(tabulate(data, headers=["ALL PASSWORDS"], tablefmt="grid"))
            elif argument == "--del":
                PasswordManager.delete_password()
                # print the passwords table
                data = sorted([[password] for password in PasswordManager.passwords_list()])
                print(tabulate(data, headers=["ALL PASSWORDS"], tablefmt="grid"))


# These are the same functions in the PasswordManager class but i wrote it here for testing
def encrypt(plain: str) -> bytes:
    key = get_key()
    f = Fernet(key)

    cipher = f.encrypt(plain.encode())

    return cipher


def decrypt(cipher: str) -> str:
    key = get_key()
    f = Fernet(key)
    plain = f.decrypt(cipher).decode()
    return plain


def get_key() -> bytes:
    hash = master_pass_key_hash("test")
    key: bytes = hash[:32].encode()
    key = base64.urlsafe_b64encode(key)
    return key


def master_pass_key_hash(password: str) -> str:
    salt = "secret"
    data = password.encode() + salt.encode()
    hash_object = hashlib.sha256()
    hash_object.update(data)
    hash = hash_object.hexdigest()

    return hash


if __name__ == "__main__":
    main()
