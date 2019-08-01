import base64
import sys
import os
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Encryption:
    def __init__(self, password):
        self.password = bytes(str(password), 'utf-8')

    def get_kek(self, salt):

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        # derive key from the user password
        dk = kdf.derive(self.password)

        # base64 encode for use with Fernet
        key = base64.urlsafe_b64encode(dk)

        return key

    @classmethod
    def get_salt(self):
        return os.urandom(16)

    def encrypt(self, data):
        key = Fernet.generate_key()
        data = bytes(data, 'utf-8')
        f = Fernet(key)

        self.token = f.encrypt(data)
        self.encrypt_cek(key)

    def encrypt_cek(self, cek):
        salt = Encryption.get_salt()
        kek = self.get_kek(salt)
        f = Fernet(kek)

        self.encrypted_cek = f.encrypt(cek)
        self.salt = salt

    def decrypt(self, token, encrypted_cek, salt):
        cek = self.decrypt_cek(encrypted_cek, salt)

        try:
            f = Fernet(cek)
            decrypted = f.decrypt(token)
        except InvalidToken:
            decrypted = b''

        return decrypted

    def decrypt_cek(self, encrypted_cek, salt):
        try:
            key = self.get_kek(salt)
            f = Fernet(key)
            cek = f.decrypt(encrypted_cek)
        except InvalidToken:
            cek = b''

        return cek
