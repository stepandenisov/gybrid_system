import os
import pickle

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding as pad
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes


class Encryptor:
    def __init__(self, settings):
        self.__ways = settings
        with open(self.__ways['symmetric_key'], mode='rb') as key_file:
            symmetric_key = key_file.read()
        with open(self.__ways['secret_key'], 'rb') as pem_in:
            private_bytes = pem_in.read()
            private_key = load_pem_private_key(private_bytes, password=None, )
        self.__key = private_key.decrypt(symmetric_key,
                                         pad.OAEP(mgf=pad.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                                  label=None))
        self.__iv = os.urandom(8)

    @property
    def iv(self):
        return self.__iv

    def encrypt(self):
        with open(self.__ways['initial_file'], 'rb') as f:
            data = f.read()
        padder = padding.ANSIX923(8).padder()
        padded_text = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.Blowfish(self.__key), modes.CBC(self.__iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_text)
        return [self.iv, encrypted_data]

    def write_encrypt_data(self):
        with open(self.__ways['encrypted_file'], 'wb') as f:
            pickle.dump(self.encrypt(), f)
