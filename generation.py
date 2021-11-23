import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as padding
from cryptography.hazmat.primitives import hashes


class Generator:

    def __init__(self, iv, settings):
        self.__ways = settings
        self.__iv = iv
        self.__symmetric_key = os.urandom(int((iv / 8)))
        self.__rsa_keys = rsa.generate_private_key(public_exponent=65537, key_size=4096,)
        self.__result_key = self.__rsa_keys.public_key().encrypt(self.__symmetric_key,
                                                                 padding.OAEP(
                                                                     mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                     algorithm=hashes.SHA256(),
                                                                     label=None))

    def write_public_key(self):
        with open(self.__ways['public_key'], 'wb') as public_out:
            public_out.write(self.__rsa_keys.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                       format=serialization.PublicFormat.SubjectPublicKeyInfo))

    def write_secret_key(self):
        with open(self.__ways['secret_key'], 'wb') as private_out:
            private_out.write(self.__rsa_keys.private_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                            encryption_algorithm=serialization.NoEncryption()))

    def write_result_key(self):
        with open(self.__ways['symmetric_key'], 'wb') as key_file:
            key_file.write(self.__result_key)
