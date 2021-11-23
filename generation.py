import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as padding
from cryptography.hazmat.primitives import hashes


class Generator:
    """
    Объект класса Generator выполняет генерацию и последующее хранение в качестве своих свойств набора
    ключей, необходимых для шифрования и дешифрования текста.
    """
    def __init__(self, iv: int, settings: dict):
        """
        Инициализирует экзмепляр класса Generator.
        Parameters
        ----------
            settings: dict
                словарь, который хранит пути к файлам, в которые необходимо записать
                полученные ключи.
        Attributes:
        ----------
            self.__ways: dict
                хранит пути к файлам, необходимым для работы шифровщика.
            self.__iv
                хранит значение вектора инициализации для шифрования.
            self.__symmetric_key
                хранит симметричный ключ шифрования.
            self.__rsa_keys
                хранит пару ключей, необходимых для ассимметричного шифрования.
            self.__result_key
                хранит симметричный ключ, зашифрованный ассиметричным шифром.
        """
        self.__ways = settings
        self.__iv = iv
        self.__symmetric_key = os.urandom(int((iv / 8)))
        self.__rsa_keys = rsa.generate_private_key(public_exponent=65537, key_size=2048,)
        self.__result_key = self.__rsa_keys.public_key().encrypt(self.__symmetric_key,
                                                                 padding.OAEP(
                                                                     mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                     algorithm=hashes.SHA256(),
                                                                     label=None))

    def write_public_key(self):
        """
        Записывает в файл открытый ключ ассиметричного шифрования.
        """
        with open(self.__ways['public_key'], 'wb') as public_out:
            public_out.write(self.__rsa_keys.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                       format=serialization.PublicFormat.SubjectPublicKeyInfo))

    def write_secret_key(self):
        """
        Записывает в файл закрытый ключ ассиметричного шифрования.
        """
        with open(self.__ways['secret_key'], 'wb') as private_out:
            private_out.write(self.__rsa_keys.private_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                            encryption_algorithm=serialization.NoEncryption()))

    def write_result_key(self):
        """
        Записывает в файл симметричный ключ, зашифрованный ассиметричным шифром (self.__result_key).
        """
        with open(self.__ways['symmetric_key'], 'wb') as key_file:
            key_file.write(self.__result_key)
