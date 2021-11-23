import os
import pickle

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding as pad
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes


class Encryptor:
    """
    Объект класса Encryptor репрезентует шифратор для текста с заданным ключом.
    """
    def __init__(self, settings: dict):
        """
        Инициализирует экзмепляр класса Encryptor.
        Parameters
        ----------
            settings: dict
                словарь, который хранит пути к файлам, необходимым для работы
                шифровщика.
        Attributes:
        ----------
            self.__ways: dict
                хранит пути к файлам, необходимым для работы шифровщика.
            self.__key
                хранит симметричный ключ шифрования.
            self.__iv
                хранит значение вектора инициализации для шифрования.
        """
        self.__ways = settings
        with open(self.__ways['symmetric_key'], mode='rb') as key_file:
            symmetric_key = key_file.read()
        with open(self.__ways['secret_key'], 'rb') as pem_in:
            private_bytes = pem_in.read()
            private_key = load_pem_private_key(private_bytes, password=None, )
        self.__key = private_key.decrypt(symmetric_key,
                                         pad.OAEP(mgf=pad.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                                  label=None))
        self.__iv = os.urandom(16)

    def encrypt(self):
        """
        Выполняет шифрование данных, хранимых в файле по ключу с помощью алгоритма AES с
        последующей записью вектора инициализации и зашифрованного текста в новый файл.
        """
        with open(self.__ways['initial_file'], 'rb') as f:
            data = f.read()
        padder = padding.ANSIX923(16).padder()
        padded_text = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.__key), modes.CBC(self.__iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_text)
        data_info = [self.__iv, encrypted_data]
        with open(self.__ways['encrypted_file'], 'wb') as f:
            pickle.dump(data_info, f)
