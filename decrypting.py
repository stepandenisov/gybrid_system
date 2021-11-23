import pickle

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding as pad
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes


class Decryptor:
    """
    Объект класса Decryptor репрезентует дешифратор для текста с заданным ключом.
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
            self.__text_to_decrypt
                хранит текст, который необходим дешифровать.
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
        with open(self.__ways['encrypted_file'], "rb") as f:
            data = pickle.load(f)
        self.__iv = data[0]
        self.__text_to_decrypt = data[1]

    def decrypt(self):
        """
        Выполняет дешифрование данных, хранимых в файле по ключу с помощью алгоритма AES с
        последующей записью расшифрованного текста в новый файл.
        """
        cipher = Cipher(algorithms.AES(self.__key), modes.CBC(self.__iv))
        decrypt = cipher.decryptor()
        dc_data = decrypt.update(self.__text_to_decrypt) + decrypt.finalize()
        unp = padding.ANSIX923(16).unpadder()
        decrypt_data = unp.update(dc_data)
        with open(self.__ways['decrypted_file'], mode="wb") as f:
            f.write(decrypt_data)
