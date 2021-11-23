import os  # можно обойтись стандартным модулем
import logging

import argparse
import pickle
import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as apadding
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives import hashes

logging.basicConfig(level=logging.INFO)
gen_logger = logging.getLogger("Generation")
enc_logger = logging.getLogger("Encrypting")
dec_logger = logging.getLogger("Decrypting")
settings = {
    'initial_file': 'initial_file.txt',  # входной текст
    'encrypted_file': 'encrypted_file.txt',  # зашифрованный текст
    'decrypted_file': 'decrypted_file.txt',  # расшифрованный текст
    'symmetric_key': 'symmetric_key.txt',  # симметричный ключ
    'public_key': 'public_key.pem',  # открытый ключ
    'secret_key': 'secret_key.pem',  # закрытый ключ
}


def private_key():
    with open(ways['secret_key'], 'rb') as pem_in:
        private_bytes = pem_in.read()
        return load_pem_private_key(private_bytes, password=None, )


parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-gen', '--generation', help='Запускает режим генерации ключей', action="store_true")
group.add_argument('-enc', '--encryption', help='Запускает режим шифрования', action="store_true")
group.add_argument('-dec', '--decryption', help='Запускает режим дешифрования', action="store_true")

parser.add_argument('-iv', '--initializing_vector', type=int, choices=range(32, 449, 8),
                    help='Количество бит для генерации ключа', required=True)

args = parser.parse_args()
if args.generation:
    with open('settings.json') as json_file:
        ways = json.load(json_file)
    gen_logger.info("Generate symmetric key..")
    sym_key = os.urandom(int((args.initializing_vector / 8)))  # это байты
    gen_logger.info("Generate RSA keys..")
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    with open(ways['public_key'], 'wb') as public_out:
        public_out.write(keys.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    with open(ways['secret_key'], 'wb') as private_out:
        private_out.write(keys.private_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PrivateFormat.TraditionalOpenSSL,
                                             encryption_algorithm=serialization.NoEncryption()))
    gen_logger.info("Generate result key..")
    cr_sym_key = keys.public_key().encrypt(sym_key,
                                           apadding.OAEP(mgf=apadding.MGF1(algorithm=hashes.SHA256()),
                                                         algorithm=hashes.SHA256(),
                                                         label=None))
    with open(ways['symmetric_key'], 'wb') as key_file:
        key_file.write(cr_sym_key)
    gen_logger.info("Done")
else:
    with open('settings.json', 'r') as json_file:
        ways = json.load(json_file)
    if args.encryption:
        enc_logger.info("Loading the key")
        with open(ways['symmetric_key'], mode='rb') as key_file:
            symmetric_key = key_file.read()
        private_key = private_key()
        key = private_key.decrypt(symmetric_key,
                                  apadding.OAEP(mgf=apadding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                                label=None))
        with open(ways['initial_file'], 'rb') as f:
            data = f.read()
        padder = padding.ANSIX923(8).padder()
        padded_text = padder.update(data) + padder.finalize()
        iv = os.urandom(8)
        enc_logger.info("Encrypting initial text...")
        cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_text)
        data_info = [iv, encrypted_data]
        with open(ways['encrypted_file'], 'wb') as f:
            pickle.dump(data_info, f)
        enc_logger.info("Done")
    else:
        dec_logger.info("Loading the key")
        with open(ways['symmetric_key'], 'rb') as key_file:
            symmetric_key = key_file.read()
        private_key = private_key()
        key = private_key.decrypt(symmetric_key,
                                  apadding.OAEP(mgf=apadding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                                label=None))
        with open(ways['encrypted_file'], "rb") as f:
            data = pickle.load(f)
        iv = data[0]
        text_to_decrypt = data[1]
        dec_logger.info("Decrypting text")
        cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv))
        decrypt = cipher.decryptor()
        dc_data = decrypt.update(text_to_decrypt) + decrypt.finalize()
        unp = padding.ANSIX923(8).unpadder()
        decrypt_data = unp.update(dc_data)
        with open(ways['decrypted_file'], mode="wb") as f:
            f.write(decrypt_data)
        dec_logger.info("Done")
