import logging
import argparse
import json

import generation
import encrypting
import decrypting

logging.basicConfig(level=logging.INFO)
gen_logger = logging.getLogger("Generation")
enc_logger = logging.getLogger("Encrypting")
dec_logger = logging.getLogger("Decrypting")

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-gen', '--generation', help='Запускает режим генерации ключей', action="store_true")
group.add_argument('-enc', '--encryption', help='Запускает режим шифрования', action="store_true")
group.add_argument('-dec', '--decryption', help='Запускает режим дешифрования', action="store_true")

parser.add_argument('-iv', '--initializing_vector', type=int, choices=range(32, 449, 8),
                    help='Количество бит для генерации ключа', required=True)

args = parser.parse_args()

with open('settings.json', 'r') as json_file:
    ways = json.load(json_file)

if args.generation:
    gen = generation.Generator(args.initializing_vector, ways)
    gen.write_public_key()
    gen.write_secret_key()
    gen.write_result_key()
else:
    if args.encryption:
        enc = encrypting.Encryptor(ways)
        enc.write_encrypt_data()
    else:
        dec = decrypting.Decryptor(ways)
        dec.write_decrypt_data()
