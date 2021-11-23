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
parser.add_argument('-iv', '--initializing_vector', type=int, choices=[128, 192, 256],
                    help='Количество бит для генерации ключа', required=True)
args = parser.parse_args()

with open('settings.json', 'r') as json_file:
    ways = json.load(json_file)

if args.generation:
    gen_logger.info("Generation of keys")
    gen = generation.Generator(args.initializing_vector, ways)
    gen_logger.info("Write public key..")
    gen.write_public_key()
    gen_logger.info("Write secret key..")
    gen.write_secret_key()
    gen_logger.info("Write symmetric result key..")
    gen.write_result_key()
    gen_logger.info("Done")
else:
    if args.encryption:
        enc = encrypting.Encryptor(ways)
        enc_logger.info("Encryption..")
        enc.encrypt()
        enc_logger.info("Done")
    else:
        dec = decrypting.Decryptor(ways)
        dec_logger.info("Decryption..")
        dec.decrypt()
        dec_logger.info("Done")
