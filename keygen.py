# Kii-U-Generator by dojafoja
# License: MIT
# https://github.com/dojafoja/Kii-U-Generator
#
# Modified from original code

from hashlib import pbkdf2_hmac, md5
import binascii
import sys
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def get_secret():
    # TODO: generate this 'secret' instead of hardcoding it.
    # Although, I'm pretty sure there's nothing wrong with including
    # it, since Nintendo generated it on the fly and never included
    # it in binary form in any way that I'm aware of. Only their
    # code that generated this would be copyrighted, not the string/number itself.
    return 'fd040105060b111c2d49'

def generate_key(title_id, pwd):
    # remove 00 padding from title id
    title_id = title_id[2:]

    # get secret string, append title id, and convert to binary string
    secret = binascii.unhexlify(get_secret() + title_id)

    # get md5 hash of secret
    hashed_secret = md5(secret).digest()
    
    # key is a pbkdf2 hash with sha1 base using hashed_secret as salt and 20 iterations
    non_encrypted_key = pbkdf2_hmac('sha1', pwd.encode(), hashed_secret, 20, 16)

    # return as hexstring
    return binascii.hexlify(non_encrypted_key)


def encrypt_title_key(title_id, title_key, ckey):
    # pad title id with trailing zeroes
    title_id += '0000000000000000'
    title_id = binascii.unhexlify(title_id)
    ckey = binascii.unhexlify(ckey)
    title_key = binascii.unhexlify(title_key)
    encryptor = Cipher(algorithms.AES(ckey), modes.CBC(title_id), backend=default_backend()).encryptor()
    encrypted_title_key = encryptor.update(title_key) + encryptor.finalize()

    # return as hexstring
    return binascii.hexlify(encrypted_title_key)

def get_ckey():
    with open('ckey.json', 'r') as f:
        return json.load(f)['commonkey']

def verify_ckey(ckey):
    #if md5(ckey.upper().encode()).hexdigest() == '35ac5994972279331d97094fa2fb97fc':
    #    return True
    return True

def encrypt_guess(title_id, pwd, ckey):
    title_id_a = title_id[2:]
    secret = binascii.unhexlify(get_secret() + title_id_a)
    hashed_secret = md5(secret).digest()
    non_encrypted_key = pbkdf2_hmac('sha1', pwd.encode(), hashed_secret, 20, 16)
    title_id += '0000000000000000'
    title_id = binascii.unhexlify(title_id)
    ckey = binascii.unhexlify(ckey)
    encryptor = Cipher(algorithms.AES(ckey), modes.CBC(title_id), backend=default_backend()).encryptor()
    encrypted_title_key = encryptor.update(non_encrypted_key) + encryptor.finalize()
    return (non_encrypted_key, binascii.hexlify(encrypted_title_key).decode())

def main(tid, ckey, password='mypass'):
    print('Using title id: {}'.format(tid))
    print('Using common key: {}'.format(ckey))
    print('Using password: {}'.format(password))
    unencrypted = generate_key(tid, password).decode()
    encrypted = encrypt_title_key(tid, unencrypted, ckey).decode()
    print('generated unencrypted: {}'.format(unencrypted))
    print('generated encrypted: {}'.format(encrypted))
    return (encrypted, unencrypted)

if __name__ == '__main__':
    ckey = get_ckey()
    if not verify_ckey(ckey):
        print('Incorrect common key, please add the correct key to the ckey.json file\nand try again. Key must be plaintext!')
        print('Found common key: {}'.format(ckey))
    else:
        if len(sys.argv) == 2:
            main(sys.argv[1], ckey)
        elif len(sys.argv) == 3:
            main(sys.argv[1], ckey, password=sys.argv[2])
        
