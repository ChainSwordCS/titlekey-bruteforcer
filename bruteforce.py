#!/usr/bin/env python3
# titlekey-bruteforcer
# License: MIT

import itertools
import string
import keygen
from wiiu_decrypt import wiiu_decrypt


def bruteforce(tid, ckey):
    chars = string.printable.strip()
    attempts = 0
    for length in range(1, 4):
        for guess in itertools.product(chars, repeat=length):
            attempts += 1
            guess = ''.join(guess)
            print(guess)
            unencrypted_keyguess = keygen.generate_key(tid, guess).decode()
            encrypted_keyguess = keygen.encrypt_title_key(tid, unencrypted_keyguess, ckey).decode()
            result = wiiu_decrypt(tid, encrypted_keyguess, ckey)
            if (result == 1):
                print('bruteforce success after '+attempts+' attempts')
                print('password: '+guess)
                print('encrypted titlekey: '+encrypted_keyguess)
                print('decrypted titlekey: '+unencrypted_keyguess)
                return
    
    print('bruteforce failed...')
    return


tid = '00050000101b9800'
ckey = keygen.get_ckey()
bruteforce(tid, ckey)
