#!/usr/bin/env python3
# titlekey-bruteforcer
# License: MIT

import itertools
import string
import keygen
import wiiu_decrypt
import binascii

def bruteforce(tid, ckey):
    chars = "0123456789"
    attempts = 0
    contents, title_id = wiiu_decrypt.get_contents(tid)
    app_data = wiiu_decrypt.get_app_data(tid, contents)
    for length in range(5, 10):
        for guess in itertools.product(chars, repeat=length):
            attempts += 1
            guess = ''.join(guess)
            print(guess)
            unencrypted_keyguess, encrypted_keyguess = keygen.encrypt_guess(tid, guess, ckey)
            result = wiiu_decrypt.decrypt(tid, encrypted_keyguess, ckey, contents, title_id, app_data)
            if (result == 1):
                print('bruteforce success after '+str(attempts)+' attempts')
                print('password: '+guess)
                print('encrypted titlekey: '+encrypted_keyguess)
                print('decrypted titlekey: '+binascii.hexlify(unencrypted_keyguess).decode())
                return
    
    print('bruteforce failed...')
    return


tid = '00050000101b9800'
ckey = keygen.get_ckey()
bruteforce(tid, ckey)
