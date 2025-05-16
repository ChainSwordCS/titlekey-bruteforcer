#!/usr/bin/env python3
# titlekey-bruteforcer
# License: MIT

import itertools
import string
import json
import argparse

import keygen
import wiiu_decrypt
import binascii

parser = argparse.ArgumentParser()
parser.add_argument('--system', help='valid options: \'wiiu\', \'dsi\'\n'+'not yet implemented: \'wii\', \'3ds\'')
parser.add_argument('--commonkey', help='choose a commonkey from ckey.json, in case the automatic choice is wrong. valid options: \'dsi_prod\', \'dsi_dev\', \'dsi_debugger\', \'wiiu_prod\', \'wiiu_dev\'')
parser.add_argument('--commonkeyoverride', help='manually specify the commonkey')
parser.add_argument('titleid')
args = parser.parse_args()

def bruteforce(tid, ckey):
    chars = "0123456789"
    attempts = 0
    contents, title_id = wiiu_decrypt.get_contents(tid)
    app_data = wiiu_decrypt.get_app_data(tid, contents)
    for length in range(5, 10):
        for guess in itertools.product(chars, repeat=length):
            attempts += 1
            guess = ''.join(guess)
            if attempts % 100 == 0:
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


tid = args.titleid

if args.system:
    match args.system:
        case 'wiiu':
            print('wiiu')
        case 'dsi':
            print('dsi')
        case _:
            sys.exit('Error: invalid argument passed in --system')
else:
    sys.exit('Error: system autodetection based on titleid not yet implemented! please use the --system argument.')

if args.commonkeyoverride:
    ckey = args.commonkeyoverride
else:
    

ckey = keygen.get_ckey()
#bruteforce(tid, ckey)
bruteforce_dsi(tid, ckey)
