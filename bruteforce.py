#!/usr/bin/env python3
# titlekey-bruteforcer
# License: MIT

import itertools
import string
import json
import argparse
import binascii

import keygen
import wiiu_decrypt

parser = argparse.ArgumentParser()
parser.add_argument('--system', help='valid options: \'wiiu\', \'dsi\'\n'+'not yet implemented: \'wii\', \'3ds\'')
parser.add_argument('--commonkey', help='choose a commonkey from ckey.json, in case the automatic choice is wrong. valid options: \'dsi_prod\', \'dsi_dev\', \'dsi_debugger\', \'wiiu_prod\', \'wiiu_dev\'')
parser.add_argument('--commonkeyoverride', help='manually specify the commonkey')
parser.add_argument('titleid')
args = parser.parse_args()

def bruteforce_wiiu(tid, ckey):
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

def bruteforce_dsi(tid, ckey):
    chars = "0123456789"
    attempts = 0



if args.titleid:
    # TODO: sanity checking
    tid = args.titleid
else:
    sys.exit('Error: invalid titleid')

system = ''
if args.system:
    system = args.system
else:
    sys.exit('Error: system autodetection based on titleid/content not yet implemented! please use the --system argument.')

match system:
    case 'wiiu':
        print('system = wiiu')
    case 'dsi':
        print('system = dsi')
    case '3ds':
        sys.exit('Error: --system 3ds not yet implemented')
    case 'wii':
        sys.exit('Error: --system wii not yet implemented')
    case _:
        sys.exit('Error: invalid argument passed in --system')


if args.commonkeyoverride:
    ckey = args.commonkeyoverride
else:
    if args.commonkey:
        with open('ckey.json', 'r') as f:
            ckey = json.load(f)[args.commonkey+'_commonkey']
        if ckey == '':
            sys.exit('Error: failed to load '+args.commonkey+'_commonkey from ckey.json')
        print('using '+args.commonkey+'_commonkey')
    else:
        keyselect = ''
        match system:
            case 'wiiu':
                keyselect = 'wiiu_dev_commonkey'
            case 'dsi':
                keyselect = 'dsi_dev_commonkey'
            case '3ds':
                keyselect = '3ds_dev_commonkey'
            case 'wii':
                keyselect = 'wii_dev_commonkey'
            case _:
                sys.exit('Error: unable to autoselect commonkey for unknown system \"'+args.system+'\"')
        with open('ckey.json', 'r') as f:
            ckey = json.load(f)[keyselect]
        if ckey == '':
            sys.exit('Error: failed to load '+keyselect+' from ckey.json')
        print('using '+keyselect)

match system:
    case 'wiiu':
        bruteforce_wiiu(tid, ckey)
    case 'dsi':
        bruteforce_dsi(tid, ckey)
    case _:
        print('system '+system+' is invalid or not yet implemented')
