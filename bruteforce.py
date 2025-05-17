#!/usr/bin/env python3
# titlekey-bruteforcer
# License: MIT

import itertools
import json
import argparse
import binascii
import sys
import multiprocessing
import string
import time

import keygen
import wiiu_decrypt

# Argument parser setup
parser = argparse.ArgumentParser()
parser.add_argument('--system', help='valid options: \'wiiu\', \'dsi\'\n'+'not yet implemented: \'wii\', \'3ds\'')
parser.add_argument('--commonkey', help='choose a commonkey from ckey.json, in case the automatic choice is wrong. valid options: \'dsi_prod\', \'dsi_dev\', \'dsi_debugger\', \'wiiu_prod\', \'wiiu_dev\'')
parser.add_argument('--commonkeyoverride', help='manually specify the commonkey')
parser.add_argument('titleid')
args = parser.parse_args()

# Threading setup
QUEUE_MAX_SIZE = 1000 # Strict
QUEUE_MIN_SIZE = 500  # Target
NUM_WORKERS = multiprocessing.cpu_count() // 2 # Probably about optimal?
BATCH_SIZE = 500
#NUM_WORKERS = 1

COMMON_PASSES = ["mypass", "5678", "56789", "1234567890", "nintendo", "test"]


def bruteforce_wiiu(tid, ckey):
    global data_queue, decoded_event
    #chars = "0123456789"
    chars = string.digits + string.ascii_lowercase # Only observed characters so far
    contents, title_id = wiiu_decrypt.get_contents(tid)
    app_data = wiiu_decrypt.get_app_data(tid, contents)
    
    # Start worker processes
    workers = []
    for i in range(NUM_WORKERS):
        p = multiprocessing.Process(target=wiiu_process_guesses, args=(i, data_queue, decoded_event, passes_done_event, contents, title_id, app_data, tid, ckey))
        p.start()
        workers.append(p)
    
    try:
        get_guesses(chars, 1, 5, 0, False)
    except KeyboardInterrupt:
        decoded_event.set() # Not actually decoded but it shuts down all the stuff
    
    for p in workers:
        p.join()
    
    if not decoded_event.is_set():
        print('bruteforce failed...')
    return

def bruteforce_dsi(tid, ckey):
    chars = "0123456789"
    attempts = 0

def get_guesses(chars = string.printable.strip(), minsize = 1, maxsize = 5, offset = 0, use_common = True):
    global data_queue, decoded_event, passes_done_event
    attempts = 0
    if use_common:
        data_queue.put((COMMON_PASSES, attempts), timeout=1)
        attempts += 1
    for length in range(minsize, maxsize+1):
        pass_iter = itertools.product(chars, repeat=length)
        iter_done = False
        while not iter_done and not decoded_event.is_set() and not passes_done_event.is_set():
            queue_size = data_queue.qsize()
            if queue_size < QUEUE_MIN_SIZE:
                for i in range((QUEUE_MAX_SIZE - queue_size)):
                    passes = []
                    try:
                        for _ in range(BATCH_SIZE):
                            passes.append(''.join(next(pass_iter)))
                    except StopIteration:
                        iter_done = True
                    if len(passes) > 0:
                        data_queue.put((passes, attempts), timeout=1)
                        if i == QUEUE_MAX_SIZE - queue_size:
                            print(passes[-1])
                        attempts += len(passes)
                    if iter_done:
                        break
                    
            time.sleep(.1)
    passes_done_event.set()

def wiiu_process_guesses(worker_id, data_queue, decoded_event, passes_done_event, contents, title_id, app_data, tid, ckey):
    checking = 0
    waiting = 0
    decrypting = 0
    while True:
        a = time.time()
        if decoded_event.is_set():
            print(f"[Worker {worker_id}] Total checking time: {checking}")
            print(f"[Worker {worker_id}] Total waiting time: {waiting}")
            print(f"[Worker {worker_id}] Total decrypting time: {decrypting}")
            break
        try:
            b = time.time()
            guesses, attempt = data_queue.get(timeout=1) # Should be longer than the guess generator's sleep
            c = time.time()
            for guess in guesses:
                unencrypted_keyguess, encrypted_keyguess = keygen.encrypt_guess(tid, guess, ckey)
                result = wiiu_decrypt.decrypt(tid, encrypted_keyguess, ckey, contents, title_id, app_data)
                d = time.time()
                checking += b-a
                waiting += c-b
                decrypting += d-c
                if (result == 1):
                    print('bruteforce success after about '+str(attempt)+' attempts')
                    print('password: '+guess)
                    print('encrypted titlekey: '+encrypted_keyguess)
                    print('decrypted titlekey: '+binascii.hexlify(unencrypted_keyguess).decode())
                    decoded_event.set()
        except:
            if passes_done_event.is_set() and data_queue.empty():
                print(f"[Worker {worker_id}] No more data and producer is done.")
                break
            continue

def main():
    global data_queue, decoded_event, passes_done_event
    manager = multiprocessing.Manager()
    data_queue = manager.Queue(QUEUE_MAX_SIZE)
    decoded_event = manager.Event()
    passes_done_event = manager.Event()
    
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

if __name__ == "__main__":
    main()