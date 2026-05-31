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
import libTWLPy

import keygen
import wiiu_decrypt
import twl_decrypt

# Threading setup
QUEUE_MAX_SIZE = 1000 # Strict
QUEUE_MIN_SIZE = 500  # Target
#NUM_WORKERS = multiprocessing.cpu_count() // 2 # Probably about optimal?
NUM_WORKERS = multiprocessing.cpu_count() - 1 # Probably about optimal?
BATCH_SIZE = 500
#NUM_WORKERS = 1

COMMON_PASSES = ["mypass", "nintendo", "1234", "5678", "56789", "1234567890", "test", "redsst", "d4t4c3nt3r", "datacenter", "password", "", "0", "0000", "5037", "nintedno", "Lucy131211", "fbf10"]

# pool of available text characters for bruteforcing
DEFAULT_CHARS = string.digits + string.ascii_lowercase # Usually the only characters in use
#DEFAULT_CHARS = string.digits + string.ascii_lowercase + string.ascii_uppercase + string.punctuation + " "
#DEFAULT_CHARS = string.printable.strip()
DEFAULT_MINLENGTH = 1
DEFAULT_MAXLENGTH = 8

def bruteforce_wiiu(tid, ckey, chars, minlength, maxlength, resumeat):
    global data_queue, decoded_event
    contents, title_id = wiiu_decrypt.get_contents(tid)
    app_data = wiiu_decrypt.get_app_data(tid, contents)
    
    # Start worker processes
    workers = []
    for i in range(NUM_WORKERS):
        p = multiprocessing.Process(target=wiiu_process_guesses, args=(i, data_queue, decoded_event, passes_done_event, contents, title_id, app_data, tid, ckey))
        p.start()
        workers.append(p)
    
    try:
        get_guesses(chars, minlength, maxlength, resumeat, True)
    except KeyboardInterrupt:
        decoded_event.set() # Not actually decoded but it shuts down all the stuff
    
    for p in workers:
        p.join()
    
    if not decoded_event.is_set():
        print('bruteforce failed...')
    return

def bruteforce_dsi(tid, ckey, chars, minlength, maxlength, resumeat):
    global data_queue, decoded_event
    metadata, content, title = twl_decrypt.get_data(tid)
    
    # Start worker processes
    workers = []
    for i in range(NUM_WORKERS):
        p = multiprocessing.Process(target=dsi_process_guesses, args=(i, data_queue, decoded_event, passes_done_event, tid, ckey, metadata, content))
        p.start()
        workers.append(p)
    
    try:
        get_guesses(chars, minlength, maxlength, resumeat, True)
    except KeyboardInterrupt:
        decoded_event.set() # Not actually decoded but it shuts down all the stuff
    
    for p in workers:
        p.join()
    
    if not decoded_event.is_set():
        print('bruteforce failed...')
    return

def get_guesses(chars, minsize, maxsize, resumeat = '', use_common = True):
    global data_queue, decoded_event, passes_done_event
    attempts = 0
    # use common passwords
    if use_common:
        attempts += len(COMMON_PASSES)
        data_queue.put((COMMON_PASSES, attempts), timeout=1)
    
    if resumeat != '':
        print('starting at "' + resumeat + '"...')
        length = len(resumeat)
        # to simplify the looping code a little, go back one index first
        #a = chars.find(resumeat[length-1:length])
        #if a == 0:
        #    a = 1 # whatever, screw it.
        #resumeat = resumeat[:length-1] + chars[a-1:a]
        
        pass_iter = itertools.product(chars, repeat=length)
        # itertools.product() doesn't have the args / API stuff needed for this,
        # so we have to do stuff manually...
        
        offset = 0
        i = 0
        while (i < length):
            b = chars.find(resumeat[length-1-i:length-i])
            offset = offset + (b * (len(chars) ** (i)))
            #print('offset+='+str(b)+' * ('+str(len(chars))+' ** '+str(i+1)+')')
            i = i + 1
        offset = offset - 1
        print('offset='+str(offset)+' (offset into list of permutations of length '+str(length)+')')
        
        # TODO: this is stupid.
        # it works well enough when offset is like, a few million...
        # but when offset is like two billion, this is excessively slow,
        # and then it takes a few mins to spin up.
        # idk if there's realistically a better way of doing this within the confines of itertools. -C
        j = 0
        while (j < offset):
            next(pass_iter)
            j = j + 1
        print('starting!')
        
        # 1:1 duplicate code starts here
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
                        if i == QUEUE_MAX_SIZE - queue_size - 1:
                            print(passes[-1])
                        attempts += len(passes)
                    if iter_done:
                        break
            time.sleep(.1)
        # end of 1:1 duplicate code
        minsize = length + 1
        
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
                        if i == QUEUE_MAX_SIZE - queue_size - 1:
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
            print(f"[Worker {worker_id}] Total checking time: {checking}\n"+
                  f"[Worker {worker_id}] Total waiting time: {waiting}\n"+
                  f"[Worker {worker_id}] Total decrypting time: {decrypting}")
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
                    time.sleep(2) # wait 2 seconds for other threads to stop so the log is more coherent
                    print('decrypting full title contents...')
                    result = wiiu_decrypt.decrypt(tid, encrypted_keyguess, ckey, contents, title_id, app_data, True)
                    if (result == 0):
                        print('Warning: One or more decrypted contents failed hash verification. (Is the data corrupt?)')
        except:
            if passes_done_event.is_set() and data_queue.empty():
                print(f"[Worker {worker_id}] No more data and producer is done.\n"+
                      f"[Worker {worker_id}] Total checking time: {checking}\n"+
                      f"[Worker {worker_id}] Total waiting time: {waiting}\n"+
                      f"[Worker {worker_id}] Total decrypting time: {decrypting}")
                break
            continue


def dsi_process_guesses(worker_id, data_queue, decoded_event, passes_done_event, tid, ckey, metadata, content):
    checking = 0
    waiting = 0
    decrypting = 0
    
    # if this title's files included a ticket (and by extension a valid titlekey)
    if metadata[6] is not None:
        while True:
            a = time.time()
            if decoded_event.is_set():
                print(f"[Worker {worker_id}] Total checking time: {checking}\n"+
                      f"[Worker {worker_id}] Total waiting time: {waiting}\n"+
                      f"[Worker {worker_id}] Total decrypting time: {decrypting}")
                break
            try:
                b = time.time()
                guesses, attempt = data_queue.get(timeout=1) # Should be longer than the guess generator's sleep
                c = time.time()
                for guess in guesses:
                    encrypted_keyguess = ''
                    unencrypted_keyguess = keygen.generate_key(tid, guess)
                    d = time.time()
                    checking += b-a
                    waiting += c-b
                    decrypting += d-c
                    #if binascii.unhexlify(unencrypted_keyguess) == binascii.unhexlify(metadata[6]):
                    if unencrypted_keyguess == metadata[6]:
                        print('bruteforce success after about '+str(attempt)+' attempts')
                        print('password: '+guess)
                        try: #not sure if this works
                            encrypted_keyguess = keygen.encrypt_title_key(tid, unencrypted_keyguess, ckey)
                            print('encrypted titlekey: '+binascii.hexlify(encrypted_keyguess).decode())
                        except:
                            print(':(')
                            continue
                        print('decrypted titlekey: '+binascii.hexlify(unencrypted_keyguess).decode())
                        decoded_event.set()
                        
            except:
                if passes_done_event.is_set() and data_queue.empty():
                    print(f"[Worker {worker_id}] No more data and producer is done.\n"+
                          f"[Worker {worker_id}] Total checking time: {checking}\n"+
                          f"[Worker {worker_id}] Total waiting time: {waiting}\n"+
                          f"[Worker {worker_id}] Total decrypting time: {decrypting}")
                    break
                continue
    else:
        # decrypt content and verify hash, business as usual
        
        # first do this oneshot
        unencrypted_keyguess = keygen.generate_key_algo2(tid)
        result = twl_decrypt.decrypt(tid, unencrypted_keyguess, ckey, metadata, content)
        if (result == 1):
            print('bruteforce success after about 1 attempts')
            encrypted_keyguess = keygen.encrypt_title_key(tid, unencrypted_keyguess, ckey)
            print('encrypted titlekey: '+encrypted_keyguess.decode())
            print('decrypted titlekey: '+unencrypted_keyguess.decode())
            decoded_event.set()
        
        while True:
            a = time.time()
            if decoded_event.is_set():
                print(f"[Worker {worker_id}] Total checking time: {checking}\n"+
                      f"[Worker {worker_id}] Total waiting time: {waiting}\n"+
                      f"[Worker {worker_id}] Total decrypting time: {decrypting}")
                break
            try:
                b = time.time()
                guesses, attempt = data_queue.get(timeout=1) # Should be longer than the guess generator's sleep
                c = time.time()
                for guess in guesses:
                    encrypted_keyguess = ''
                    unencrypted_keyguess = keygen.generate_key(tid, guess)
                    result = twl_decrypt.decrypt(tid, binascii.unhexlify(unencrypted_keyguess), ckey, metadata, content)
                    d = time.time()
                    checking += b-a
                    waiting += c-b
                    decrypting += d-c
                    if (result == 1):
                        print('bruteforce success after about '+str(attempt)+' attempts')
                        print('password: '+guess)
                        encrypted_keyguess = keygen.encrypt_title_key(tid, unencrypted_keyguess, ckey)
                        print('encrypted titlekey: '+encrypted_keyguess.decode())
                        print('decrypted titlekey: '+unencrypted_keyguess.decode())
                        decoded_event.set()
                    elif (result == 2):
                        print('false positive(?) at about '+str(attempt)+' attempts')
                        print('password: '+guess)
                        encrypted_keyguess = keygen.encrypt_title_key(tid, unencrypted_keyguess, ckey)
                        print('encrypted titlekey: '+encrypted_keyguess.decode())
                        print('decrypted titlekey: '+unencrypted_keyguess.decode())
                        # keep going
                    #elif (result == 0):
                        # do nothing; keep going
            except:
                if passes_done_event.is_set() and data_queue.empty():
                    print(f"[Worker {worker_id}] No more data and producer is done.\n"+
                          f"[Worker {worker_id}] Total checking time: {checking}\n"+
                          f"[Worker {worker_id}] Total waiting time: {waiting}\n"+
                          f"[Worker {worker_id}] Total decrypting time: {decrypting}")
                    break
                continue



def main(arg_titleid, arg_system = None, arg_commonkey = None, arg_commonkeyoverride = None, arg_chars = None, arg_minlength = None, arg_maxlength = None, arg_resumeat = None):
    global data_queue, decoded_event, passes_done_event
    manager = multiprocessing.Manager()
    data_queue = manager.Queue(QUEUE_MAX_SIZE)
    decoded_event = manager.Event()
    passes_done_event = manager.Event()
    
    if not arg_chars:
        arg_chars = DEFAULT_CHARS
    if not arg_minlength:
        arg_minlength = DEFAULT_MINLENGTH
    if not arg_maxlength:
        arg_maxlength = DEFAULT_MAXLENGTH
    if not arg_resumeat:
        arg_resumeat = ''
    
    if arg_titleid:
        # TODO: sanity checking
        tid = arg_titleid
    else:
        sys.exit('Error: invalid titleid')
    
    system = ''
    if arg_system:
        system = arg_system
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
    
    
    if arg_commonkeyoverride:
        ckey = arg_commonkeyoverride
    else:
        if arg_commonkey:
            with open('ckey.json', 'r') as f:
                ckey = json.load(f)[arg_commonkey+'_commonkey']
            if ckey == '':
                sys.exit('Error: failed to load '+arg_commonkey+'_commonkey from ckey.json')
            print('using '+arg_commonkey+'_commonkey')
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
                    sys.exit('Error: unable to autoselect commonkey for unknown system \"'+arg_system+'\"')
            with open('ckey.json', 'r') as f:
                ckey = json.load(f)[keyselect]
            if ckey == '':
                sys.exit('Error: failed to load '+keyselect+' from ckey.json')
            print('using '+keyselect)
    
    match system:
        case 'wiiu':
            bruteforce_wiiu(tid, ckey, arg_chars, arg_minlength, arg_maxlength, arg_resumeat)
        case 'dsi':
            bruteforce_dsi(tid, ckey, arg_chars, arg_minlength, arg_maxlength, arg_resumeat)
        case _:
            print('system '+system+' is invalid or not yet implemented')
    
    # return

if __name__ == "__main__":
    # Argument parser setup
    parser = argparse.ArgumentParser()
    parser.add_argument('--system', help='valid options: \'wiiu\', \'dsi\'. '+'not yet implemented: \'wii\', \'3ds\'')
    parser.add_argument('--commonkey', help='choose a commonkey from ckey.json, in case the automatic choice is wrong. valid options: \'dsi_prod\', \'dsi_dev\', \'dsi_debugger\', \'wiiu_prod\', \'wiiu_dev\'')
    parser.add_argument('--commonkeyoverride', help='manually specify the commonkey')
    parser.add_argument('--chars', help='available text characters for password bruteforcing (default=0123456789abcdefghijklmnopqrstuvwxyz)')
    parser.add_argument('--minlength', help='minimum password length to try. (default=1)')
    parser.add_argument('--maxlength', help='maximum password length to try. (default=8)')
    parser.add_argument('--resumeat', help='password to resume / (re-)start bruteforcing at.')
    #parser.add_argument('--extract', help='extract game files after successful decryption', action='store_true')
    parser.add_argument('titleid')
    args = parser.parse_args()
    
    main(args.titleid, args.system, args.commonkey, args.commonkeyoverride, args.chars, args.minlength, args.maxlength, args.resumeat)
