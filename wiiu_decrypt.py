#!/usr/bin/env python3
# wiiu_decrypt.py by ihaveamac
# License: MIT
# https://github.com/ihaveamac/wiiu-things
#
# Modified from original code

# encrypted titlekey is decrypted with the Wii U Common Key
# with IV being TID + 0x00 padding

# contents are decrypted with the decrypted titlekey
# with IV being all 0x00, or index bytes + 0x00 padding

import binascii
import hashlib
import math
import os
import struct
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def show_progress(val, maxval, cid):
    # crappy workaround I bet, but print() didn't do what I wanted
    minval = min(val, maxval)
    sys.stdout.write('\rDecrypting {}...  {:>5.1f}% {:>10} / {:>10} ({} MiB)'.format(cid, (minval / maxval) * 100, minval, maxval, maxval / (1024 ** 2)))
    sys.stdout.flush()

def show_chunk(num, count, cid):
    # crappy workaround I bet, but print() didn't do what I wanted
    sys.stdout.write('\rDecrypting {}...  Chunk  {:>10} / {:>10} ({} MiB)'.format(cid, num + 1, count, (count * 0x10000) / (1024 ** 2)))
    sys.stdout.flush()

def get_contents(arg_tid):
    tmdfilename = ''
    
    if os.path.isfile(arg_tid+'/title.tmd'):
        tmdfilename = 'title.tmd'
    elif os.path.isfile(arg_tid+'/tmd'):
        tmdfilename = 'tmd'
    elif os.path.isfile(arg_tid+'/tmd.0'):
        tmdfilename = 'tmd.0'
    else:
        sys.exit('No TMD (title.tmd) was found.')
    print('found '+tmdfilename)

    # find title id and content id
    title_id = b''
    contents = []
    with open(arg_tid+'/'+tmdfilename, 'rb') as tmd:
        tmd.seek(0x18C)
        title_id = tmd.read(8)

        tmd.seek(0x1DE)
        content_count = struct.unpack('>H', tmd.read(2))[0]

        tmd.seek(0x204)

        for c in range(content_count):
            tmd.seek(0xB04 + (0x30 * c))
            content_id = tmd.read(0x4).hex()

            tmd.seek(0xB08 + (0x30 * c))
            content_index = tmd.read(0x2)

            tmd.seek(0xB0A + (0x30 * c))
            content_type = struct.unpack('>H', tmd.read(2))[0]

            tmd.seek(0xB0C + (0x30 * c))
            content_size = struct.unpack('>Q', tmd.read(8))[0]

            # content_size = os.path.getsize(content_id)
            tmd.seek(0xB14 + (0x30 * c))
            content_hash = tmd.read(0x14)

            contents.append([content_id, content_index, content_type, content_size, content_hash])
    
    return contents, title_id

def get_app_data(arg_tid, contents):
    h3_hasheses = []
    sizes = []
    apps = []
    for c in contents:
        sizes.append(os.path.getsize(arg_tid + '/' + c[0] + '.app'))

        if c[2] & 2:  # if has a hash tree
            with open(arg_tid + '/' + c[0] + '.h3', 'rb') as h3:
                h3_hasheses.append(h3.read())
        else:
            h3_hasheses.append(0)
        
        with open(arg_tid + '/' + c[0] + '.app', 'rb') as encrypted:
            apps.append(encrypted.read())
    
    return (h3_hasheses, sizes, apps)

def finalize_dec(arg_tid, contents, decrypted_parts):
    for i in range(len(decrypted_parts)):
        c = contents[i]
        with open(arg_tid + '/' + c[0] + '.app.dec', 'wb') as decrypted:
            decrypted.write(decrypted_parts[i])
            
# if the argument decrypt_full_contents is False, this function returns early
# after decrypting juuuust enough data to verify a hash.
# this strategy is lightning-fast, but could possibly result in false-positives.
# 
# if decrypt_full_contents is True, this function doesn't return until decrypting
# full/all contents of the title.
# 
# returns 1 on success; all content hashes match, titlekey is correct.
# returns 0 on failure; either the titlekey is wrong (99% likely), or the content is corrupt.
def decrypt(arg_tid, arg_titlekey, arg_ckey, contents, title_id, app_data, decrypt_full_contents = False):
    # this var is only used if decrypt_full_contents == True
    corruption_detected = False
    
    #try:
    #    with open(os.path.expanduser('~/.wiiu/common-key'), 'r') as f:
    #        # to allow for spaces in the hex text
    #        wiiu_common_key = f.read(32).strip().replace(' ', '')
    #except FileNotFoundError:
    #    sys.exit('Please set the Wii U common key at the file ~/.wiiu/common-key.')
    
    wiiu_common_key = arg_ckey

    ##########################

    #wiiu_common_key_hash = hashlib.sha1(wiiu_common_key.encode('utf-8').upper())
    #if wiiu_common_key_hash.hexdigest() != 'e3fbc19d1306f6243afe852ab35ed9e1e4777d3a':
    #    print('Wrong Wii U Common Key. Place the correct one at the file ~/.wiiu/common-key.')

    ckey = binascii.unhexlify(wiiu_common_key)

    readsize = 8 * 1024 * 1024

    h3_hasheses, sizes, apps = app_data

    #print('Title ID:               ' + title_id.hex().upper())

    # find encrypted titlekey
    encrypted_titlekey = b''
    encrypted_titlekey = binascii.unhexlify(arg_titlekey)
    #if os.path.isfile('title.tik'):
    #    with open('title.tik', 'rb') as cetk:
    #        cetk.seek(0x1BF)
    #        encrypted_titlekey = cetk.read(0x10)
    #elif len(sys.argv) > 1:
    #    encrypted_titlekey = binascii.unhexlify(sys.argv[1])
    #else:
    #    sys.exit('Missing CETK (title.tik). Please add an argument containing the encrypted titlekey.')

    #print('Encrypted Titlekey:     ' + encrypted_titlekey.hex().upper())

    # decryption fun
    cipher_titlekey = Cipher(algorithms.AES(ckey), modes.CBC(title_id + bytes(8)), backend=default_backend()).decryptor()
    decrypted_titlekey = cipher_titlekey.update(encrypted_titlekey) + cipher_titlekey.finalize()
    #print('Decrypted Titlekey:     ' + decrypted_titlekey.hex().upper())
    
    decrypted_parts = []

    for i in range(len(contents)):
        c = contents[i]
        left = sizes[i]  # set to file size
        left_hash = c[3]  # set to tmd size (can differ to filesize)
        
        # logging
        if decrypt_full_contents:
            size_string = ''
            if left < 1024:
                size_string = str(left)+' bytes'
            elif left < 1024 * 1024:
                mysize = left * 1.0 / 1024
                size_string = '{0:.1f}'.format(mysize)+' KiB'
            elif left < 1024 * 1024 * 1024:
                mysize = left * 1.0 / (1024*1024)
                size_string = '{0:.1f}'.format(mysize)+' MiB'
            else:
                mysize = left * 1.0 / (1024*1024*1024)
                size_string = '{0:.1f}'.format(mysize)+' GiB'
            print('Decrypting {}'.format(c[0])+' ('+size_string+')...')

        if c[2] & 2:  # if has a hash tree
            chunk_count = left // 0x10000
            chunk_num = 0
            h3_hashes = h3_hasheses[i]
            if hashlib.sha1(h3_hashes).digest() != c[4]:
                if decrypt_full_contents:
                    corruption_detected = True
                    print('H3 Hash mismatch!')
                    print(' > TMD:    ' + c[4].hex().upper())
                    print(' > Result: ' + content_hash.hexdigest().upper())
                else:
                    return 0

            h0_hash_num = 0
            h1_hash_num = 0
            h2_hash_num = 0
            h3_hash_num = 0

            #with open(arg_tid + '/' + c[0] + '.app', 'rb') as encrypted, open(arg_tid + '/' + c[0] + '.app.dec', 'wb') as decrypted:
            encrypted = apps[i]
            decrypted = bytes()
            for chunk_num in range(chunk_count):
                #show_chunk(chunk_num, chunk_count, c[0])
                # decrypt and verify hash tree
                cipher_hash_tree = Cipher(algorithms.AES(decrypted_titlekey), modes.CBC(bytes(16)), backend=default_backend()).decryptor()
                hash_tree = cipher_hash_tree.update(encrypted[0x10000*chunk_num:0x10000*chunk_num+0x400]) + cipher_hash_tree.finalize()
                h0_hashes = hash_tree[0:0x140]
                h1_hashes = hash_tree[0x140:0x280]
                h2_hashes = hash_tree[0x280:0x3c0]

                h0_hash = h0_hashes[(h0_hash_num * 0x14):((h0_hash_num + 1) * 0x14)]
                h1_hash = h1_hashes[(h1_hash_num * 0x14):((h1_hash_num + 1) * 0x14)]
                h2_hash = h2_hashes[(h2_hash_num * 0x14):((h2_hash_num + 1) * 0x14)]
                h3_hash = h3_hashes[(h3_hash_num * 0x14):((h3_hash_num + 1) * 0x14)]
                if hashlib.sha1(h0_hashes).digest() != h1_hash:
                    if decrypt_full_contents:
                        corruption_detected = True
                        print('\rH0 Hashes invalid in chunk {}'.format(chunk_num))
                    else:
                        return 0
                if hashlib.sha1(h1_hashes).digest() != h2_hash:
                    if decrypt_full_contents:
                        corruption_detected = True
                        print('\rH1 Hashes invalid in chunk {}'.format(chunk_num))
                    else:
                        return 0
                if hashlib.sha1(h2_hashes).digest() != h3_hash:
                    if decrypt_full_contents:
                        corruption_detected = True
                        print('\rH2 Hashes invalid in chunk {}'.format(chunk_num))
                    else:
                        return 0

                iv = h0_hash[0:0x10]
                cipher_content = Cipher(algorithms.AES(decrypted_titlekey), modes.CBC(iv), backend=default_backend()).decryptor()
                decrypted_data = cipher_content.update(encrypted[0x10000*chunk_num+0x400:0x10000*chunk_num+0xFC00+0x400]) + cipher_content.finalize()
                if hashlib.sha1(decrypted_data).digest() != h0_hash:
                    if decrypt_full_contents:
                        corruption_detected = True
                        print('\rData block hash invalid in chunk {}'.format(chunk_num))
                    else:
                        return 0
                decrypted += hash_tree + decrypted_data

                h0_hash_num += 1
                if h0_hash_num >= 16:
                    h0_hash_num = 0
                    h1_hash_num += 1
                if h1_hash_num >= 16:
                    h1_hash_num = 0
                    h2_hash_num += 1
                if h2_hash_num >= 16:
                    h2_hash_num = 0
                    h3_hash_num += 1
            #print('')
            decrypted_parts.append(decrypted)
        else:
            cipher_content = Cipher(algorithms.AES(decrypted_titlekey), modes.CBC(c[1] + bytes(14)), backend=default_backend()).decryptor()
            content_hash = hashlib.sha1()
            
            encrypted = apps[i]
            decrypted = bytes()
            encrypted_idx = 0
            #with open(arg_tid + '/' + c[0] + '.app', 'rb') as encrypted, open(arg_tid + '/' + c[0] + '.app.dec', 'wb') as decrypted:
            for _ in range(int(math.floor((c[3] / readsize)) + 1)):
                to_read = min(readsize, left)
                to_read_hash = min(readsize, left_hash)

                encrypted_content = encrypted[encrypted_idx:encrypted_idx+to_read]
                encrypted_idx += to_read
                decrypted_content = cipher_content.update(encrypted_content)
                content_hash.update(decrypted_content[0:to_read_hash])
                decrypted += decrypted_content
                left -= readsize
                left_hash -= readsize

                #show_progress(c[3] - left, c[3], c[0])
                if left_hash < 0:
                    left_hash = 0
                if left <= 0:
                    break
            cipher_content.finalize()
            if c[4] != content_hash.digest():
                if decrypt_full_contents:
                    corruption_detected = True
                    print('Content Hash mismatch!')
                    print(' > TMD:    ' + c[4].hex().upper())
                    print(' > Result: ' + content_hash.hexdigest().upper())
                else:
                    return 0
            decrypted_parts.append(decrypted)
        # If the above hash checks pass, then this check is run.
        # This check is only done once per content file,
        # to be slightly less redundant and slightly
        # more performant with decrypting .app/.h3 pairs
        if not decrypt_full_contents:
            return 1
    
    # this code is only run if decrypt_full_contents == True
    finalize_dec(arg_tid, contents, decrypted_parts)
    if corruption_detected:
        return 0
    else:
        return 1
