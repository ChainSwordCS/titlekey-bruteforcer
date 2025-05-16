#!/usr/bin/env python3
# loosely based on parts of https://github.com/NinjaCheetah/NUSGet
# and https://github.com/NinjaCheetah/libTWLPy
#
# License: MIT

import pathlib
import hashlib
import libTWLPy




def get_data(tid):
    title = libTWLPy.Title()
    title_dir = tid
    with open(tid+'/title.tmd', 'rb') as tmdfile:
        title.load_tmd(tmdfile.read())
    #title_version = title.tmd.title_version
    title.load_content_records()
    
    contentstr = '{:08X}'.format(title.tmd.content_record.content_id)
    #contentstr = contentstr+'.app'
    content = open(tid+'/'+contentstr, 'rb').read()
    
    metadata = []
    metadata.append([title.tmd.content_record.content_id])
    metadata.append([0]) # content_index
    metadata.append([title.tmd.content_record.content_type])
    metadata.append([title.tmd.content_record.content_size])
    metadata.append([title.tmd.content_record.content_hash])
    
    return title.tmd.content_record, content, title
    

def decrypt(tid, keyguess, ckey, content_record, content):
    # decrypt
    content_dec = libTWLPy.crypto.decrypt_content(content, keyguess, content_record.content_size)
    
    # verify hash
    content_dec_hash = hashlib.sha1(content_dec).hexdigest()
    content_record_hash = str(content_record.content_hash.decode())
    if content_dec_hash != content_record_hash:
        return 0
    else:
        return 1


def decrypt2(titlekeyguess):
    try:
        title.get_content()
    except ValueError:
        # libTWLPy throwing an exception during decryption here
        # indicates the hash doesn't match
        return 0
    # success!
    return 1

def maketad():
    print('not yet implemented')
    #title.set_enc_content(contentfile, content_id, content_type, content_size, content_hash)
