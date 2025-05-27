#!/usr/bin/env python3
# loosely based on parts of https://github.com/NinjaCheetah/NUSGet
# and https://github.com/NinjaCheetah/libTWLPy
#
# License: MIT

from hashlib import sha1
from Crypto.Cipher import AES
import binascii
import os
import libTWLPy # designed for libTWLPy v0.1.0




def get_data(tid):
    title = libTWLPy.Title()
    title_dir = tid
    
    tmdfilename = ''
    if os.path.isfile(tid+'/title.tmd'):
        tmdfilename = 'title.tmd'
    elif os.path.isfile(tid+'/tmd'):
        tmdfilename = 'tmd'
    elif os.path.isfile(tid+'/tmd.0'):
        tmdfilename = 'tmd.0'
    else:
        sys.exit('No TMD (title.tmd) was found.')
    print('found '+tmdfilename)
    
    with open(tid+'/'+tmdfilename, 'rb') as tmdfile:
        title.load_tmd(tmdfile.read())
    #title_version = title.tmd.title_version
    title.load_content_records()
    
    enc_titlekey = None
    dec_titlekey = None
    # check if the title is bundled with a ticket included
    ticketpath = ''
    if os.path.isfile(tid+'/cetk'):
        ticketpath = tid+'/cetk'
    elif os.path.isfile(tid+'/tik'):
        ticketpath = tid+'/tik'
    if ticketpath != '':
        title.load_ticket(open(ticketpath, 'rb').read())
        print('preexisting ticket found!')
        print('reported common_key_index: '+str(title.ticket.common_key_index))
        if title.ticket.common_key_index == 0:
            # we have to manually override it with the correct value
            # for libTWLPy's decryption-related methods to actually work. :P
            # additional note: title.ticket.get_title_key() is one such method.
            print('overriding...')
            title.ticket.common_key_index = 1
            print('common_key_index: '+str(title.ticket.common_key_index))
        enc_titlekey = binascii.hexlify(title.ticket.title_key_enc)
        dec_titlekey = binascii.hexlify(title.ticket.get_title_key())
        print('encrypted titlekey from ticket: '+enc_titlekey.decode())
        print('decrypted titlekey from ticket: '+dec_titlekey.decode())
    
    contentstr = '{:08X}'.format(title.tmd.content_record.content_id)
    #contentstr = contentstr+'.app'
    content = open(tid+'/'+contentstr, 'rb').read()
    
    metadata = []
    metadata.append(title.tmd.content_record.content_id)
    metadata.append(0) # content_index
    metadata.append(title.tmd.content_record.content_type)
    metadata.append(title.tmd.content_record.content_size)
    metadata.append(title.tmd.content_record.content_hash)
    metadata.append(enc_titlekey)
    metadata.append(dec_titlekey)
    #decrypt_from_ticket(tid, metadata, content, title)
    return metadata, content, title
    
# adapted (with modifications) from crypto.py from libTWLPy - https://github.com/NinjaCheetah/libTWLPy
def crypto_decrypt_content(content_enc, title_key, content_length) -> bytes:
    # TADs only have one content, so the IV is always all 0 bytes.
    content_iv = b'\x00' * 16
    # Align content to 16 bytes to ensure that it works with AES encryption.
    if (len(content_enc) % 16) != 0:
        content_enc = content_enc + (b'\x00' * (16 - (len(content_enc) % 16)))
    # Create a new AES object with the values provided, with the content's unique ID as the IV.
    aes = AES.new(title_key, AES.MODE_CBC, content_iv)
    # Decrypt the content using the AES object.
    content_dec = aes.decrypt(content_enc)
    # Trim additional bytes that may have been added so the content is the correct size.
    content_dec = content_dec[:content_length]
    return content_dec

def decrypt(tid, keyguess, ckey, metadata, content):
    # decrypt
    #content_dec = libTWLPy.crypto.decrypt_content(content, binascii.unhexlify(keyguess), metadata[3])
    content_dec = crypto_decrypt_content(content, binascii.unhexlify(keyguess), metadata[3])
    
    # verify hash
    content_dec_hash = sha1(content_dec).hexdigest()
    content_record_hash = str(metadata[4].decode())
    if content_dec_hash != content_record_hash:
        return 0
    else:
        srlpath = tid + '/' + '{:08X}'.format(metadata[0]) + '.srl'
        with open(srlpath, 'wb') as out:
            out.write(content_dec)
        return 1


def decrypt_from_ticket(tid, metadata, content, title):
    
    title.set_enc_content(content, metadata[0], metadata[2], metadata[3], metadata[4])
    
    # tell libTWLPy to use the dev common key.
    #
    # NOTE: libTWLPy issue. this field of the ticket metadata
    # isn't actually used like this for this purpose in practice.
    # dsi titles from the dev cdn archive, their tickets have this
    # field set to 0, not 1
    title.ticket.common_key_index = 1
    
    try:
        content_bytes = title.get_content()
        with open(tid + '/' + '{:08X}'.format(title.tmd.content_record.content_id) + '.srl', 'wb') as out:
            out.write(content_bytes)
        print(':)')
    except ValueError:
        print(':(')
        # libTWLPy throwing an exception during decryption here
        # indicates the hash doesn't match
        return 0
    # success!
    return 1

def maketad():
    print('not yet implemented')
    #title.set_enc_content(contentfile, content_id, content_type, content_size, content_hash)
