import sys
import os
import pefile
import hashlib
import json
import magic

def print_help () :
    pass

def isfile(file_path):
	if os.path.isfile(file_path):
		return True
	else:
		print("No file found.")
		exit()

def get_imphash( pe ):
    try :
        return pe.get_imphash()
    except :
        return ""

def get_hash(file_path):
    fh = open(file_path, 'rb')
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    s256 = hashlib.sha256()

    while True:
        data = fh.read(8192)
        if not data:
            break
        md5.update(data)
        sha1.update(data)
        s256.update(data)

    md5 = md5.hexdigest()
    sha1 = sha1.hexdigest()
    sha256 = s256.hexdigest()

    return md5, sha1, sha256

def run( file_path ) :
    pe = pefile.PE(file_path)
    json_obj = dict()

    # Hash
    json_obj['hash'] = dict()
    json_obj['hash']['md5'], json_obj['hash']['sha1'], json_obj['hash']['sha256'] = get_hash(file_path)
    json_obj['hash']['imphash'] = get_imphash(pe)

    # Magic
    json_obj['file_type'] = magic.from_file(file_path)

    # Save report file
    with open("{}.json".format(json_obj['hash']['sha256']), 'w') as f :
        json.dump(json_obj, f)

if __name__ == '__main__' :
    if len(sys.argv) == 1 :
        print_help()
        exit(0)
    if len(sys.argv) == 2 :
        file_path = sys.argv[1]
        if isfile(file_path) :
            run(file_path)