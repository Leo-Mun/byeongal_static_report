import sys
import os
import pefile
import peutils
import hashlib
import json
import magic
import datetime
import chardet

_ROOT = os.path.abspath(os.path.dirname(__file__))
_USER_DB = os.path.join(_ROOT, 'signatures', 'userdb_panda.txt')

def print_help () :
    pass

def isfile(file_path):
    if os.path.isfile(file_path):
        return True
    else :
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

def get_compile_time(pe) :
    # timestamp
    tstamp = pe.FILE_HEADER.TimeDateStamp
    try:
        tsdate = datetime.datetime.fromtimestamp(tstamp).strftime("%Y-%m-%d %H:%M:%S")
    except:
        tsdate = str(tstamp) + " [Invalid date]"
    return tsdate

def get_packer_info( pe ) :
    signatures = peutils.SignatureDatabase(_USER_DB)
    matches = signatures.match_all(pe, ep_only=True)
    array = []
    if matches:
        for item in matches:
            if item[0] not in array:
                array.append(item[0])
    return array
    pass

def get_sections_number( pe ):
    return pe.FILE_HEADER.NumberOfSections

def get_resources_info( pe ) :
    res_array = []
    try :
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None:
                name = "%s" % resource_type.name
            else:
                name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
            if name == None:
                name = "%d" % resource_type.struct.Id
            if hasattr(resource_type, 'directory') :
                for resource_id in resource_type.directory.entries :
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            data = ""
                            try:
                                raw_data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                encoding_option = chardet.detect(raw_data)['encoding']
                                if encoding_option != None :
                                    data = raw_data.decode(encoding_option, 'ignore')
                            except:
                                pass
                            lang = pefile.LANG.get(resource_lang.data.lang, '*unknown*')
                            sublang = pefile.get_sublang_name_for_lang(resource_lang.data.lang, resource_lang.data.sublang)
                            res_array.append({"name": name, "data": data, "offset": hex(resource_lang.data.struct.OffsetToData),"size": resource_lang.data.struct.Size, "language": lang, "sublanguage": sublang})
    except :
        pass
    return res_array

def get_sections_info( pe ) :
    array = []
    for section in pe.sections:
        section.get_entropy()
        if section.SizeOfRawData == 0 or (section.get_entropy() > 0 and section.get_entropy() < 1) or section.get_entropy() > 7:
            suspicious = True
        else:
            suspicious = False

        scn = section.Name
        md5 = section.get_hash_md5()
        sha1 = section.get_hash_sha1()
        spc = suspicious
        va = hex(section.VirtualAddress)
        vs = hex(section.Misc_VirtualSize)
        srd = section.SizeOfRawData
        array.append({"name": scn.decode(), "hash_md5": md5, "hash_sha1": sha1, "suspicious": spc, "virtual_address": va, "virtual_size": vs, "size_raw_data": srd})

    return array

def get_import_function( pe ) :
    array = []
    library = set()
    libdict = {}
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll
            encoding_option = chardet.detect(dll)['encoding']
            if encoding_option == None:
                continue
            dll = dll.decode(encoding_option, 'ignore')
            for imp in entry.imports:
                address = hex(imp.address)
                function = imp.name
                encoding_option = chardet.detect(function)['encoding']
                if encoding_option == None:
                    continue
                function = function.decode(encoding_option, 'ignore')
                if dll not in library:
                    library.add(dll)
                array.append({"library": dll, "address": address, "function": function})

        for key in library:
            libdict[key] = []

        for lib in library:
            for item in array:
                if lib == item['library']:
                    libdict[lib].append({"address": item['address'], "function": item['function']})
    except:
        pass

    return libdict

def run( file_path ) :
    pe = pefile.PE(file_path)
    json_obj = dict()

    # Hash
    json_obj['hash'] = dict()
    ## Cryptographic Hash
    json_obj['hash']['md5'], json_obj['hash']['sha1'], json_obj['hash']['sha256'] = get_hash(file_path)
    ## Imphash
    json_obj['hash']['imphash'] = get_imphash(pe)

    # Magic
    json_obj['file_type'] = magic.from_file(file_path)

    # File Size
    json_obj['file_size'] = os.path.getsize(file_path)

    # PE Info
    json_obj['pe_info'] = dict()
    ## Compile Time
    json_obj['pe_info']['compile_time'] = get_compile_time(pe)
    ## Packer Info
    json_obj['pe_info']['packer_info'] = get_packer_info( pe )
    ## Sessions Number
    json_obj['pe_info']['sections_number'] = get_sections_number(pe)
    ## Resources
    json_obj['pe_info']['resources_info'] = get_resources_info(pe)
    ## Sections Info
    json_obj['pe_info']['sections_ino'] = get_sections_info(pe)
    ## Import Function
    json_obj['pe_info']['import_function'] = get_import_function(pe)
    # Save report file
    with open("{}.json".format(json_obj['hash']['sha256']), 'w') as f :
        json.dump(json_obj, f, indent=4)

if __name__ == '__main__' :
    if len(sys.argv) == 1 :
        #print_help()
        run("atom.exe")
        exit(0)
    if len(sys.argv) == 2 :
        file_path = sys.argv[1]
        if isfile(file_path) :
            run(file_path)