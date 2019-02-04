import sys
import os
import pefile
import peutils
import hashlib
import magic
import yara
import ssdeep
import tlsh

import simplejson as json

_ROOT = os.path.abspath(os.path.dirname(__file__))
_USER_DB = os.path.join(_ROOT, 'signatures', 'userdb.txt')
#_ANTIDEBUG = os.path.join(_ROOT, 'signatures', 'AntiDebugging.yara')

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
    return pe.FILE_HEADER.TimeDateStamp

def get_packer_info( pe ) :
    signatures = peutils.SignatureDatabase(_USER_DB)
    matches = signatures.match_all(pe, ep_only=True)
    array = []
    if matches:
        for item in matches:
            if item[0] not in array:
                array.append(item[0])
    return array

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
                            raw_data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                            raw_data = [ format(i, '#04x') for i in raw_data ]
                            lang = pefile.LANG.get(resource_lang.data.lang, '*unknown*')
                            sublang = pefile.get_sublang_name_for_lang(resource_lang.data.lang, resource_lang.data.sublang)
                            res_array.append({"name": name, "data": raw_data, "offset": hex(resource_lang.data.struct.OffsetToData),"size": resource_lang.data.struct.Size, "language": lang, "sublanguage": sublang})
    except :
        pass
    return res_array

def get_sections_info( pe ) :
    array = []
    for section in pe.sections:
        if section.SizeOfRawData == 0 or ( 0 < section.get_entropy() < 1) or section.get_entropy() > 7 :
            suspicious = True
        else:
            suspicious = False
        scn = section.Name
        md5 = section.get_hash_md5()
        sha1 = section.get_hash_sha1()
        spc = suspicious
        va = section.VirtualAddress
        vs = section.Misc_VirtualSize
        srd = section.SizeOfRawData
        entropy = section.get_entropy()
        array.append({"name": scn.decode().strip(' \t\r\n\0'), "hash_md5": md5, "hash_sha1": sha1, "suspicious": spc, "virtual_address": va, "virtual_size": vs, "size_raw_data": srd, "entropy" : entropy})

    return array

def get_import_function( pe ) :
    array = []
    library = set()
    libdict = {}
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll
            if dll == None :
                continue
            dll = dll.decode().strip(' \t\r\n\0')
            for imp in entry.imports:
                address = hex(imp.address)
                function = imp.name
                ordinal = imp.ordinal
                function = function.decode().strip(' \t\r\n\0')
                if dll not in library:
                    library.add(dll)
                array.append({"library": dll, "address": address, "function": function, "ordinal" : ordinal})

        for key in library:
            libdict[key] = []

        for lib in library:
            for item in array:
                if lib == item['library']:
                    libdict[lib].append({"address": item['address'], "function": item['function'], "ordinal" : item['ordinal']})
    except:
        pass

    return libdict

def get_export_function( pe ) :
    array = []
    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name == None :
                continue
            # No dll
            address = hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)
            function = exp.name.decode().strip(' \t\r\n\0')
            array.append({"address": address, "function": function})
    except:
        pass
    return array

# def get_anti_debug_info( file_data ) :
#     rules = yara.compile(_ANTIDEBUG)
#
#     matches = rules.match(data = file_data)
#
#     ret = []
#     for each in matches :
#         ret.append(each.rule)
#
#     return ret

def get_string( file_data ) :
    printable = set(string.printable)
    ret = []
    found_str = ""
    for char in file_data :
        try :
            char = chr(char)
            if char in printable :
                found_str += char
            elif len(found_str) >= 4 :
                ret.append(found_str)
                found_str = ""
            else :
                found_str = ""
        except :
            found_str = ""
    return ret

def get_fuzzy_hash( context ) :
    ret = dict()
    ret['ssdeep'] = ssdeep.hash(context)
    ret['tlsh'] = tlsh.hash(context)
    return ret

def get_feature_from_file_header( pe ) :
    FILE_HEADER = ['Machine', 'NumberOfSections', 'TimeDateStamp', 'PointerToSymbolTable', 'NumberOfSymbols', 'SizeOfOptionalHeader', 'Characteristics']
    ret = dict()
    if hasattr(pe, 'FILE_HEADER') :
        for each in FILE_HEADER :
            ret[each] = getattr(pe.FILE_HEADER, each, None)
    return ret

def get_feature_from_optional_header( pe ) :
    OPTIONAL_HEADER = ['Structure', 'Magic', 'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode',
                       'SizeOfInitializedData', 'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode',
                       'BaseOfData', 'ImageBase', 'SectionAlignment', 'FileAlignment', 'MajorOperatingSystemVersion',
                       'MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion',
                       'MinorSubsystemVersion', 'Reserved1', 'SizeOfImage', 'SizeOfHeaders', 'CheckSum', 'Subsystem',
                       'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve',
                       'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes']
    ret = dict()
    if hasattr(pe, 'OPTIONAL_HEADER') :
        for each in OPTIONAL_HEADER :
            ret[each] = getattr(pe.FILE_HEADER, each, None)
    return ret


def run( file_path ) :
    with open(file_path, 'rb') as f :
        file_data = f.read()

    pe = pefile.PE( data = file_data )
    json_obj = dict()

    # File Name
    json_obj['name'] = os.path.basename(file_path)

    # Dll
    json_obj['dll'] = pe.is_dll()

    # Hash
    json_obj['hash'] = dict()
    ## Cryptographic Hash
    json_obj['hash']['md5'], json_obj['hash']['sha1'], json_obj['hash']['sha256'] = get_hash(file_path)

    # Magic
    json_obj['file_type'] = magic.from_file(file_path)

    # File Size
    json_obj['file_size'] = os.path.getsize(file_path)

    # String
    json_obj['string'] = get_string(file_data)

    # PE Info
    json_obj['pe_info'] = dict()
    ## Imphash
    json_obj['pe_info']['imphash'] = get_imphash(pe)
    ## From File Header
    json_obj['pe_info']['file_header'] = get_feature_from_file_header( pe )
    ## From Optional Header
    json_obj['pe_info']['optional_header'] = get_feature_from_optional_header( pe )
    ## Packer Info
    json_obj['pe_info']['packer_info'] = get_packer_info(pe)

    # Yara
    json_obj['yara'] = dict()
    ## Anti Debugging
    #json_obj['yara']['anti_debug_info'] = get_anti_debug_info( file_data )

    # Fuzzy Hash
    json_obj['fuzzy_hash'] = get_fuzzy_hash( file_data )

    # Save report file
    with open("{}.json".format(json_obj['hash']['sha256']), 'w') as f :
        json.dump(json_obj, f, indent=4)

if __name__ == '__main__' :
    if len(sys.argv) == 1 :
        print_help()
        exit(0)
    if len(sys.argv) == 2 :
        file_path = sys.argv[1]
        if isfile(file_path) :
            run(file_path)
