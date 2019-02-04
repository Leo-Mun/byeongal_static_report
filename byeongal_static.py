import sys
import os
import pefile
import peutils
import hashlib
import json
import magic
import yara
import string
import ssdeep
import tlsh

_ROOT = os.path.abspath(os.path.dirname(__file__))
_USER_DB = os.path.join(_ROOT, 'signatures', 'userdb.txt')
_APIALERT = os.path.join(_ROOT, 'signatures', 'apialertv6.1.txt')
_ANTIDEBUG = os.path.join(_ROOT, 'signatures', 'AntiDebugging.yara')

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
    printable = set(string.printable)
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
        va = hex(section.VirtualAddress)
        vs = hex(section.Misc_VirtualSize)
        srd = hex(section.SizeOfRawData)
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

def get_anti_debug_info( file_data ) :
    rules = yara.compile(_ANTIDEBUG)

    matches = rules.match(data = file_data)

    ret = []
    for each in matches :
        ret.append(each.rule)

    return ret

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

def get_machine_info( pe ) :
    return hex(pe.FILE_HEADER.Machine)

def get_size_of_optional_header( pe ) :
    return pe.FILE_HEADER.SizeOfOptionalHeader

def get_characteristics( pe ) :
    return hex(pe.FILE_HEADER.Characteristics)

def get_major_linker_version ( pe ) :
    return pe.OPTIONAL_HEADER.MajorLinkerVersion

def get_minor_linker_version ( pe ) :
    return pe.OPTIONAL_HEADER.MinorLinkerVersion

def get_size_of_code( pe ) :
    return pe.OPTIONAL_HEADER.SizeOfCode

def get_size_of_initialized_data(pe) :
    return pe.OPTIONAL_HEADER.SizeOfInitializedData

def get_size_of_uninitialized_data(pe) :
    return pe.OPTIONAL_HEADER.SizeOfUninitializedData

def get_address_of_entry_point(pe) :
    return pe.OPTIONAL_HEADER.AddressOfEntryPoint

def get_base_of_code( pe ) :
    return pe.OPTIONAL_HEADER.BaseOfCode

def get_base_of_data( pe ) :
    try :
        return pe.OPTIONAL_HEADER.BaseOfData
    except :
        return None

def get_image_base(pe) :
    return pe.OPTIONAL_HEADER.ImageBase

def get_section_alignment(pe) :
    return pe.OPTIONAL_HEADER.SectionAlignment

def get_file_alignment(pe) :
    return pe.OPTIONAL_HEADER.FileAlignment

def get_major_operating_system_version(pe) :
    return pe.OPTIONAL_HEADER.MajorOperatingSystemVersion

def get_minor_operating_system_version(pe) :
    return pe.OPTIONAL_HEADER.MinorOperatingSystemVersion

def get_major_image_version(pe) :
    return pe.OPTIONAL_HEADER.MajorImageVersion

def get_minor_image_version(pe) :
    return pe.OPTIONAL_HEADER.MinorImageVersion

def get_major_subsystem_version(pe) :
    return pe.OPTIONAL_HEADER.MajorSubsystemVersion

def get_minor_subsystem_version(pe) :
    return pe.OPTIONAL_HEADER.MinorSubsystemVersion

def get_size_of_image(pe) :
    return pe.OPTIONAL_HEADER.SizeOfImage

def get_size_of_headers(pe) :
    return pe.OPTIONAL_HEADER.SizeOfHeaders

def get_check_sum(pe) :
    return pe.OPTIONAL_HEADER.CheckSum

def get_subsystem(pe) :
    return pe.OPTIONAL_HEADER.Subsystem

def get_dll_characteristics(pe) :
    return hex(pe.OPTIONAL_HEADER.DllCharacteristics)

def get_size_of_stack_reserve(pe) :
    return pe.OPTIONAL_HEADER.SizeOfStackReserve

def get_size_of_stack_reserve(pe) :
    return pe.OPTIONAL_HEADER.SizeOfStackReserve

def get_size_of_stack_commit(pe) :
    return pe.OPTIONAL_HEADER.SizeOfStackCommit

def get_size_of_heap_reserve(pe) :
    return pe.OPTIONAL_HEADER.SizeOfHeapReserve

def get_size_of_heap_commit(pe) :
    return pe.OPTIONAL_HEADER.SizeOfHeapCommit

def get_loader_flags(pe) :
    return pe.OPTIONAL_HEADER.LoaderFlags

def get_number_of_rva_and_sizes(pe) :
    return pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

def run( file_path ) :
    with open(file_path, 'rb') as f :
        file_data = f.read()

    pe = pefile.PE(file_path)
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
    ## Export Function
    json_obj['pe_info']['export_function'] = get_export_function(pe)
    ## Machine
    json_obj['pe_info']['machine'] = get_machine_info( pe )
    ## SizeOfOptionalHeader
    json_obj['pe_info']['size_of_optional_header'] = get_size_of_optional_header(pe)
    ## Characteristics
    json_obj['pe_info']['characteristics'] = get_characteristics(pe)
    ## MajorLinkerVersion
    json_obj['pe_info']['major_linker_version'] = get_major_linker_version(pe)
    ## MinorLinkerVersion
    json_obj['pe_info']['minor_linker_version'] = get_minor_linker_version(pe)
    ## SizeOfCode
    json_obj['pe_info']['size_of_code'] = get_size_of_code(pe)
    ## SizeOfInitializedData
    json_obj['pe_info']['size_of_initialized_data'] = get_size_of_initialized_data(pe)
    ## SizeOfUninitializedData
    json_obj['pe_info']['size_of_uninitialized_data'] = get_size_of_uninitialized_data(pe)
    ## AddressOfEntryPoint
    json_obj['pe_info']['address_of_entry_point'] = get_address_of_entry_point(pe)
    ## BaseOfCode
    json_obj['pe_info']['base_of_code'] = get_base_of_code(pe)
    ## BaseOfData
    json_obj['pe_info']['base_of_data'] = get_base_of_data(pe)
    ## ImageBase
    json_obj['pe_info']['image_base'] = get_image_base(pe)
    ## SectionAlignment
    json_obj['pe_info']['section_alignment'] = get_section_alignment(pe)
    ## FileAlignment
    json_obj['pe_info']['file_alignment'] = get_file_alignment(pe)
    ## MajorOperatingSystemVersion
    json_obj['pe_info']['major_operating_system_version'] = get_major_operating_system_version(pe)
    ## MinorOperatingSystemVersion
    json_obj['pe_info']['minor_operating_system_version'] = get_minor_operating_system_version(pe)
    ## MajorImageVersion
    json_obj['pe_info']['major_image_version'] = get_major_image_version(pe)
    ## MinorImageVersion
    json_obj['pe_info']['minor_image_version'] = get_minor_image_version(pe)
    ## MajorSubsystemVersion
    json_obj['pe_info']['major_subsystem_version'] = get_major_subsystem_version(pe)
    ## MinorSubsystemVersion
    json_obj['pe_info']['minor_subsystem_version'] = get_minor_subsystem_version(pe)
    ## SizeOfImage
    json_obj['pe_info']['size_of_image'] = get_size_of_image(pe)
    ## SizeOfHeaders
    json_obj['pe_info']['size_of_headers'] = get_size_of_headers(pe)
    ## CheckSum
    json_obj['pe_info']['check_sum'] = get_check_sum(pe)
    ## Subsystem
    json_obj['pe_info']['subsystem'] = get_subsystem(pe)
    ## DllCharacteristics
    json_obj['pe_info']['dll_characteristics'] = get_dll_characteristics(pe)
    ## SizeOfStackReserve
    json_obj['pe_info']['size_of_stack_reserve'] = get_size_of_stack_reserve(pe)
    ## SizeOfStackCommit
    json_obj['pe_info']['size_of_stack_commit'] = get_size_of_stack_commit(pe)
    ## SizeOfHeapReserve
    json_obj['pe_info']['size_of_heap_reserve'] = get_size_of_heap_reserve(pe)
    ## SizeOfHeapCommit
    json_obj['pe_info']['size_of_heap_commit'] = get_size_of_heap_commit(pe)
    ## LoaderFlags
    json_obj['pe_info']['loader_flags'] = get_loader_flags(pe)
    ## NumberOfRvaAndSizes
    json_obj['pe_info']['number_of_rva_and_sizes'] = get_number_of_rva_and_sizes(pe)

    # Yaraget_number_of_rva_and_sizes(pe)
    json_obj['yara'] = dict()
    ## Anti Debugging
    json_obj['yara']['anti_debug_info'] = get_anti_debug_info( file_data )

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
