import lief
from . import colors
from lief import PE

lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR)

# print PE optionals header


def get(malware):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "OPT HEADER", " -------------------------------" + colors.DEFAULT)))
    binary = lief.parse(malware)
    optional_header = binary.optional_header
    format_str = "{:<43} {:<30}"
    format_dec = "{:<43} {:<30d}"
    format_hex = "{:<43} 0x{:<28x}"
    dll_char_str = " - ".join([str(chara).split(".")[-1]
                               for chara in optional_header.dll_characteristics_lists])
    subsystem_str = str(optional_header.subsystem).split(".")[-1]
    magic = "PE32" if optional_header.magic == PE.PE_TYPE.PE32 else "PE64"
    print((format_str.format(colors.WHITE + "Magic:" + colors.DEFAULT, magic)))
    print((format_dec.format(colors.WHITE + "Major linker version:" +
                             colors.DEFAULT,           optional_header.major_linker_version)))
    print((format_dec.format(colors.WHITE + "Minor linker version:" +
                             colors.DEFAULT,           optional_header.minor_linker_version)))
    print((format_dec.format(colors.WHITE + "Size of code:" +
                             colors.DEFAULT,                   optional_header.sizeof_code)))
    print((format_dec.format(colors.WHITE + "Size of initialized data:" +
                             colors.DEFAULT,       optional_header.sizeof_initialized_data)))
    print((format_dec.format(colors.WHITE + "Size of uninitialized data:" +
                             colors.DEFAULT,     optional_header.sizeof_uninitialized_data)))
    print((format_hex.format(colors.WHITE + "Entry point:" + colors.DEFAULT,
                             optional_header.addressof_entrypoint)))
    print((format_hex.format(colors.WHITE + "Base of code:" +
                             colors.DEFAULT,                   optional_header.baseof_code)))
    if magic == "PE32":
        print((format_hex.format(colors.WHITE + "Base of data" +
                                 colors.DEFAULT,                optional_header.baseof_data)))
        print((format_hex.format(colors.WHITE + "Image base:" +
                                 colors.DEFAULT,                     optional_header.imagebase)))
        print((format_hex.format(colors.WHITE + "Section alignment:" +
                                 colors.DEFAULT,              optional_header.section_alignment)))
        print((format_hex.format(colors.WHITE + "File alignment:" +
                                 colors.DEFAULT,                 optional_header.file_alignment)))
        print((format_dec.format(colors.WHITE + "Major operating system version:" +
                                 colors.DEFAULT, optional_header.major_operating_system_version)))
        print((format_dec.format(colors.WHITE + "Minor operating system version:" +
                                 colors.DEFAULT, optional_header.minor_operating_system_version)))
        print((format_dec.format(colors.WHITE + "Major image version:" +
                                 colors.DEFAULT,            optional_header.major_image_version)))
        print((format_dec.format(colors.WHITE + "Minor image version:" +
                                 colors.DEFAULT,            optional_header.minor_image_version)))
        print((format_dec.format(colors.WHITE + "Major subsystem version:" +
                                 colors.DEFAULT,        optional_header.major_subsystem_version)))
        print((format_dec.format(colors.WHITE + "Minor subsystem version:" +
                                 colors.DEFAULT,        optional_header.minor_subsystem_version)))
        print((format_dec.format(colors.WHITE + "WIN32 version value:" +
                                 colors.DEFAULT,            optional_header.win32_version_value)))
        print((format_hex.format(colors.WHITE + "Size of image:" +
                                 colors.DEFAULT,                  optional_header.sizeof_image)))
        print((format_hex.format(colors.WHITE + "Size of headers:" +
                                 colors.DEFAULT,                optional_header.sizeof_headers)))
        print((format_hex.format(colors.WHITE + "Checksum:" +
                                 colors.DEFAULT,                       optional_header.checksum)))
        print((format_str.format(colors.WHITE + "Subsystem:" +
                                 colors.DEFAULT,                      subsystem_str)))
        print((format_str.format(colors.WHITE + "DLL Characteristics:" +
                                 colors.DEFAULT,            dll_char_str)))
        print((format_hex.format(colors.WHITE + "Size of stack reserve:" +
                                 colors.DEFAULT,          optional_header.sizeof_stack_reserve)))
        print((format_hex.format(colors.WHITE + "Size of stack commit:" +
                                 colors.DEFAULT,           optional_header.sizeof_stack_commit)))
        print((format_hex.format(colors.WHITE + "Size of heap reserve:" +
                                 colors.DEFAULT,           optional_header.sizeof_heap_reserve)))
        print((format_hex.format(colors.WHITE + "Size of heap commit:" +
                                 colors.DEFAULT,            optional_header.sizeof_heap_commit)))
        print((format_dec.format(colors.WHITE + "Loader flags:" +
                                 colors.DEFAULT,                   optional_header.loader_flags)))
        print((format_dec.format(colors.WHITE + "Number of RVA and size:" +
                                 colors.DEFAULT,         optional_header.numberof_rva_and_size)))
