import lief
from . import colors

lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR)

# print the PE header


def get(malware):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "HEADER", " -------------------------------" + colors.DEFAULT)))
    binary = lief.parse(malware)
    header = binary.header
    format_str = "{:<43} {:<30}"
    format_dec = "{:<43} {:<30d}"
    char_str = " - ".join([str(chara).split(".")[-1]
                           for chara in header.characteristics_list])
    print((format_str.format(colors.WHITE + "Signature:" +
                             colors.DEFAULT,               "".join(map(chr, header.signature)))))
    print((format_str.format(colors.WHITE + "Machine:" +
                             colors.DEFAULT,                 str(header.machine))))
    print((format_dec.format(colors.WHITE + "Number of sections:" +
                             colors.DEFAULT,      header.numberof_sections)))
    print((format_dec.format(colors.WHITE + "Time Date stamp:" +
                             colors.DEFAULT,         header.time_date_stamps)))
    print((format_dec.format(colors.WHITE + "Pointer to symbols:" +
                             colors.DEFAULT,      header.pointerto_symbol_table)))
    print((format_dec.format(colors.WHITE + "Number of symbols:" +
                             colors.DEFAULT,       header.numberof_symbols)))
    print((format_dec.format(colors.WHITE + "Size of optional header:" +
                             colors.DEFAULT, header.sizeof_optional_header)))
    print((format_str.format(colors.WHITE + "Characteristics:" +
                             colors.DEFAULT,         char_str)))
