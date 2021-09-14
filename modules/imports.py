import lief
from . import colors

lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR)

# print imports of PE


def get(malware):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "IMPORTS", " -------------------------------") + colors.DEFAULT))
    binary = lief.parse(malware)
    for imported_library in binary.imports:
        print((colors.YELLOW + imported_library.name + colors.DEFAULT))
        for func in imported_library.entries:
            f_value = "\t{:<10} {:<33}"
            print((f_value.format(colors.GREEN + "0x" +
                                  str(func.iat_address) + colors.DEFAULT, func.name)))
        print("\n")
