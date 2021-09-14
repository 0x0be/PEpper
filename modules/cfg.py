import lief
from . import colors

lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR)

# check if PE file supports control flow guard


def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "CFG", " -------------------------------") + colors.DEFAULT))
    binary = lief.parse(malware)
    if binary.optional_header.has(lief.PE.DLL_CHARACTERISTICS.GUARD_CF):
        print((colors.GREEN + "[" + '\u2713' +
               "]" + colors.DEFAULT + " The file supports Control Flow Guard (CFG)"))
        csv.write("1,")
    else:
        print((
            colors.RED + "[X]" + colors.DEFAULT + " The file doesn't support Control Flow Guard (CFG)"))
        csv.write("0,")
