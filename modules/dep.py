import lief
from . import colors

lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR)

# check if PE supports Data Execution Prevention


def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "DEP", " -------------------------------") + colors.DEFAULT))
    binary = lief.parse(malware)
    if binary.optional_header.has(lief.PE.DLL_CHARACTERISTICS.NX_COMPAT):
        print((colors.GREEN + "[" + '\u2713' +
               "]" + colors.DEFAULT + " The file supports Data Execution Prevention (DEP)"))
        csv.write("1,")
    else:
        print((
            colors.RED + "[X]" + colors.DEFAULT + " The file doesn't support Data Execution Prevention (DEP)"))
        csv.write("0,")
