import lief
from . import colors

lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR)

# check if PE support for Address Space Layout Randomization


def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "ASLR", " -------------------------------") + colors.DEFAULT))
    binary = lief.parse(malware)
    if binary.optional_header.has(lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE):
        print((colors.GREEN + "[" + '\u2713' +
               "]" + colors.DEFAULT + " The file supports Address Space Layout Randomization (ASLR)"))
        csv.write("1,")
    else:
        print((
            colors.RED + "[X]" + colors.DEFAULT + " The file doesn't support Address Space Layout Randomization (ASLR)"))
        csv.write("0,")
