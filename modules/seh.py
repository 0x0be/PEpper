import lief
from . import colors

lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR)

# check if PE file use Structured Error Handling (SEH)


def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "SEH", " -------------------------------") + colors.DEFAULT))
    binary = lief.parse(malware)
    if binary.optional_header.has(lief.PE.DLL_CHARACTERISTICS.NO_SEH):
        print((
            colors.RED + "[X]" + colors.DEFAULT + " The file doesn't support Structured Exception Handling (SEH)"))
        csv.write("0,")
    else:
        print((colors.GREEN + "[" + '\u2713' +
               "]" + colors.DEFAULT + " The file supports Structured Exception Handling (SEH)"))
        csv.write("1,")
