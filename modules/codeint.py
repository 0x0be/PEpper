import lief
from . import colors

lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR)

# PE ignores Code Integrity? Let's find out together


def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "CODE INTEGRITY", " -------------------------------" + colors.DEFAULT)))
    binary = lief.parse(malware)
    if binary.has_configuration:
        if isinstance(binary.load_configuration, lief.PE.LoadConfigurationV2) and binary.load_configuration.code_integrity.catalog == 0xFFFF:
            print((colors.RED +
                   "[X]" + colors.DEFAULT + " The file doesn't support Code Integrity"))
            csv.write("0,")
        else:
            print((colors.GREEN + "[" + '\u2713' +
                   "]" + colors.DEFAULT + " The file supports Code Integrity"))
            csv.write("1,")
    else:
        print((colors.RED + "[X]" + colors.DEFAULT +
               " Binary has no configuration"))
        csv.write("Exception,")
