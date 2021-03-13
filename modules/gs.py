import lief
from . import colors

lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR)

# check if PE supports cookies on the stack (GS)


def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "GS", " -------------------------------") + colors.DEFAULT))
    binary = lief.parse(malware)
    if binary.has_configuration:
        if binary.load_configuration.security_cookie == 0:
            print((
                colors.RED + "[X]" + colors.DEFAULT + " The file doesn't support cookies on the stack (GS)"))
            csv.write("0,")
        else:
            print((colors.GREEN + "[" + '\u2713' +
                   "]" + colors.DEFAULT + " The file supports cookies on the stack (GS)"))
            csv.write("1,")
    else:
        print((colors.RED + "[X]" + colors.DEFAULT +
               " Binary has no configuration"))
        csv.write("Exception,")
