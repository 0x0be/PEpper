import lief
from . import colors

lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR)

# check if PE has a version


def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "VERSION", " -------------------------------") + colors.DEFAULT))
    binary = lief.parse(malware)
    if binary.has_resources and not binary.resources_manager.has_version:
        print((colors.RED + "[X]" + colors.DEFAULT + " PE has no version"))
        csv.write("0,")
    else:
        print((colors.GREEN + "[" + '\u2713' +
               "]" + colors.DEFAULT + " PE has a version"))
        print((str(binary.resources_manager.version.string_file_info)))
        csv.write("1,")
