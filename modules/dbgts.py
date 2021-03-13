import lief
from . import colors
import datetime

lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR)

# check for suspicious debug timestamps


def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "DEBUG TIME-STAMP", " -------------------------------" + colors.DEFAULT)))
    binary = lief.parse(malware)
    if binary.has_debug:
        debug_list = binary.debug
        for item in debug_list:
          ts = item.timestamp
        dbg_time = datetime.datetime.fromtimestamp(ts)
        if dbg_time > datetime.datetime.now():
            print((colors.RED + '[' + '\u2713' + "]" + colors.DEFAULT + " The age (%s) of the debug file is suspicious" % (
                str(dbg_time))))
            csv.write("1,")

        else:
            print((colors.GREEN + "[X]" + colors.DEFAULT + " Not suspicious"))
            csv.write("0,")
    else:
        print((colors.RED + "[X]" + colors.DEFAULT +
               " PE has not debug object"))
        csv.write("Exception,")
