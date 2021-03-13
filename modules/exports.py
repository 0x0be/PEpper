import lief
from . import colors

lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR)

# print exports of PE


def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "EXPORTS", " -------------------------------") + colors.DEFAULT))
    binary = lief.parse(malware)
    count = 0
    try:
        for exported_library in binary.exports:
            count = count + 1
            print(exported_library.name)
            for func in exported_library.entries:
                f_value = "  {:<33} 0x{:<14x}"
                print((colors.WHITE + f_value.format(func.address,
                                                     func.name) + colors.DEFAULT))
        print("\n")
        csv.write(str(count) + ",")
    except Exception as e:
        print((colors.RED + "[X]" + colors.DEFAULT + " None"))
        csv.write("0,")
