import os
import sys
import lief
from . import colors

lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR)

# checks for suspicious calls


def get_rule(path):
    root_dir = os.path.dirname(sys.modules['__main__'].__file__)
    return os.path.join(root_dir, 'signatures', path)


def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "API ALERT", " -------------------------------") + colors.DEFAULT))
    suspicious_api = []
    count = 0
    with open(get_rule('alerts.txt')) as f:
        content = [x for x in (line.strip() for line in f) if x]
    try:
        binary = lief.parse(malware)
        for imported_library in binary.imports:
            for func in imported_library.entries:
                for susp in content:
                    if func.name == susp:
                        count += 1
                        suspicious_api.append(susp)
        if count > 0:
            for x in suspicious_api:
                print((colors.RED + x + colors.DEFAULT))
        else:
            print((
                colors.WHITE + "\n[*] Number of suspicious API calls: " + str(count) + colors.DEFAULT))
        f.close()

        csv.write(str(count)+",")

    except Exception as e:
        print(e)
        csv.write("Exception,")
