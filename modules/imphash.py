import pefile
import sys
import os
from . import colors

# Computes a fingerprint of the binary's IAT (Import Address Table).
# In a PE (Portable Executable) file, IAT contains the list of the dynamically linked libraries
# and functions a given binary needs to run. Thus, the idea here is:
# if two binaries have the same "imphash", there are high chances they have similar objectives.


def get_rule(path):
    root_dir = os.path.dirname(sys.modules['__main__'].__file__)
    return os.path.join(root_dir, 'signatures', path)


# print the imphash
def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "IMP-HASH", " -------------------------------") + colors.DEFAULT))
    try:
        pe = pefile.PE(malware)
        global susp_imp
        susp_imp = False
        print((pe.get_imphash()))
        csv.write(pe.get_imphash()+",")

    except Exception as e:
        print(e)
        csv.write("Exception,")
