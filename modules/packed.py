import pefile
import sys
import peutils
import os
from . import colors


# check if the PE is packed


def get_rule(path):
    root_dir = os.path.dirname(sys.modules['__main__'].__file__)
    return os.path.join(root_dir, 'signatures', path)


def get(malware, csv):
    # We use a list of the most common signature (signatureDB.txt), credits goes to creators of PEid "BobSoft"
    # get all possible matches found as the signature tree is walked.
    # The last signature will always be the most precise (as more bytes will have been matched)
    # and is the one returned by the match() method.

    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "PACKED", " -------------------------------") + colors.DEFAULT))
    try:
        pe = pefile.PE(malware)
        signatures = peutils.SignatureDatabase(get_rule('packers.txt'))
        matches = signatures.match_all(pe, ep_only=True)
        array = []
        if matches:
            for item in matches:
                if item[0] not in array:
                    array.append(item[0])
                    print((colors.RED + "".join(array) + colors.DEFAULT))
            csv.write("1,")
        else:
            print((colors.GREEN +
                   "[X]" + colors.DEFAULT + " No packers signatures detected"))
            csv.write("0,")

    except Exception as e:
        print(e)
        csv.write("Exception,")
