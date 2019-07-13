import sys
from . import colors


# check the script's argument (argparse who you are?)


def get():
    if len(sys.argv) != 2:
        print(colors.ORANGE + "Usage: ./pepper ./malware_dir" + colors.ORANGE)
        sys.exit(1)
