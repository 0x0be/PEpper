import magic
import os
from . import hashes
import datetime
from . import colors
import re


# print metadata of PE


def get(malware):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "METADATA", " -------------------------------") + colors.DEFAULT))
    name = re.sub(r'.*/', '/', malware)[1:]
    format_dec = "{:<43} {:<30}"
    print((format_dec.format(colors.WHITE +
                             "File name:" + colors.DEFAULT,				str(name))))
    print((format_dec.format(colors.WHITE + "Upload time:" + colors.DEFAULT,
                             str((datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))))))
    print((format_dec.format(colors.WHITE + "File size:" + colors.DEFAULT,
                             str(os.path.getsize(malware)) + " byte")))
    print((format_dec.format(colors.WHITE + "File type:" +
                             colors.DEFAULT,           	str(magic.from_file(malware)))))
    print((format_dec.format(colors.WHITE + "MD5:" + colors.DEFAULT,
                             str(hashes.get(malware)['md5']))))
    print((format_dec.format(colors.WHITE + "SHA1:" + colors.DEFAULT,
                             str(hashes.get(malware)['sha1']))))
    print((format_dec.format(colors.WHITE + "SHA256:" + colors.DEFAULT,
                             str(hashes.get(malware)['sha256']))))
