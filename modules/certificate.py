import lief
import datetime
import time
from . import colors
from lief.PE import oid_to_string

lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR)

# print PE certificates


def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "CERTIFICATE", " -------------------------------") + colors.DEFAULT))
    binary = lief.parse(malware)
    format_str = "{:<33} {:<30}"
    format_dec = "{:<33} {:<30d}"

    if binary.has_signatures:
        for item in binary.signatures:
            for cert in item.certificates:
                valid_from = "-".join(map(str, cert.valid_from[:3]))
                dt = datetime.datetime.strptime(valid_from, '%Y-%m-%d')
                timestamp = time.mktime(dt.timetuple())
                cert_from = datetime.datetime.fromtimestamp(timestamp)

                valid_to = "-".join(map(str, cert.valid_to[:3]))
                dt = datetime.datetime.strptime(valid_to, '%Y-%m-%d')
                timestamp = time.mktime(dt.timetuple())
                cert_to = datetime.datetime.fromtimestamp(timestamp)

                sn_str = ":".join(
                    ["{:02x}".format(e) for e in cert.serial_number])

                if cert_from > datetime.datetime.now() or cert_to < datetime.datetime.now():
                    print((
                        colors.RED + "[X]" + colors.DEFAULT + " Invalid certificate"))
                    valid_from_str = "-".join(map(str, cert.valid_from[:3])) + " " + ":".join(
                        map(str, cert.valid_from[3:]))
                    valid_to_str = "-".join(map(str, cert.valid_to[:3])) + " " + ":".join(
                        map(str, cert.valid_to[3:]))
                    print((format_dec.format(colors.WHITE + "Version:" +
                                             colors.DEFAULT,             cert.version)))
                    print((format_str.format(colors.WHITE +
                                             "Serial Number:" + colors.DEFAULT,       sn_str)))
                    print((format_str.format(colors.WHITE + "Signature Algorithm:" +
                                             colors.DEFAULT, oid_to_string(cert.signature_algorithm))))
                    print((format_str.format(colors.WHITE + "Valid from:" +
                                             colors.DEFAULT,          valid_from_str)))
                    print((format_str.format(colors.WHITE + "Valid to:" +
                                             colors.DEFAULT,            valid_to_str)))
                    print((format_str.format(colors.WHITE + "Issuer:" +
                                             colors.DEFAULT,              cert.issuer)))
                    print((format_str.format(colors.WHITE + "Subject:" +
                                             colors.DEFAULT,             cert.subject)))
                    print('\n')
                else:
                    print((
                        colors.GREEN + "[" + '\u2713' + "]" + colors.DEFAULT + " Valid certificate"))
                    valid_from_str = "-".join(map(str, cert.valid_from[:3])) + " " + ":".join(
                        map(str, cert.valid_from[3:]))
                    valid_to_str = "-".join(map(str, cert.valid_to[:3])) + " " + ":".join(
                        map(str, cert.valid_to[3:]))
                    print((format_dec.format(colors.WHITE + "Version:" +
                                             colors.DEFAULT,             cert.version)))
                    print((format_str.format(colors.WHITE +
                                             "Serial Number:" + colors.DEFAULT,       sn_str)))
                    print((format_str.format(colors.WHITE + "Signature Algorithm:" +
                                             colors.DEFAULT, oid_to_string(cert.signature_algorithm))))
                    print((format_str.format(colors.WHITE + "Valid from:" +
                                             colors.DEFAULT,          valid_from_str)))
                    print((format_str.format(colors.WHITE + "Valid to:" +
                                             colors.DEFAULT,            valid_to_str)))
                    print((format_str.format(colors.WHITE + "Issuer:" +
                                             colors.DEFAULT,              cert.issuer)))
                    print((format_str.format(colors.WHITE + "Subject:" +
                                             colors.DEFAULT,             cert.subject)))
                    print('\n')

            csv.write("1,")

    if not binary.has_signatures:
        print((colors.RED +
               "[X]" + colors.DEFAULT + " None"))
        csv.write("0,")
