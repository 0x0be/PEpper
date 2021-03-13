import yara
import os
import sys
from . import colors
import string


# checks if the PE matches some YARA rules (database: ~/rules)


def get_yara(path):
    root_dir = os.path.dirname(sys.modules['__main__'].__file__)
    return os.path.join(root_dir, 'rules', path)


def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "YARA RULES", " -------------------------------") + colors.DEFAULT))
    rules = yara.compile(filepaths={'AntiVM/DB': get_yara('Antidebug_AntiVM_index.yar'),
                                    'Crypto': get_yara('Crypto_index.yar'),
                                    'CVE': get_yara('CVE_Rules_index.yar'),
                                    'Exploit': get_yara('Exploit-Kits_index.yar'),
                                    'Document': get_yara('Malicious_Documents_index.yar'),
                                    'Malware': get_yara('malware_index.yar'),
                                    'Packers': get_yara('Packers_index.yar'),
                                    'Webshell': get_yara('Webshells_index.yar')})

    strings_list = []
    format_str = "{:<35} {:<1} {:<1}"

    with open(malware, 'rb') as f:
        matches = rules.match(data=f.read())
    if matches:
        for x in matches:
            print((colors.YELLOW + str(x.rule) + colors.DEFAULT))
            print((colors.WHITE + "\tType: " + colors.RED + str(x.namespace)))
            print((colors.WHITE + "\tTags: " + colors.DEFAULT + "".join(x.tags)
                   if x.tags else colors.WHITE + "\tTags: " + colors.DEFAULT + "None"))
            print((colors.WHITE + "\tMeta:" + colors.DEFAULT))
            print((colors.WHITE + "\t\tDate: " +
                   colors.DEFAULT + str(x.meta.get('date'))))
            print((colors.WHITE + "\t\tVersion: " +
                   colors.DEFAULT + str(x.meta.get('version'))))
            print((colors.WHITE + "\t\tDescription: " +
                   colors.DEFAULT + str(x.meta.get('description'))))
            print((colors.WHITE + "\t\tAuthor: " +
                   colors.DEFAULT + str(x.meta.get('author'))))
            if not x.strings:
                print((colors.WHITE + "\tStrings: " + colors.DEFAULT + "None"))
            else:
                for i in x.strings:
                    strings_list.append(i[2])
                print((colors.WHITE + "\tStrings: " + colors.DEFAULT))
                non_printable_count = 0
                for i in list(set(strings_list)):
                    if all(str(c) in string.printable for c in i):
                        print(("\t\t" + format_str.format(str(i), colors.WHITE +
                                                          "| Occurrences:" + colors.DEFAULT, str(strings_list.count(i)))))
                    else:
                        non_printable_count += 1
                if non_printable_count > 0:
                    print("\t\t[X] " + str(non_printable_count) + " string(s) not printable")
                del(strings_list[:])
            print("\n")
        csv.write(str(len(matches)))
    else:
        print((colors.RED + "[X] No" + colors.DEFAULT))
        csv.write(str(len(matches)))
