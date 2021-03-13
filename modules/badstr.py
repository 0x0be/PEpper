import lief
import sys
import xml.etree.ElementTree as ET
import os
import string
from . import colors

lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR)

# check for some possible bad strings hardcoded inside PE


def get_rule(path):
    root_dir = os.path.dirname(sys.modules['__main__'].__file__)
    return os.path.join(root_dir, 'signatures', path)


def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "BAD STRINGS", " -------------------------------" + colors.DEFAULT)))
    stringsXml = ET.parse(get_rule('strings.xml')).getroot()
    blacklisted = 0
    p = False
    binary = lief.parse(malware)
    strings = set()
    for sect in binary.sections:
        s = ""
        for byte in sect.content:
            if chr(byte) in string.printable:
                s += chr(byte)
            else:
                if len(s) > 3:
                    strings.add(s)
                    s = ""

    print((colors.WHITE + "Passwords:" + colors.DEFAULT))
    for r in stringsXml.find('psw').findall('item'):
        if r.text in strings:
            print(("\t" + colors.RED + r.text + colors.DEFAULT))
            blacklisted += 1
            p = True
    if not p:
        print("\tNone")
    p = False

    print((colors.WHITE + "\nAnti-Virus detection:" + colors.DEFAULT))
    for r in stringsXml.find('avs').findall('av'):
        if r.text in strings:
            print(("\t" + colors.RED + r.text + colors.DEFAULT))
            blacklisted += 1
            p = True
    if not p:
        print("\tNone")
    p = False

    print((colors.WHITE + "\nRegular Expressions:" + colors.DEFAULT))
    for r in stringsXml.find('regexs').findall('regex'):
        if r.text in strings:
            print(("\t" + colors.RED + r.text + colors.DEFAULT))
            blacklisted += 1
            p = True
    if not p:
        print("\tNone")
    p = False

    print((colors.WHITE + "\nPrivileges:" + colors.DEFAULT))
    for r in stringsXml.find('privs').findall('priv'):
        if r.text in strings:
            print(("\t" + colors.RED + r.text + colors.DEFAULT))
            blacklisted += 1
            p = True
    if not p:
        print("\tNone")
    p = False

    print((colors.WHITE + "\nOids:" + colors.DEFAULT))
    for r in stringsXml.find('oids').findall('oid'):
        if r.text in strings:
            print(("\t" + colors.RED + r.text + colors.DEFAULT))
            blacklisted += 1
            p = True
    if not p:
        print("\tNone")
    p = False

    print((colors.WHITE + "\nAgents:" + colors.DEFAULT))
    for r in stringsXml.find('agents').findall('agent'):
        if r.text in strings:
            print(("\t" + colors.RED + r.text + colors.DEFAULT))
            blacklisted += 1
            p = True
    if not p:
        print("\tNone")
    p = False

    print((colors.WHITE + "\nFile extensions:" + colors.DEFAULT))
    for r in stringsXml.find('exts').findall('ext'):
        if r.text in strings:
            print(("\t" + colors.RED + r.text + colors.DEFAULT))
            blacklisted += 1
            p = True
    if not p:
        print("\tNone")
    p = False

    print((colors.WHITE + "\nSDDLs:" + colors.DEFAULT))
    for r in stringsXml.find('sddls').findall('sddl'):
        if r.text in strings:
            print(("\t" + colors.RED + r.text + colors.DEFAULT))
            blacklisted += 1
            p = True
    if not p:
        print("\tNone")
    p = False

    allFolders = [f for fs in stringsXml.findall(
        'folders') for f in fs.findall('folder')]
    for r in allFolders:
        if r.text in strings:
            if r.attrib['name'] is not None:
                print(("\t" + colors.RED + r.text + colors.DEFAULT))
            else:
                print(("\t" + colors.RED + r.text + colors.DEFAULT))
                blacklisted += 1

    print((colors.WHITE + "\nGUIDs:" + colors.DEFAULT))
    for r in stringsXml.find('guids').findall('guid'):
        if r.text in strings:
            print(("\t" + colors.RED + r.text + colors.DEFAULT))
            blacklisted += 1
            p = True
    if not p:
        print("\tNone")
    p = False

    print((colors.WHITE + "\nRegistry:" + colors.DEFAULT))
    for r in stringsXml.find('regs').findall('reg'):
        if r.text in strings:
            print(("\t" + colors.RED + r.text + colors.DEFAULT))
            blacklisted += 1
            p = True
    if not p:
        print("\tNone")
    p = False

    print((colors.WHITE + "\nOperating Systems:" + colors.DEFAULT))
    for r in stringsXml.find('oss').findall('os'):
        if r.text in strings:
            print(("\t" + colors.RED + r.text + colors.DEFAULT))
            blacklisted += 1
            p = True
    if not p:
        print("\tNone")
    p = False

    print((colors.WHITE + "\nSandbox products:"))
    for r in stringsXml.find('products').findall('product'):
        if r.text in strings:
            print(("\t" + colors.RED + r.text + colors.DEFAULT))
            blacklisted += 1
            p = True
    if not p:
        print("\tNone")
    p = False

    print((colors.WHITE + "\nSIDs:"))
    for r in stringsXml.find('sids').findall('sid'):
        if r.text in strings:
            print(("\t" + colors.RED + r.text + colors.DEFAULT))
            blacklisted += 1
            p = True
    if not p:
        print("\tNone")
    p = False

    print((colors.WHITE + "\nProtocols:"))
    for r in stringsXml.find('protocols').findall('protocol'):
        if r.text in strings:
            print(("\t" + colors.RED + r.text + colors.DEFAULT))
            blacklisted += 1
            p = True
    if not p:
        print("\tNone")
    p = False

    print((colors.WHITE + "\nUtilities:" + colors.DEFAULT))
    for r in stringsXml.find('utilities').findall('item'):
        if r.text in strings:
            print(("\t" + colors.RED + r.text + colors.DEFAULT))
            blacklisted += 1
            p = True
    if not p:
        print("\tNone")
    p = False

    keys = 0
    print((colors.WHITE + "\nKeyboard keys:" + colors.DEFAULT))
    for r in stringsXml.find('keys').findall('key'):
        if r.text in strings:
            print(("\t" + colors.RED + r.text + colors.DEFAULT))
            blacklisted += 1
            keys += 1
            p = True
    if not p:
        print("\tNone")
    p = False

    print((colors.WHITE + "\nOperating Systems:" + colors.DEFAULT))
    for r in stringsXml.find('oss').findall('os'):
        if r.text in strings:
            print(("\t" + colors.RED + r.text + colors.DEFAULT))
            blacklisted += 1
            p = True
    if not p:
        print("\tNone")
    p = False

    print((colors.WHITE + "\nEvents:" + colors.DEFAULT))
    for r in stringsXml.find('events').findall('event'):
        if r.text in strings:
            print(("\t" + colors.RED + r.text + colors.DEFAULT))
            blacklisted += 1
            insults = 0
            p = True
    if not p:
        print("\tNone")
    p = False

    print((colors.WHITE + "\nInsult:" + colors.DEFAULT))
    for r in stringsXml.find('insults').findall('insult'):
        if r.text in strings:
            print(("\t" + colors.RED + r.text + colors.DEFAULT))
            blacklisted += 1
            insults += 1
            p = True
    if not p:
        print("\tNone")

    csv.write(str(blacklisted)+",")
