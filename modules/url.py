#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
from . import stringstat
from . import colors

# check for presence of IP/URL in PE


def valid_ip(address):
    try:
        host_bytes = address.split('.')
        valid = [int(b) for b in host_bytes]
        valid = [b for b in valid if b >= 0 and b <= 255]
        return len(host_bytes) == 4 and len(valid) == 4
    except:
        return False


def get(malware, csv):
    print(colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "URL", " -------------------------------") + colors.DEFAULT)
    ip_list = []
    file_list = []
    url_list = []
    strings_list = list(stringstat.get_result(malware))

    # Strings analysis
    for string in strings_list:

        if len(string) < 2000:
            # URL list
            urllist = re.findall(
                r'((smb|srm|ssh|ftps?|file|https?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\\.&](#!)?)*)', string, re.MULTILINE)
            if urllist:
                for url in urllist:
                    url_list.append(re.sub(r'\(|\)|;|,|\$', '', url[0]))

            # IP list
            iplist = re.findall(r'[0-9]+(?:\.[0-9]+){3}', string, re.MULTILINE)
            if iplist:
                for ip in iplist:
                    if valid_ip(str(ip)) and not re.findall(r'[0-9]{1,}\.[0-9]{1,}\.[0-9]{1,}\.0', str(ip)):
                        ip_list.append(str(ip))

            # FILE list
            fname = re.findall(
                "(.+(\.([a-z]{2,3}$)|\/.+\/|\\\.+\\\))+", string, re.IGNORECASE | re.MULTILINE)
            if fname:
                for word in fname:
                    file_list.append(word[0])

    ip_list = list(set([item for item in ip_list]))
    url_list = list(set([item for item in url_list]))

    if url_list:
        print("\n".join(url_list))
        csv.write(str(len(url_list))+",")
    else:
        print(colors.RED + "[X]" + colors.DEFAULT + " No URL")
        csv.write("0,")

    print(colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "IP", " -------------------------------") + colors.DEFAULT)
    if ip_list:
        print("\n".join(ip_list))
        csv.write(str(len(ip_list))+",")
    else:
        print(colors.RED + "[X]" + colors.DEFAULT + " None")
        csv.write("0,")
