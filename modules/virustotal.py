from . import hashes
import requests
from . import colors

# check the md5 hash of pe file with the VirusTotal Database


def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "VIRUS-TOTAL", " -------------------------------" + colors.DEFAULT)))
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': '',  # your private key here
              'resource': hashes.get(malware)['md5']}

    if params['apikey']:
        response = requests.get(url, params=params)
        result = response.json()
        if result['response_code'] == 0:
            print((colors.RED + "[X]" + colors.DEFAULT + " No\n"))
            csv.write("0%,")
        else:
            print((colors.GREEN + "[" + '\u2713' +
                   "]" + colors.DEFAULT + " Found match"))
            print((colors.WHITE + "Resource: " + colors.DEFAULT + str(result['resource'])
                   + colors.WHITE + "\nDetection ratio: " + colors.DEFAULT +
                   str(result['positives']) + " / " + str(result['total'])
                   + colors.WHITE + "\nAnalysis date: " + colors.DEFAULT + str(result['scan_date'] + "\n")))
            csv.write(str(result['positives']/result['total']) + "%,")
    else:
        print(colors.RED + "[X]" + colors.DEFAULT + " API token not found")
        csv.write("Exception,")
