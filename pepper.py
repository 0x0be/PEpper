#!/usr/bin/env python

from modules import banner
from modules import argv
from modules import run
from modules import output

import sys


def main():
    argv.get()
    banner.get()
    filename = sys.argv[1]
    csv = open(filename+"-output.csv", 'w')
    csv.write("id,susp_entrop_ratio,susp_name_ratio,susp_code_size,imphash,n_exports,n_antidbg,n_antivm,n_susp_api,"
              "has_gs, "
              "has_cfg,has_dep,has_aslr,has_seh,has_tls,susp_dbg_ts,n_url,n_ip,has_manifest,has_version,"
              "n_susp_strings,is_packed,"
              "has_certificate,"
              "susp_virustotal_ratio,n_yara_rules")
    run.get(filename, csv)
    csv.close()
    output.get(filename)


if __name__ == "__main__":
    main()
