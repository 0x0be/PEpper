from modules import metadata
from modules import url
from modules import virustotal
from modules import fileheader
from modules import optheader
from modules import sections
from modules import imports
from modules import exports
from modules import certificate
from modules import manifest
from modules import version
from modules import yarar
from modules import imphash
from modules import antidbg
from modules import antivm
from modules import apialert
from modules import cfg
from modules import dep
from modules import aslr
from modules import seh
from modules import packed
from modules import gs
from modules import codeint
from modules import dbgts
from modules import tls
from modules import badstr
import os


# run the analysis against multiple or single PE


def get(argv, csv):
    if os.path.isdir(argv):
        mal_directory = argv
        for mal in (os.listdir(mal_directory)):
            malware = mal_directory + "/" + mal
            csv.write("\n"+mal+",")
            metadata.get(malware)
            fileheader.get(malware)
            optheader.get(malware)
            sections.get(malware, csv)
            imphash.get(malware, csv)
            imports.get(malware)
            exports.get(malware, csv)
            antidbg.get(malware, csv)
            antivm.get(malware, csv)
            apialert.get(malware, csv)
            codeint.get(malware, csv)
            cfg.get(malware, csv)
            dep.get(malware, csv)
            aslr.get(malware, csv)
            seh.get(malware, csv)
            gs.get(malware, csv)
            tls.get(malware, csv)
            codeint.get(malware, csv)
            dbgts.get(malware, csv)
            url.get(malware, csv)
            manifest.get(malware, csv)
            version.get(malware, csv)
            badstr.get(malware, csv)
            packed.get(malware, csv)
            certificate.get(malware, csv)
            virustotal.get(malware, csv)
            yarar.get(malware, csv)

    else:
        malware = argv
        csv.write("\n"+malware+",")
        metadata.get(malware)
        fileheader.get(malware)
        optheader.get(malware)
        sections.get(malware, csv)
        imphash.get(malware, csv)
        imports.get(malware)
        exports.get(malware, csv)
        antidbg.get(malware, csv)
        antivm.get(malware, csv)
        apialert.get(malware, csv)
        codeint.get(malware, csv)
        cfg.get(malware, csv)
        dep.get(malware, csv)
        aslr.get(malware, csv)
        seh.get(malware, csv)
        gs.get(malware, csv)
        tls.get(malware, csv)
        codeint.get(malware, csv)
        dbgts.get(malware, csv)
        url.get(malware, csv)
        manifest.get(malware, csv)
        version.get(malware, csv)
        badstr.get(malware, csv)
        packed.get(malware, csv)
        certificate.get(malware, csv)
        virustotal.get(malware, csv)
        yarar.get(malware, csv)
