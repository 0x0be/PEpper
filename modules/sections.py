import lief
from . import colors

lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR)

# print PE sections


def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "SECTIONS", " -------------------------------") + colors.DEFAULT))
    sec = 0
    susp_sec = 0
    format_str = "{:<35} {:<35}"
    binary = lief.parse(malware)
    for section in binary.sections:
        sec += 1
        print((colors.YELLOW + section.name + colors.DEFAULT))
        print((format_str.format(colors.WHITE + "\tVirtual Address: " +
                                 colors.DEFAULT, str(section.virtual_address))))
        print((format_str.format(colors.WHITE + "\tVirtual Size: " +
                                 colors.DEFAULT, str(section.virtual_size))))
        print((format_str.format(colors.WHITE + "\tRaw Size: " +
                                 colors.DEFAULT, str(section.sizeof_raw_data))))
        print((format_str.format(colors.WHITE + "\tEntropy: " +
                                 colors.DEFAULT, str(section.entropy))))

        if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_READ):
            print((format_str.format(colors.WHITE + "\tReadable: " +
                                     colors.GREEN, "[" + str('\u2713') + "]")))
        else:
            print((format_str.format(colors.WHITE +
                                     "\tReadable: " + colors.RED, "[X]")))

        if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE):
            print((format_str.format(colors.WHITE + "\tWritable: " +
                                     colors.GREEN, "[" + str('\u2713') + "]")))
        else:
            print((format_str.format(colors.WHITE +
                                     "\tWritable: " + colors.RED, "[X]")))

        if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE):
            print((format_str.format(colors.WHITE + "\tExecutable: " +
                                     colors.GREEN, "[" + str('\u2713') + "]")))
        else:
            print((format_str.format(colors.WHITE +
                                     "\tExecutable: " + colors.RED, "[X]")))

        if section.size == 0 or (0 < section.entropy < 1) or section.entropy > 7:
            print((format_str.format(colors.WHITE + "\tSuspicious:" +
                                     colors.GREEN, "[" + str('\u2713') + "]")))
            susp_sec += 1
        else:
            print((format_str.format(colors.WHITE +
                                     "\tSuspicious: " + colors.RED, "[X]")))

    # suspicious section based on entropy
    print((colors.RED + "\n[-]" + colors.WHITE + " Suspicious section (entropy) ratio:" + colors.DEFAULT + " %i/%i" %
           (susp_sec, sec)))
    csv.write(str(susp_sec/sec) + "%,")

    # suspicious section names
    standardSectionNames = [".text", ".bss", ".rdata",
                            ".data", ".idata", ".reloc", ".rsrc"]
    suspiciousSections = 0
    for section in binary.sections:
        if not section.name in standardSectionNames:
            suspiciousSections += 1
    print((colors.RED + "[-]" + colors.WHITE + " Suspicious section (name) ratio:" + colors.DEFAULT + " %i/%i" %
           (suspiciousSections, sec)))
    csv.write(str(suspiciousSections/sec) + "%,")

    # size of code greater than size of code section
    code_sec_size = 0
    for section in binary.sections:
        if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.CNT_CODE):
            code_sec_size += section.size

    if binary.optional_header.sizeof_code > code_sec_size:
        print((colors.RED + "[X]" + colors.DEFAULT + "The size of code (%i bytes) is bigger than the size (%i bytes) "
                                                     "of code sections" %
               (binary.optional_header.sizeof_code, code_sec_size)))
        csv.write("1,")
    else:
        print((colors.GREEN + "[" + '\u2713' + "]" + colors.DEFAULT + "The size of code (%i bytes) matches the size "
                                                                      "of code sections" %
               binary.optional_header.sizeof_code))
        csv.write("0,")
