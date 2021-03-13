import lief
from . import colors

lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR)

# malwares employ Thread Local Storage callbacks to evade debugger messages


def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "TLS", " -------------------------------") + colors.DEFAULT))
    binary = lief.parse(malware)
    if not binary.has_tls:
        print((colors.GREEN + "[X]" + colors.DEFAULT + " None"))
        csv.write("0,")

    else:
        csv.write("1,")
        table_entry_address = binary.tls.addressof_callbacks
        callback = binary.get_content_from_virtual_address(
            table_entry_address, 4)
        callback = '0x' + "".join(["{0:02x}".format(x)
                                   for x in callback[::-1]])
        while int(callback, 16) != 0:
            print(('\t' + callback))
            table_entry_address += 4
            callback = binary.get_content_from_virtual_address(
                table_entry_address, 4)
            callback = '0x' + "".join(["{0:02x}".format(x) for x in callback])
