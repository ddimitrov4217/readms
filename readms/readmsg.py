# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

import re
from readms.readole import OLE
from readms.readutl import dump_hex
from readms.readpst import PropertyValue
from readms.metapst import enrich_prop_code

# [MS-OXMSG]: Outlook Item (.msg) File Format
# Описанието на формата се намира на
# https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxmsg
# https://interoperability.blob.core.windows.net/files/MS-OXMSG/[MS-OXMSG].pdf

def test_content(file):
    with OLE(file) as ole:
        for _level, dire in ole.dire_trip(start=0):
            obuf = ole.dire_read(dire)
            print("%s, len=%d" % (dire.name, len(obuf)))
            dump_hex(obuf[:512])


def test_properties(file):
    prop_name_pattern = re.compile(
        r'__substg1.0_(?P<code>[0-9A-F]{4})'
        r'(?P<type>[0-9A-F]{4})(?:[-](?P<index>[0-9]{1,}))?')

    with OLE(file) as ole:
        for _level, dire in ole.dire_trip(start=0, skip='attach|recip'):
            if not prop_name_pattern.match(dire.name):
                continue

            found = prop_name_pattern.search(dire.name)
            prop_code = [ dict(propTag=int(found.group('code'), 16)) ]
            enrich_prop_code(prop_code)
            prop_code = prop_code[0]

            prop_type = int(found.group('type'), 16)
            if prop_type == 0x101F:
                # TODO Обслужване на multi-value стойности
                continue
            pc = PropertyValue(prop_type, ole.dire_read(dire))
            print('\n', dire.name, prop_code['propCode'])
            print(pc.get_value())

if __name__ == '__main__':
    from sys import argv
    file_name_ = argv[1]
    # test_content(file_name_)
    test_properties(file_name_)
