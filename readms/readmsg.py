# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

import re
from collections import namedtuple
from struct import unpack_from as unpackb
from readms.readole import OLE
from readms.readutl import dump_hex
from readms.readpst import PropertyValue
from readms.metapst import enrich_prop_code

# [MS-OXMSG]: Outlook Item (.msg) File Format
# Описанието на формата се намира на
# https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxmsg
# https://interoperability.blob.core.windows.net/files/MS-OXMSG/[MS-OXMSG].pdf

prop_name_pattern = re.compile(
    r'__substg1.0_(?P<code>[0-9A-F]{4})'
    r'(?P<type>[0-9A-F]{4})(?:[-](?P<index>[0-9]{1,}))?')

Property = namedtuple('Property', ['value', 'prop'])

def enrich_prop(tag):
    prop = [dict(propTag=tag)]
    enrich_prop_code(prop)
    return prop[0]


def load_properties(ole, dire, target):
    for dire_ in ole.dire_childs(dire.id):
        found = prop_name_pattern.search(dire_.name)
        if found is not None:
            prop = enrich_prop(int(found.group('code'), 16))
            ptype = int(found.group('type'), 16)
            if ptype & 0x1000:
                continue  # TODO Обслужване на multi-value стойности
            pv = PropertyValue(ptype, ole.dire_read(dire_))
            target.append(Property(value=pv, prop=prop))

        if dire_.name.startswith('__properties_version1.0'):
            # 2.4.2.1 Fixed Length Property Entry
            pdire = ole.dire_parent(dire_.id)
            if pdire.name.startswith('Root'):
                data_offset = 32
            if pdire.name.startswith('__attach') or pdire.name.startswith('__recip'):
                data_offset = 8

            obuf = ole.dire_read(dire_)
            for pos_ in range(data_offset, len(obuf)-data_offset, 16):
                tag = list(unpackb("<HH", obuf, pos_)) # Property Tag (type, code)
                # 2.4.2.2 Variable Length Property or Multiple-Valued Property Entry
                # за тези с променлива дължина, стойността е размера на истинската стойност,
                # което не си заслужава да се проверява със зареденото в предишния if блок
                # 0x101F (multy-valued) 0x001F (string)
                if tag[0] not in (0x101F, 0x001F):
                    pv = PropertyValue(tag[0], obuf[pos_+8:pos_+16])
                    prop = enrich_prop(tag[1])
                    target.append(Property(value=pv, prop=prop))

class Attachment:
    pass


class Recipient:
    pass


class Message:
    # pylint: disable=too-few-public-methods
    # Представлява контейнер на атрибути, които са публични

    def __init__(self, file):
        self.file = file
        self.properties = []
        self.attachments = []
        self.recipients = []

        with OLE(file) as ole:
            load_properties(ole, ole.root, self.properties)
            # TODO Приложени файлове __attach_version1.0
            # TODO Получатели __recip_version1.0
            # TODO Още атрибути (именувани) от __nameid_version1.0


def test_content(file):
    with OLE(file) as ole:
        for _level, dire in ole.dire_trip(start=0):
            obuf = ole.dire_read(dire)
            print("%s, len=%d" % (dire.name, len(obuf)))
            dump_hex(obuf[:512])


def test_read_message(file):
    msg = Message(file)
    for pc in msg.properties:
        print('\n', pc.prop['propCode'], sep='')
        print(pc.value.get_value())


if __name__ == '__main__':
    from sys import argv
    file_name_ = argv[1]
    # test_content(file_name_)
    test_read_message(file_name_)
