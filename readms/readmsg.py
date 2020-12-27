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

def print_property(pc, value_limit=30, binary_limit=128, with_empty=True):
    value_type, value_def_size, _ = pc.value.pt_desc
    value_size = len(pc.value._buf)

    if value_size == 0 and not with_empty:
        return

    print("0x%04X %-10s %4d %6d %-40s" % (
        pc.prop['propTag'], value_type, value_def_size,
        value_size, pc.prop['propCode'], ), end='')

    if value_type != 'Binary':
        value = pc.value.get_value()
        value = value if len(str(value)) <= value_limit else '\n%s\n' % value
        print(value, end='')
    else:
        if binary_limit == 0:
            print('--скрито--', end='')
        else:
            value = pc.value.get_value()
            value = PropertyValue.BinaryValue(value.data[:binary_limit])
            print('\n', value, '\n', sep='', end='')
    print()


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


class AttributesContainer:
    def __init__(self, ole, dire):
        self.name = dire.name
        self.properties = []
        load_properties(ole, dire, self.properties)

    def print(self, heading='', value_limit=30, binary_limit=128, with_empty=True):
        print('\n==', heading, self.name, '='*(76-len(self.name)), '\n')
        for pc_ in sorted(self.properties, key=AttributesContainer._sort_props_key):
            print_property(pc_, with_empty=with_empty, binary_limit=binary_limit,
                           value_limit=value_limit)

    @staticmethod
    def _sort_props_key(x):
        code = x.prop['propCode']
        return code if not code.startswith('0x') else 'zzz-%s' % code


class Attachment(AttributesContainer):
    def __init__(self, ole, dire):
        AttributesContainer.__init__(self, ole, dire)


class Recipient(AttributesContainer):
    def __init__(self, ole, dire):
        AttributesContainer.__init__(self, ole, dire)


class Message(AttributesContainer):
    # pylint: disable=too-few-public-methods
    # Представлява контейнер на атрибути, които са публични

    def __init__(self, ole, dire):
        AttributesContainer.__init__(self, ole, dire)
        self.attachments = []
        self.recipients = []
        for _level, dire_ in ole.dire_trip(start=dire.id):
            if dire_.name.startswith('__recip_version1.0'):
                self.recipients.append(Recipient(ole, dire_))
            if dire_.name.startswith('__attach_version1.0'):
                self.attachments.append(Attachment(ole, dire_))
        
        # TODO Приложени съобщения, рекурсивно
        # TODO Още атрибути (именувани) от __nameid_version1.0


def test_content(file):
    with OLE(file) as ole:
        for _level, dire in ole.dire_trip(start=0):
            obuf = ole.dire_read(dire)
            print("%s, len=%d" % (dire.name, len(obuf)))
            dump_hex(obuf[:512])


def test_read_message(file):
    with OLE(file) as ole:
        msg = Message(ole, ole.root)

    def custom_print(x, heading):
        x.print(heading, with_empty=False, binary_limit=0)

    custom_print(msg, 'Message')
    for re_ in msg.recipients:
        custom_print(re_, 'Recipient')
    for re_ in msg.attachments:
        custom_print(re_, 'Attachment')


if __name__ == '__main__':
    from sys import argv
    file_name_ = argv[1]
    # test_content(file_name_)
    test_read_message(file_name_)
