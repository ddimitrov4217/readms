# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

import re
from codecs import decode
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


class PropertiesStream(OLE):
    def __init__(self, file):
        OLE.__init__(self, file)
        self._named_entries = None
        self._named_map = None

    def __enter__(self):
        OLE.__enter__(self)
        self._named_entries = self._load_named_entries()
        self._named_map = self._load_named_map()
        print(self._named_entries)
        self._print_named_map()
        return self

    def enrich_prop(self, tag):
        if tag in self._named_map:
            return dict(propTag=tag, propCode=self._named_map[tag].code)
        prop = [dict(propTag=tag)]
        enrich_prop_code(prop)
        return prop[0]

    NamedMapEntry = namedtuple('NamedMapEntry', ('tag', 'code', 'guid_ix', 'flag', 'ino'))

    def _load_named_entries(self):
        # 2.2.3 Named Property Mapping Storage
        dire = self.dire_find('__nameid_version1.0')

        entry_stream = []
        for dire_ in self.dire_childs(dire.id):
            obuf = self.dire_read(dire_)

            if dire_.name.startswith('__substg1.0_00020102'):
                # TODO 2.2.3.1.1 GUID Stream
                print(dire_.name, len(obuf))
                dump_hex(obuf)

            if dire_.name.startswith('__substg1.0_00030102'):
                # 2.2.3.1.2 Entry Stream
                for pos in range(0, len(obuf), 8):
                    name_ix = unpackb("<L", obuf, pos)[0]  # Name Identifier/String Offset
                    # 2.2.3.1.2.1 Index and Kind Information
                    prop_ix = unpackb("<H", obuf, pos+6)[0]  # Property Index
                    guid_ix = unpackb("<H", obuf, pos+4)[0]  # GUID Index
                    entry_stream.append((name_ix, guid_ix>>1, guid_ix&0x1, prop_ix))

            if dire_.name.startswith('__substg1.0_00040102'):
                # 2.2.3.1.3 String Stream - имената на атрибутите, само буфера е достатъчен
                att_names = obuf

        # TODO За какво се използват останалите stream-ове от __nameid_version1.0

        result = []
        for name_ix, guid_ix, entry_flag, prop_ix in entry_stream:
            if entry_flag == 1:
                name_len = unpackb("<l", att_names, name_ix)[0]
                entry_name = decode(att_names[name_ix+4:name_ix+4+name_len], "UTF-16LE", "replace")
                # print('%2d %04X %2d %s' % (prop_ix, prop_ix+0x8000, guid_ix, entry_name))
                result.append(PropertiesStream.NamedMapEntry(
                    tag=prop_ix+0x8000, code=entry_name,
                    guid_ix=guid_ix, flag=entry_flag, ino=prop_ix))
            else:
                # print('%2d %04X %2d' % (prop_ix, name_ix, guid_ix))
                result.append(PropertiesStream.NamedMapEntry(
                    tag=name_ix, code=None, guid_ix=guid_ix, flag=entry_flag, ino=prop_ix))

        return result

    def _load_named_map(self):
        result = {}
        for ex_ in self._named_entries:
            if ex_.flag == 1:
                result[ex_.tag] = ex_
        return result

    def _print_named_map(self):
        for key_ in sorted(self._named_map.keys()):
            print('%04X ' % key_, end='')
            print(self._named_map[key_])


class AttributesContainer:
    def __init__(self, ole, dire):
        self.name = dire.name
        self.properties = []
        self._load(ole, dire)

    def print(self, heading='', value_limit=30, binary_limit=128, with_empty=True):
        print('\n==', heading, self.name, '='*(76-len(self.name)), '\n')
        for pc_ in sorted(self.properties, key=AttributesContainer._sort_props_key):
            print_property(pc_, with_empty=with_empty, binary_limit=binary_limit,
                           value_limit=value_limit)

    @staticmethod
    def _sort_props_key(x):
        code = x.prop['propCode']
        return code if not code.startswith('0x') else 'zzz-%s' % code

    def _load(self, ole, dire):
        for dire_ in ole.dire_childs(dire.id):
            self._load_variable_length(ole, dire_)
            self._load_fixed_length(ole, dire_)

    def _load_variable_length(self, ole, dire):
        found = prop_name_pattern.search(dire.name)
        if found is None:
            return

        prop = ole.enrich_prop(int(found.group('code'), 16))
        ptype = int(found.group('type'), 16)
        if ptype & 0x1000:
            return  # TODO Обслужване на multi-value стойности

        pv = PropertyValue(ptype, ole.dire_read(dire))
        self.properties.append(Property(value=pv, prop=prop))


    def _load_fixed_length(self, ole, dire):
        if not dire.name.startswith('__properties_version1.0'):
            return

        # 2.4.2.1 Fixed Length Property Entry
        pdire = ole.dire_parent(dire.id)
        if pdire.name.startswith('Root'):
            data_offset = 32
        if pdire.name.startswith('__attach') or pdire.name.startswith('__recip'):
            data_offset = 8

        obuf = ole.dire_read(dire)
        for pos_ in range(data_offset, len(obuf)-data_offset, 16):
            tag = list(unpackb("<HH", obuf, pos_)) # Property Tag (type, code)
            # 2.4.2.2 Variable Length Property or Multiple-Valued Property Entry
            # за тези с променлива дължина, стойността е размера на истинската стойност,
            # което не си заслужава да се проверява със зареденото в предишния if блок
            # 0x101F (multy-valued) 0x001F (string)
            if tag[0] not in (0x101F, 0x001F):
                pv = PropertyValue(tag[0], obuf[pos_+8:pos_+16])
                prop = ole.enrich_prop(tag[1])
                self.properties.append(Property(value=pv, prop=prop))


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
        for dire_ in ole.dire_childs(dire.id):
            if dire_.name.startswith('__recip_version1.0'):
                self.recipients.append(Recipient(ole, dire_))
            if dire_.name.startswith('__attach_version1.0'):
                self.attachments.append(Attachment(ole, dire_))

        # TODO Приложени съобщения, рекурсивно


def test_content(file):
    with OLE(file) as ole:
        for _level, dire in ole.dire_trip(start=0):
            obuf = ole.dire_read(dire)
            print("%s, len=%d" % (dire.name, len(obuf)))
            dump_hex(obuf[:512])


def test_read_message(file):
    with PropertiesStream(file) as ole:
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
