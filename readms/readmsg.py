# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

import logging
import re
from codecs import decode
from collections import namedtuple
from struct import unpack_from as unpackb
from sys import argv

import click

from readms.metapst import enrich_prop_code
from readms.readole import OLE
from readms.readpst import PropertyValue
from readms.readutl import uuid_from_buf

log = logging.getLogger(__name__)

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

    print(f"{pc.prop['propTag']:04X} {value_type:10s} "
          f"{value_def_size:#4d} {value_size:#6d} {pc.prop['propCode']:40s}",
          end='')

    if value_type != 'Binary':
        value = pc.value.get_value()
        value = value if len(str(value)) <= value_limit else f'\n{value}\n'
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
        self._named_map = self._load_named_entries()
        self._debug_named_map()
        return self

    def enrich_prop(self, tag):
        if tag in self._named_map:
            return {'propTag': tag, 'propCode': self._named_map[tag].code}
        return self._oxprops(tag)

    @staticmethod
    def _oxprops(tag):
        prop = [{'propTag': tag}]
        enrich_prop_code(prop)
        return prop[0]

    NamedMapEntry = namedtuple('NamedMapEntry', ('tag', 'code', 'guid', 'flag'))

    def _load_named_entries(self):
        # 2.2.3 Named Property Mapping Storage
        dire = self.dire_find('__nameid_version1.0')

        entry_stream = []
        guids_list = []
        for dire_ in self.dire_childs(dire.id):
            obuf = self.dire_read(dire_)

            if dire_.name.startswith('__substg1.0_00020102'):
                # 2.2.3.1.1 GUID Stream
                # [MS-OXPROPS] 1.3.2 Commonly Used Property Sets
                # https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/
                for pos in range(0, len(obuf), 16):
                    guid = uuid_from_buf(obuf[pos:])
                    guids_list.append(str(guid).upper())

            if dire_.name.startswith('__substg1.0_00030102'):
                # 2.2.3.1.2 Entry Stream
                for pos in range(0, len(obuf), 8):
                    name_ix = unpackb("<L", obuf, pos)[0]  # Name Identifier/String Offset
                    # 2.2.3.1.2.1 Index and Kind Information
                    prop_ix = unpackb("<H", obuf, pos+6)[0]  # Property Index
                    guid_ix = unpackb("<H", obuf, pos+4)[0]  # GUID Index
                    entry_stream.append((name_ix, guid_ix >> 1, guid_ix & 0x1, prop_ix))

            if dire_.name.startswith('__substg1.0_00040102'):
                # 2.2.3.1.3 String Stream - имената на атрибутите, само буфера е достатъчен
                att_names = obuf

        # 2.2.3.2 Property Name to Property ID Mapping Streams
        # Няма нужда от това тъй като то дублира горното съответствие в обратна посока

        result = []
        for name_ix, guid_ix, entry_flag, prop_ix in entry_stream:
            guid = guids_list[guid_ix-3] if guid_ix >= 3 else None
            if entry_flag == 1:
                name_len = unpackb("<l", att_names, name_ix)[0]
                entry_name = decode(att_names[name_ix+4:name_ix+4+name_len], "UTF-16LE", "replace")
                result.append(PropertiesStream.NamedMapEntry(
                    tag=prop_ix+0x8000, code=entry_name,
                    guid=guid, flag=entry_flag))
            else:
                result.append(PropertiesStream.NamedMapEntry(
                    tag=prop_ix+0x8000, code=self._oxprops(name_ix)['propCode'],
                    guid=guid, flag=entry_flag))

        return {ex_.tag: ex_ for ex_ in result}

    def _debug_named_map(self):
        for key_ in sorted(self._named_map.keys()):
            log.debug('%04X %s', key_, self._named_map[key_])


# pylint: disable=too-few-public-methods
# представлява контейнер на стойности - много подготовка, лесен достъп
class AttributesContainer:
    def __init__(self, ole, dire):
        self.name = dire.name
        self.properties = []
        self.dict = {}
        self._load(ole, dire)
        self._load_dict()

    def print(self, value_limit=30, binary_limit=128, with_empty=True):
        heading = self.__class__.__name__
        print('\n==', heading, self.name, '='*(76-len(self.name)-len(heading)), '\n')
        for pc_ in sorted(self.properties, key=AttributesContainer._sort_props_key):
            print_property(pc_, with_empty=with_empty, binary_limit=binary_limit,
                           value_limit=value_limit)

    @staticmethod
    def _sort_props_key(x):
        code = x.prop['propCode']
        return code if not code.startswith('0X') else f'zzz-{code}'

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
            return  # TODO: Обслужване на multi-value стойности

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
        if pdire.name.startswith('__substg1.0_3701000D'):
            data_offset = 24

        obuf = ole.dire_read(dire)
        for pos_ in range(data_offset, len(obuf)-data_offset, 16):
            tag = list(unpackb("<HH", obuf, pos_))  # Property Tag (type, code)
            # 2.4.2.2 Variable Length Property or Multiple-Valued Property Entry
            # за тези с променлива дължина, стойността е размера на истинската стойност,
            # което не си заслужава да се проверява със зареденото в предишния if блок
            # 0x101F (multy-valued) 0x001F (string)
            if tag[0] not in (0x101F, 0x001F):
                pv = PropertyValue(tag[0], obuf[pos_+8:pos_+16])
                prop = ole.enrich_prop(tag[1])
                self.properties.append(Property(value=pv, prop=prop))

    def _load_dict(self):
        ino = 1
        for px in self.properties:
            pkey = px.prop['propCode']
            if pkey in self.dict:
                pkey = f'{pkey}.{ino}'
                ino += 1
            self.dict[pkey] = px


class Attachment(AttributesContainer):
    def __init__(self, ole, dire):
        AttributesContainer.__init__(self, ole, dire)
        self.attach_method = self._attach_method()
        self.message = self._load_message(ole, dire)

    def print(self, value_limit=30, binary_limit=128, with_empty=True):
        AttributesContainer.print(self, value_limit, binary_limit, with_empty)
        if self.message is not None:
            self.message.print(value_limit, binary_limit, with_empty)

    def _load_message(self, ole, dire):
        # 2.2.2.1 Embedded Message Object Storage - PidTagAttachMethod==5?
        if self.attach_method == 5:
            for dire_ in ole.dire_childs(dire.id):
                if dire_.name.startswith('__substg1.0_3701000D'):
                    return Message(ole, dire_)
        return None

    def _attach_method(self):
        for px_ in self.properties:
            if px_.prop['propCode'] == 'AttachMethod':
                return px_.value.get_value()
        return None


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

    def print(self, value_limit=30, binary_limit=128, with_empty=True):
        AttributesContainer.print(self, value_limit, binary_limit, with_empty)
        for re_ in self.recipients:
            re_.print(value_limit, binary_limit, with_empty)
        for re_ in self.attachments:
            re_.print(value_limit, binary_limit, with_empty)


@click.group()
def cli():
    pass


@cli.command('dump', help='Извежда всички атрибути на съобщението')
@click.argument('file')
@click.option('--binary-limit', default=0, show_default=True, help='Максимум байтове за извеждане')
@click.option('--with-empty', is_flag=True, show_default=True, help='Извежда и празните атрибути')
def test_read_message(file, with_empty=False, binary_limit=0):
    with PropertiesStream(file) as ole:
        msg = Message(ole, ole.root)
        msg.print(with_empty=with_empty, binary_limit=binary_limit)


def test():
    file_name_ = argv[1]
    # test_content(file_name_)
    test_read_message(file_name_)


if __name__ == '__main__':
    # test()
    cli()
