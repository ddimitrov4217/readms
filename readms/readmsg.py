# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

import re
from collections import namedtuple
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

def read_property(ole, dire):
    found = prop_name_pattern.search(dire.name)
    prop = [ dict(propTag=int(found.group('code'), 16)) ]
    enrich_prop_code(prop)
    prop = prop[0]
    ptype = int(found.group('type'), 16)
    if ptype == 0x101F:
        # TODO Обслужване на multi-value стойности
        return None
    return Property(value=PropertyValue(ptype, ole.dire_read(dire)), prop=prop)


def load_properties(ole, dires, target):
    for dire in dires:
        if not prop_name_pattern.match(dire.name):
            continue
        pc = read_property(ole, dire)
        if pc is not None:
            target.append(pc)


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
            load_properties(ole, ole.dire_childs(0), self.properties)
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
