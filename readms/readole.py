# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

from os import path
from collections import namedtuple
import re
import logging
import logging.config

from struct import unpack_from as unpackb
from codecs import decode
from readms.readutl import dump_hex

if __name__ == '__main__':
    logging.config.fileConfig(path.join(path.dirname(__file__), 'logging.ini'))
log = logging.getLogger(__name__)

# Описанието на формата се намира на
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/
# https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-CFB/[MS-CFB].pdf

class OLE:
    # pylint: disable=attribute-defined-outside-init
    # Тъй като има много атрибути за четене и парзване и създаване на структури, за прегледност
    # това е направено в много функции. Всички тези функции се извикват в рамките на създаването
    # на обекта и са напълно готови за използване след това.
    # pylint: disable=too-many-instance-attributes
    # Сложността на OLE структурата предполага използването на голям брой атрибути.

    def __init__(self, file_name):
        self._fnm = file_name

    def __enter__(self):
        self._fin = open(self._fnm, "rb")
        self._read_header()
        self._read_fat_map()
        self._read_dir()
        self._build_dire_hier()
        self._read_minifat_map()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            self._fin.close()
        except:
            from traceback import print_exc
            print_exc()
        return False

    def _read_header(self):
        # 2.2 Compound File Header
        b0 = self._fin.read(512)
        magic = unpackb("8B", b0, 0)
        endian = unpackb("2B", b0, 28)
        assert magic == (0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)
        assert endian == (0xFE, 0xFF)  # little-endian

        self._version = (unpackb("<h", b0, 26)[0], unpackb("<h", b0, 24)[0])
        log.debug('Version: %s', self._version)
        # assert self._version == (3, 62) or self._version == (4, 62)

        self._lssize = 2**unpackb("<h", b0, 30)[0]  # Sector Shift
        self._sssize = 2**unpackb("<h", b0, 32)[0]  # Mini Sector Shift
        log.debug('Sector Size (long/short): %d/%d', self._lssize, self._sssize)

        self._dirs_cnt  = unpackb("<l", b0, 40)[0]  # Number of Directory Sectors
        self._fats_cnt  = unpackb("<l", b0, 44)[0]  # Number of FAT Sectors
        self._dirs_fsid = unpackb("<l", b0, 48)[0]  # First Directory Sector Location
        self._mfat_fsid = unpackb("<l", b0, 60)[0]  # First Mini FAT Sector Location
        self._mfat_cnt  = unpackb("<l", b0, 64)[0]  # Number of Mini FAT Sectors
        log.debug('Directory Sector Location: %d; count: %d', self._dirs_fsid, self._dirs_cnt)
        log.debug('Mini FAT Sector Location: %d; count: %d', self._mfat_fsid, self._mfat_cnt)
        log.debug('Number of FAT Sectors: %d', self._fats_cnt)

        self._difat_fsid = unpackb("<l", b0, 68)[0] # First DIFAT Sector Location
        self._difat_cnt  = unpackb("<l", b0, 72)[0] # Number of DIFAT Sectors
        log.debug('First DIFAT Sector Location: %d; count: %d', self._difat_fsid, self._difat_cnt)

        self._max_ssize = unpackb("<l", b0, 56)[0]  # Mini Stream Cutoff Size
        assert self._max_ssize == 4096

        # FIXME прочитане на всички, не само на първите 109 има още self._difat_cnt
        self._fat_list = unpackb("<109l", b0, 76)  # DIFAT first 109 FAT sector locations
        self._fat_list = self._fat_list[:self._fats_cnt]
        log.debug('FATs sectors: %s', self._fat_list)

    def _read_fat_map(self):
        self._fat_map = []
        for sid in self._fat_list:
            if sid < 0:
                continue
            self._seek_sector(sid)
            b0 = self._fin.read(self._lssize)
            sc = unpackb("<%dl" % (self._lssize/4), b0, 0)
            self._fat_map.extend(sc)
        self._fat_map = tuple(self._fat_map)
        # log.debug('FATs map: %s', self._fat_map)

    def _read_minifat_map(self):
        self._minifat_map = []
        for sid in self._chain_fat(self._mfat_fsid):
            self._seek_sector(sid)
            b0 = self._fin.read(self._lssize)
            sc = unpackb("<%dl" % (self._lssize/4,), b0, 0)
            self._minifat_map.extend(sc)
        self._minifat_map = tuple(self._minifat_map)
        # log.debug('Mini FATs map: %s', self._minifat_map)

    def _read_dir(self):
        self._dire = []
        seq_id = 0
        for sid in self._chain_fat(self._dirs_fsid):
            self._seek_sector(sid)
            b0 = self._fin.read(self._lssize)
            sd = 0
            while sd < self._lssize:
                ty = unpackb("<1B", b0, sd+66)[0]
                if ty in (0x01, 0x02, 0x05,):
                    de = OLE.DIRE(b0, sd, seq_id)
                    self._dire.append(de)
                    if ty == 0x05:
                        self.root = de
                sd += 128
                seq_id += 1

    def _seek_sector(self, sid):
        apos = 512 + sid * self._lssize
        self._fin.seek(apos, 0)

    @staticmethod
    def _chain_sectors(sid, fat_map):
        sector_list = []
        while sid >= 0:
            sector_list.append(sid)
            sid = fat_map[sid]
        return sector_list

    def _chain_fat(self, sid):
        return OLE._chain_sectors(sid, self._fat_map)

    def _chain_minifat(self, sid):
        return OLE._chain_sectors(sid, self._minifat_map)

    # Двата начина на четене (по FAT и Mini-FAT) прочитат всичко в паметта.
    # Това може да не изглежда много оптимално и да е добре да се направят и stream функции.
    # Но в контекста на MS бинарните формати почти винаги се налага да се прочете всичко тъй
    # като за обхождането на структурите се налага всичко да се достъпва по индекси в паметта.

    def _read_by_minifat(self, dire):
        if not isinstance(dire, OLE.DIRE):
            assert dire <= len(self._dire)
            dire = self._dire[dire]
        assert dire._size < self._max_ssize

        b0 = self._read_by_fat(0, True)
        out = bytearray()
        szrem = dire._size
        for sid in self._chain_minifat(dire._fsid):
            sp = self._sssize * sid
            out.extend(b0[sp:sp+min(szrem, self._sssize)])
            szrem -= self._sssize
        return memoryview(out)

    def _read_by_fat(self, dire, root=False):
        if not isinstance(dire, OLE.DIRE):
            assert dire <= len(self._dire) or root
            dire = self._dire[dire]
        assert dire._size >= self._max_ssize or root

        out = bytearray()
        szrem = dire._size
        for sid in self._chain_fat(dire._fsid):
            self._seek_sector(sid)
            b0 = self._fin.read(min(szrem, self._lssize))
            out.extend(b0)
            szrem -= self._lssize
        return memoryview(out)

    Sibling = namedtuple('Sibling', ['left', 'right', 'child'])

    class DIRE:
        # 2.6 Compound File Directory Sectors
        # pylint: disable=too-few-public-methods
        # Това е вътрешен, помощен клас с описание на directory entry

        def __init__(self, buf, pos, entry_id):
            self.id = entry_id
            name_sz = unpackb("<h", buf, pos+64)[0]
            self.name = decode(buf[pos:pos+name_sz], "UTF16")
            self._type = unpackb("<1B", buf, pos+66)[0]
            self.type_name = { 0: 'Unknown', 1: 'Storage', 2: 'Stream', 5: 'Root' }[self._type]
            log.debug('DIRE [%d] type/name: %d: %s', self.id, self._type, self.name)

            self._sibs = OLE.Sibling(left=unpackb("<l", buf, pos+68)[0],
                                     right=unpackb("<l", buf, pos+72)[0],
                                     child=unpackb("<l", buf, pos+76)[0])
            log.debug('  Neighbours: %s', self._sibs)

            self._fsid = unpackb("<l", buf, pos+116)[0]  # Starting Sector Location
            self._size = unpackb("<l", buf, pos+120)[0]  # Stream Size
            log.debug('  Starting Sector Location: %d; size: %d', self._fsid, self._size)

    def _build_dire_hier(self):
        sibs = [x._sibs for x in self._dire]
        childrens = [[] for _x in sibs]
        parents = [None for _x in sibs]

        def proc_sibs(sib, ix, where):
            parents[sib] = parents[ix]
            ixx = childrens[parents[ix]].index(ix)
            childrens[parents[ix]].insert(ixx+where, sib)
            trip(sib)

        def trip(ix):
            sib = sibs[ix]
            if sib.child > 0:
                childrens[ix].append(sib.child)
                parents[sib.child] = ix
                trip(sib.child)
            if sib.left > 0:
                proc_sibs(sib.left, ix, 0)
            if sib.right > 0:
                proc_sibs(sib.right, ix, 1)

        trip(0)
        # log.debug('%s', childrens)
        self._dire_hier = childrens
        self._dire_hier_parents = parents

    def dire_trip(self, start=0, skip=None):
        if skip is not None:
            skip = re.compile(skip)

        def trip(ix, level):
            if skip is not None and skip.search(self._dire[ix].name):
                return
            yield level, self._dire[ix]
            for cix in self._dire_hier[ix]:
                for lx, dire in trip(cix, level+1):
                    yield lx, dire
        return trip(start, level=0)

    def dire_childs(self, dire_id):
        return [self._dire[ix_] for ix_ in self._dire_hier[dire_id]]

    def dire_parent(self, dire_id):
        return self._dire[self._dire_hier_parents[dire_id]]

    def dire_find(self, dire_pattern):
        ma = re.compile(dire_pattern)
        for de in self._dire:
            if ma.match(de.name):
                return de
        raise KeyError(dire_pattern)

    def dire_read(self, dire):
        if dire._size >= self._max_ssize or dire.id == 0:
            return self._read_by_fat(dire, root=dire.id==0)
        return self._read_by_minifat(dire)


def test_ole(file):
    with OLE(file) as _ole:
        pass


def test_dire(file, start=0):
    with OLE(file) as ole:
        trip_list = []
        max_level = 0

        for level, dire in ole.dire_trip(start=start):
            trip_list.append((level, dire))
            if max_level < level:
                max_level = level

        for level, dire in trip_list:
            print('%s[%3d] %-32s%s %7d (%s)' %
                  (' '*2*level, dire.id, dire.name, ' '*2*(max_level-level),
                   dire._size, dire.type_name))


def test_content(file, maxlen=512):
    def test_read(ole, stream_name, maxlen=maxlen):
        dire = ole.dire_find(stream_name)
        obuf = ole.dire_read(dire)
        print("%s, len=%d" % (stream_name, len(obuf)))
        dump_hex(obuf[:maxlen])

    with OLE(file) as ole:
        print()
        for _level, dire in ole.dire_trip(start=0):
            test_read(ole, dire.name)

if __name__ == '__main__':
    from sys import argv
    log.setLevel('DEBUG')
    file_name_ = argv[1]
    # test_ole(file_name_)
    test_dire(file_name_, start=0)
    # test_content(file_name_)
