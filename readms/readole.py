# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

from os import path
from io import StringIO
import re
import logging
import logging.config

from struct import unpack_from as unpackb
from codecs import decode
from readms.readutl import dump_hex

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
        # XXX self._read_ssat()
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
        log.debug('FATs map: %s', self._fat_map)

    def _read_ssat(self):
        self._ssat_list = []
        for sid in self._chain_sat(self._ssat_fsid):
            self._seek_sector(sid)
            b0 = self._fin.read(self._lssize)
            sc = unpackb("<%dl" % (self._lssize/4,), b0, 0)
            self._ssat_list.extend(sc)
        self._ssat_list = tuple(self._ssat_list)

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
                        self._root = de
                sd += 128
                seq_id += 1
        # sectors chain for short size stream
        # XXX self._sss_chain = self._chain_sat(self._root._fsid)

    def _seek_sector(self, sid):
        apos = 512 + sid * self._lssize
        self._fin.seek(apos, 0)

    def _chain_fat(self, sid):
        sec_list = []
        while sid >= 0:
            sec_list.append(sid)
            sid = self._fat_map[sid]
        return sec_list

    def _chain_ssat(self, sid):
        sec_list = []
        while sid >= 0:
            sec_list.append(sid)
            sid = self._ssat_list[sid]
        return sec_list

    def _read_ss(self, dire):
        if not isinstance(dire, OLE.DIRE):
            assert dire <= len(self._dire)
            dire = self._dire[dire]
        assert dire._size < self._max_ssize
        # FIXME не е оптимално
        b0 = self._read_ls(0, True)
        out = bytearray()
        szrem = dire._size
        for sid in self._chain_ssat(dire._fsid):
            sp = self._sssize * sid
            out.extend(b0[sp:sp+min(szrem, self._sssize)])
            szrem -= self._sssize
        return memoryview(out)

    def _read_ls(self, dire, root=False):
        if not isinstance(dire, OLE.DIRE):
            assert dire <= len(self._dire) or root
            dire = self._dire[dire]
        assert dire._size >= self._max_ssize or root
        # FIXME прочита всичко в паметта
        out = bytearray()
        szrem = dire._size
        for sid in self._chain_sat(dire._fsid):
            self._seek_sector(sid)
            b0 = self._fin.read(min(szrem, self._lssize))
            out.extend(b0)
            szrem -= self._lssize
        return memoryview(out)

    class DIRE:
        # 2.6 Compound File Directory Sectors
        def __init__(self, buf, pos, id):
            self._id = id
            name_sz = unpackb("<h", buf, pos+64)[0]
            self._name = decode(buf[pos:pos+name_sz], "UTF16")
            self._type = unpackb("<1B", buf, pos+66)[0]
            log.debug('DIRE [%d] type/name: %d: %s', self._id, self._type, self._name)

            # XXX Тези може би са излишни за описанието на структурата
            self._left_sib  = unpackb("<l", buf, pos+68)[0]
            self._right_sib = unpackb("<l", buf, pos+72)[0]
            self._child_id  = unpackb("<l", buf, pos+76)[0]
            log.debug('  Siblings: left/ right/ child: %d; %d; %d',
                      self._left_sib, self._right_sib, self._child_id)

            self._fsid = unpackb("<l", buf, pos+116)[0]  # Starting Sector Location
            self._size = unpackb("<l", buf, pos+120)[0]  # Stream Size
            log.debug('  Starting Sector Location: %d; size: %d', self._fsid, self._size)

    def find_dire(self, dire_pattern):
        ma = re.compile(dire_pattern)
        for de in self._dire:
            if ma.match(de._name):
                return de
        raise KeyError(dire_pattern)

    def read_dire(self, dire):
        if dire._size >= self._max_ssize:
            return self._read_ls(dire)
        return self._read_ss(dire)


def test_ole(file, with_dire=True, verbose=True):
    def test_read(ole, stream_name, maxlen=512):
        dire = ole.find_dire(stream_name)
        obuf = ole.read_dire(dire)
        print("%s, len=%d" % (stream_name, len(obuf)))
        dump_hex(obuf[:maxlen])

    with OLE(file) as ole:
        if with_dire:
            for de in ole._dire:
                print(de)
                if verbose:
                    test_read(ole, de._name)


if __name__ == '__main__':
    from sys import argv
    # tx_ = int(argv[1]) if len(argv) > 1 else 0
    # cx_ = int(argv[2]) if len(argv) > 2 else 0
    # [test_ole_1,
    #  lambda x: test_read_1(x, _debug=True), ][tx_](cx_)
    test_ole(argv[1], with_dire=False)
