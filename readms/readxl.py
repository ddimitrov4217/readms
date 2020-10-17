# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

from io import StringIO
import re
from struct import unpack_from as unpackb
from codecs import decode
from readutl import dump_hex
from metaxl import biff_rec_name



# Всички цитати и точки, които се използва по-долу са от „OpenOffice.org's
# Documentation of the Microsoft Compound Document File Format“, който може
# да се свали от http://sc.openoffice.org/compdocfileformat.pdf
# ==========================================================================
# § 4.1 Compound Document Header Contents
# ==========================================================================
#  0   8 Compound document file identifier: D0H CFH 11H E0H A1H B1H 1AH E1H
#  8  16 Unique identifier (UID) of this file (not of interest in the
#        following, may be all 0)
# 24   2 Revision number of the file format (most used is 003EH)
# 26   2 Version number of the file format (most used is 0003H)
# 28   2 Byte order identifier (§4.2):
#           FEH FFH = Little-Endian
#           FFH FEH = Big-Endian
# 30   2 Size of a sector in the compound document file (§3.1) in
#        power-of-two (ssz), real sector size is sec_size = 2ssz bytes
#        (minimum value is 7 which means 128 bytes, most used value is 9
#        which means 512 bytes)
# 32   2 Size of a short-sector in the short-stream container stream (§6.1)
#        in power-of-two (sssz), real short-sector size is short_sec_size =
#        2sssz bytes (maximum value is sector size ssz, see above, most used
#        value is 6 which means 64 bytes)
# 34  10 Not used
# 44   4 Total number of sectors used for the sector allocation table (§5.2)
# 48   4 SecID of first sector of the directory stream (§7)
# 52   4 Not used
# 56   4 Minimum size of a standard stream (in bytes, minimum allowed and
#        most used size is 4096 bytes), streams with an actual size smaller
#        than (and not equal to) this value are stored as short-streams (§6)
# 60   4 SecID of first sector of the short-sector allocation table (§6.2),
#        or –2 (End Of Chain SecID, §3.1) if not extant
# 64   4 Total number of sectors used for the short-sector allocation table
#        (§6.2)
# 68   4 SecID of first sector of the master sector allocation table (§5.1),
#        or –2 (End Of Chain SecID, §3.1) if no additional sectors used
# 72   4 Total number of sectors used for the master sector allocation table
#        (§5.1)
# 76 436 First part of the master sector allocation table (§5.1) containing
#        109 SecIDs
# ==========================================================================
# § 7.2.1 Directory Entry Structure
# ==========================================================================
#   0 64 Character array of the name of the entry, always 16-bit Unicode
#        characters, with trailing zero character (results in a maximum name
#        length of 31 characters)
#  64  2 Size of the used area of the character buffer of the name (not
#        character count), including the trailing zero character (e.g. 12
#        for a name with 5 characters: (5+1)∙2 = 12)
#  66  1 Type of the entry:
#             00H = Empty        03H = LockBytes (unknown)
#             01H = User storage 04H = Property (unknown)
#             02H = User stream  05H = Root storage
#  67  1 Node colour of the entry: 00H = Red 01H = Black
#  68  4 DirID of the left child node inside the red-black tree of all
#        direct members of the parent storage (if this entry is a user
#        storage or stream, §7.1), –1 if there is no left child
#  72  4 DirID of the right child node inside the red-black tree of all
#        direct members of the parent storage (if this entry is a user
#        storage or stream, §7.1), –1 if there is no right child
#  76  4 DirID of the root node entry of the red-black tree of all storage
#        members (if this entry is a storage, §7.1), –1 otherwise
#  80 16 Unique identifier, if this is a storage (not of interest in the
#        following, may be all 0)
#  96  4 User flags (not of interest in the following, may be all 0)
# 100  8 Time stamp of creation of this entry (§7.2.3). Most implementations
#        do not write a valid time stamp, but fill up this space with zero
#        bytes.
# 108  8 Time stamp of last modification of this entry (§7.2.3). Most
#        implementations do not write a valid time stamp, but fill up this
#        space with zero bytes.
# 116  4 SecID of first sector or short-sector, if this entry refers to a
#        stream (§7.2.2), SecID of first sector of the short-stream
#        container stream (§6.1), if this is the root storage entry, 0
#        otherwise
# 120  4 Total stream size in bytes, if this entry refers to a stream
#        (§7.2.2), total size of the shortstream container stream (§6.1), if
#        this is the root storage entry, 0 otherwise
# 124  4 Not used


class OLE:
    def __init__(self, file_name):
        self._fnm = file_name

    def __enter__(self):
        self._fin = open(self._fnm, "rb")
        self._read_header()
        self._read_msat()
        self._read_dir()
        self._read_ssat()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            self._fin.close()
        except:
            from traceback import print_exc
            print_exc()
        return False

    def _read_header(self):
        b0 = self._fin.read(512)
        magic = unpackb("8B", b0, 0)
        endian = unpackb("2B", b0, 28)
        assert magic == (0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)
        assert endian == (0xFE, 0xFF)  # little-endian
        self._lssize = 2**unpackb("<h", b0, 30)[0]
        self._sssize = 2**unpackb("<h", b0, 32)[0]
        self._msat_list = unpackb("<109l", b0, 76)
        self._dirs_fsid = unpackb("<l", b0, 48)[0]
        self._ssat_fsid = unpackb("<l", b0, 60)[0]
        self._msat_fsid = unpackb("<l", b0, 68)[0]
        self._max_ssize = unpackb("<l", b0, 56)[0]

    def _read_msat(self):
        # FIXME прочитане на всички, не само на първите 109
        self._sat_list = []
        for sid in self._msat_list:
            if sid < 0:
                continue
            self._seek_sector(sid)
            b0 = self._fin.read(self._lssize)
            sc = unpackb("<%dl" % (self._lssize/4), b0, 0)
            self._sat_list.extend(sc)
        self._sat_list = tuple(self._sat_list)

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
        for sid in self._chain_sat(self._dirs_fsid):
            self._seek_sector(sid)
            b0 = self._fin.read(self._lssize)
            sd = 0
            while sd < self._lssize:
                ty = unpackb("<1B", b0, sd+66)[0]
                if ty in (0x01, 0x02, 0x05,):
                    de = OLE.DIRE(b0, sd)
                    self._dire.append(de)
                    if ty == 0x05:
                        self._root = de
                sd += 128
        # sectors chain for short size stream
        self._sss_chain = self._chain_sat(self._root._fsid)

    def _seek_sector(self, sid):
        apos = 512 + sid * self._lssize
        self._fin.seek(apos, 0)

    def _chain_sat(self, sid):
        sec_list = []
        while sid >= 0:
            sec_list.append(sid)
            sid = self._sat_list[sid]
        return sec_list

    def _chain_ssat(self, sid):
        sec_list = []
        while sid >= 0:
            sec_list.append(sid)
            sid = self._ssat_list[sid]
        return sec_list

    def __str__(self):
        out = StringIO()
        print("<%s instance at 0x%08X>" % (self.__class__, id(self)), file=out)
        print("  long-sector-size: %6d" % self._lssize, file=out)
        print("  short-sector-size:%6d" % self._sssize, file=out)
        print("  short-max-size:   %6d" % self._max_ssize, file=out)
        print("  DIR first SecID:  %6d" % self._dirs_fsid, file=out)
        print("  SSAT first SecID: %6d" % self._ssat_fsid, file=out)
        print("  MSAT first SecID: %6d" % self._msat_fsid, file=out)
        print("  MSAT list: %s" % (self._msat_list,), file=out)
        print("  SAT  list: %s" % (self._sat_list,), file=out)
        print("  SSAT list: %s" % (self._ssat_list,), file=out)
        for de in self._dire:
            print(de, file=out)
        return out.getvalue()

    def _read_ss(self, dire):
        if not isinstance(dire, OLE.DIRE):
            assert dire <= len(self._dire)
            dire = self._dire[dire]
        assert(dire._size < self._max_ssize)
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
        def __init__(self, buf, pos):
            name_sz = unpackb("<h", buf, pos+64)[0]
            self._type = unpackb("<1B", buf, pos+66)[0]
            self._name = decode(buf[pos:pos+name_sz-2], "UTF16")
            self._fsid = unpackb("<l", buf, pos+116)[0]
            self._size = unpackb("<l", buf, pos+120)[0]

        def __str__(self):
            out = StringIO()
            print("<%s instance at 0x%08X>" % (self.__class__, id(self)), file=out)
            print("  type: %02X" % self._type)
            print("  name: %s" % self._name)
            print("  fsid: %6d" % self._fsid)
            print("  size: %6d" % self._size)
            return out.getvalue()

    def find_dire(self, dire_pattern):
        ma = re.compile(dire_pattern)
        for de in self._dire:
            if ma.match(de._name):
                return de
        raise KeyError(dire_pattern)

    def read_dire(self, dire):
        if dire._size >= self._max_ssize:
            return self._read_ls(dire)
        else:
            return self._read_ss(dire)


def read_workbook(file_name):
    with OLE(file_name) as ole:
        dire = ole.find_dire("Workbook")
        buf = ole.read_dire(dire)
        pos = 0
        lex = len(buf)
        while pos < lex:
            rtag, size = unpackb("<HH", buf, pos)
            obuf = buf[(pos+4):(pos+4+size)]
            yield (biff_rec_name(rtag), obuf)
            pos += size + 4


def test_file(cx=0):
    from os import path
    fnm = (u"test.xls", u"131352367_2014_Q4.xls", u"FCL_грешни_МИС.xls",
           u"2015 04 09 FCL Migration.xls",
           path.join("S:", "USI", "SHARED", "ALL", "ISIS-2", "IF",
                     "07.04.2015", "IF_instrumens_2014_part1.xls"))
    return fnm[cx]


def test_ole_1(cx=0):
    def test_read(ole, stream_name, maxlen=200):
        dire = ole.find_dire(stream_name)
        obuf = ole.read_dire(dire)
        print("%s, len=%d" % (stream_name, len(obuf)))
        dump_hex(obuf[:maxlen])

    with OLE(test_file(cx)) as ole:
        print(ole)
        print(dir(ole))
        test_read(ole, "Workbook")
        test_read(ole, ".DocumentSummaryInformation")
        test_read(ole, ".SummaryInformation")
        test_read(ole, ".CompObj")
        test_read(ole, ".Ole")


def test_read_1(cx=1, _debug=False):
    fnm = test_file(cx)
    for (rtag, buf,) in read_workbook(fnm):
        if _debug:
            print("%4d %s" % (len(buf), rtag,))
            if len(buf) > 0:
                dump_hex(buf)


if __name__ == '__main__':
    from sys import argv
    tx_ = int(argv[1]) if len(argv) > 1 else 0
    cx_ = int(argv[2]) if len(argv) > 2 else 0
    [test_ole_1,
     lambda x: test_read_1(x, _debug=True), ][tx_](cx_)
