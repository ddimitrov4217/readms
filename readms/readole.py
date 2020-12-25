# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

from io import StringIO
import re
from struct import unpack_from as unpackb
from codecs import decode
from readms.readutl import dump_hex

# Описанието на формата се намира на
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/
# https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-CFB/[MS-CFB].pdf

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
        #print("  MSAT list: %s" % (self._msat_list,), file=out)
        #print("  SAT  list: %s" % (self._sat_list,), file=out)
        #print("  SSAT list: %s" % (self._ssat_list,), file=out)
        #for de in self._dire:
        #    print(de, file=out)
        return out.getvalue()

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
        def __init__(self, buf, pos):
            name_sz = unpackb("<h", buf, pos+64)[0]
            self._type = unpackb("<1B", buf, pos+66)[0]
            self._name = decode(buf[pos:pos+name_sz-2], "UTF16")
            self._fsid = unpackb("<l", buf, pos+116)[0]
            self._size = unpackb("<l", buf, pos+120)[0]
            self._root_id = unpackb("<l", buf, pos+76)[0]
            self._left_id = unpackb("<l", buf, pos+68)[0]
            self._right_id = unpackb("<l", buf, pos+72)[0]

        def __str__(self):
            out = StringIO()
            print("<%s instance at 0x%08X>" % (self.__class__, id(self)), file=out)
            print("  type:  %02X" % self._type, file=out)
            print("  name:  %s" % self._name, file=out)
            print("  fsid:  %6d" % self._fsid, file=out)
            print("  size:  %6d" % self._size, file=out)
            print("  root:  %6d" % self._root_id, file=out)
            print("  left:  %6d" % self._left_id, file=out)
            print("  right: %6d" % self._right_id, file=out)
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
        return self._read_ss(dire)


def test_ole(file, with_dire=True, verbose=True):
    def test_read(ole, stream_name, maxlen=512):
        dire = ole.find_dire(stream_name)
        obuf = ole.read_dire(dire)
        print("%s, len=%d" % (stream_name, len(obuf)))
        dump_hex(obuf[:maxlen])

    with OLE(file) as ole:
        print(ole)
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
    test_ole(argv[1])
