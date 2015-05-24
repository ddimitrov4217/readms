# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

import gzip
import time
from codecs import decode, encode
from StringIO import StringIO
from datetime import datetime, timedelta
from struct import unpack_from as unpackb
from readutl import (
    dump_hex, decode_permute, ulong_from_tuple, UnpackDesc,
    run_profile)
from metapst import (
    page_types, nid_types, prop_types, all_props_types,
    hn_header_client_sig,
    enrich_prop_code, props_tags_codes,
    get_hid_index, get_hnid_type)
from metapst import (
    HEADER_1, HEADER_2,
    PAGE_TRAILER, BT_PAGE, BT_ENTRY, BBT_ENTRY, NBT_ENTRY,
    BLOCK_TRAILER, BLOCK_SIGNATURE, SL_ENTRY,
    HN_HDR, HN_PAGE_MAP, BTH_HEADER,
    PC_BTH_RECORD)


def read_ndb_page(fin, bref):
    bid, ib = bref
    fin.seek(ib)
    buf = memoryview(fin.read(512))
    # dump_hex(buf)
    eng = UnpackDesc(buf)
    eng.seek(488)
    eng.unpack(BT_PAGE)
    eng.skip(4)  # dwPadding DWORD # Padding; MUST be set to zero (0)

    eng.unpack(PAGE_TRAILER)
    btpage, meta = eng.out
    assert eng.pos == 512
    assert meta["ptype"] == meta["ptypeRepeat"]

    ptype_desc = dict(BT=BT_ENTRY, BBT=BBT_ENTRY, NBT=NBT_ENTRY)
    ptype_code = page_types[meta["ptype"]][0]
    assert ptype_code in ("NBT", "BBT"), hex(meta["ptype"])
    if ptype_code == "NBT":
        if btpage["cLevel"] == 0:
            sdesc = "NBT"
        else:
            sdesc = "BT"
    else:
        if btpage["cLevel"] == 0:
            sdesc = "BBT"
        else:
            sdesc = "BT"
    meta["entriesType"] = sdesc
    model = ptype_desc[sdesc]
    entries = []
    for p in range(0, btpage["cEnt"]):
        eng = UnpackDesc(buf, pos=p*btpage["cbEnt"])
        eng.unpack(model)
        entries.extend(eng.out)
    return dict(meta=meta, entries=entries)


class NDBLayer:
    def __init__(self, file_name):
        self._fin = open(file_name, "rb")
        self._read_header()
        self._bbt = []
        self._nbt = []
        start = time.time()
        self._read_bbt(self._header["brefBBT"])
        self._read_nbt(self._header["brefNBT"])
        # TODO create tree structutes for BBT and NBT
        # тъй като файлът е read-only, за сега,
        # hash структура също върши работа
        self._done_time = time.time() - start

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self.close()
        except:
            from traceback import print_exc
            print_exc()
        return False

    def close(self):
        self._fin.close()

    def _read_header(self):
        self._fin.seek(0)
        buf = memoryview(self._fin.read(564))
        # dump_hex(buf)
        eng = UnpackDesc(buf)
        eng.unpack(HEADER_1)
        eng.skip(4)    # skip dwAlign  DWORD
        eng.skip(128)  # skip rgbFMap  byte[128] Deprecated FMap
        eng.skip(128)  # skip rgbFPMap byte[128] Deprecated FPMap
        eng.unpack(HEADER_2)

        assert eng.pos == len(buf), "pos=%d, len=%d" % (eng.pos, len(buf))
        self._header, h2 = eng.out
        self._header.update(h2)
        assert self._header["dwMagic"] == (0x21, 0x42, 0x44, 0x4E)
        assert self._header["wMagicClient"] == (0x53, 0x4D)
        assert self._header["wVer"] == 23, "Unicode PST"
        assert self._header["bCryptMethod"] in (0x00, 0x01,), "Encrypted PST"

    def _read_bbt(self, bref):
        bbt = read_ndb_page(self._fin, bref)
        if bbt["meta"]["entriesType"] == "BT":
            for bt in bbt["entries"]:
                self._read_bbt(bt["bref"])
        else:
            for ex in bbt["entries"]:
                ex["internal"] = ex["bref"][0] & 2 != 0
            self._bbt.extend(bbt["entries"])
        self._bbtx = {}
        for bx in self._bbt:
            bid, bbt = bx["bref"]
            self._bbtx[bid] = bx

    def _enrich_nid_type(self, ex):
        ex["type"] = ex["nid"] & 0x1F
        type_desc = nid_types.get(ex["type"], None)
        if type_desc is not None:
            ex["typeCode"] = type_desc[0]
        else:
            ex["typeCode"] = "0x%04X" % ex["type"]

    def _read_nbt(self, bref):
        nbt = read_ndb_page(self._fin, bref)
        if nbt["meta"]["entriesType"] == "BT":
            for bt in nbt["entries"]:
                self._read_nbt(bt["bref"])
        else:
            for ex in nbt["entries"]:
                self._enrich_nid_type(ex)
                sbid = ex["bidSub"]
                if sbid != 0:
                    # read 2.2.2.8.3.3 Subnode BTree
                    # print "_read_nbt::ex[nid]", ex["nid"]
                    sub_entries = self._read_sub_btree(sbid)
                    for sbe in sub_entries.values():
                        self._enrich_nid_type(sbe)
                    ex["subEntries"] = sub_entries
            self._nbt.extend(nbt["entries"])
        self._nbtx = {}
        for nx in self._nbt:
            self._nbtx[nx["nid"]] = nx

    def _read_sub_btree(self, bid):
        bx = self._bbtx[bid]
        data = self._read_block(bx)
        sign, pos = self._read_block_sign(data)
        # print "_read_sub_btree::", sign, pos
        assert sign["btype"] == 2

        # 2.2.2.8.3.3.1.1 SLENTRY (Leaf Block Entry)
        def read_SL_entries(buf, pos):
            eng = UnpackDesc(buf, pos=pos)
            for _ in range(sign["cEnt"]):
                eng.unpack(SL_ENTRY)
            for ex in eng.out:
                # FIXME много странно, че само така работи
                ex["nid"] = ex["nid"] & 0xFFFFFFFF
            entries = dict([(x["nid"], x) for x in eng.out])
            return entries, eng.pos

        c_level = sign["cLevel"]
        if c_level == 0:
            # 2.2.2.8.3.3.1 SLBLOCKs
            pos += 4  # dwPadding (4 bytes)
            entries, pos = read_SL_entries(data, pos)
            ext_entries = {}
            for ex in entries.values():
                if ex["bidSub"] != 0:
                    enx = self._read_sub_btree(ex["bidSub"])
                    ext_entries.update(enx)
            entries.update(ext_entries)
            # pprint(("_read_SLBLOCKs", entries))
            # dump_hex(data)
        elif c_level == 1:
            # TODO 2.2.2.8.3.3.2 SIBLOCKs
            raise NotImplementedError
        else:
            raise KeyError(c_level)
        return entries

    def _read_block(self, bbt):
        bid, ib = bbt["bref"]
        # print "_read_block::bbt", bbt
        # block_size is near greater multiple by 64
        # 16 is the trailer block size
        block_size = (((bbt["cb"] + 16) - 1) / 64 + 1) * 64
        assert block_size <= 8192  # 8176 + block trailer(16)
        self._fin.seek(ib)
        buf = memoryview(self._fin.read(block_size))
        # dump_hex(buf)
        # block trailer is the last 16 bytes
        eng = UnpackDesc(buf, pos=block_size-16)
        block_trailer = eng.unpack(BLOCK_TRAILER)
        assert block_trailer["cb"] == bbt["cb"]
        assert block_trailer["bid"] == bid
        data = buf[0:block_trailer["cb"]]
        if not bbt["internal"]:
            # decode with Permutation Algorithm (section 5.1)
            # only for user data blocks
            if self._header["bCryptMethod"] == 0x01:
                data = decode_permute(data)
        return data

    def _read_block_sign(self, buf):
        eng = UnpackDesc(buf)
        return eng.unpack(BLOCK_SIGNATURE), eng.pos

    def _read_data_block(self, bid):
        bx = self._bbtx[bid]
        data = self._read_block(bx)
        if bx["internal"]:
            # 2.2.2.8.3.2 Data Tree XBLOCKS, XXBLOCKS
            data_bids = []

            def read_xblock_bids(data):
                # dump_hex(data)
                sign, pos = self._read_block_sign(data)
                assert sign["btype"] == 1
                icb = unpackb("<L", data, pos)[0]
                bids = unpackb("<%dQ" % sign["cEnt"], data, pos+4)
                if sign["cLevel"] == 1:  # XBLOCK
                    data_bids.extend(bids)
                    return icb
                if sign["cLevel"] == 2:  # XXBLOCK
                    totb = 0
                    for bidx in bids:
                        bx = self._bbtx[bidx]
                        datax = self._read_block(bx)
                        totb += read_xblock_bids(datax)
                    return totb
                raise KeyError(sign["cLevel"])
            totb = read_xblock_bids(data)
            out_data = bytearray()
            for bix in data_bids:
                data = self._read_data_block(bix)
                out_data.extend(data)
            data = memoryview(out_data)
        return data

    def _bid_size(self, bid):
        if bid != 0:
            bx = self._bbtx[bid]
            return bx["cb"]
        else:
            return 0

    def _get_bid(self, nid, hnid=None):
        nx = self._nbtx[nid]
        if hnid is not None:
            bid = nx["subEntries"][hnid]["bid"]
        else:
            bid = nx["bidData"]
        return bid

    def read_nid(self, nid, hnid=None):
        return self._read_data_block(self._get_bid(nid, hnid))

    def nid_size(self, nid, hnid=None):
        # NOTE само приблизително: не се отчитат XBLOCKS,
        # вътрешните връзки от PC и TC, bidSubData; за да
        # се отчетат ще трябва да се прочете в детайли
        # целия файл, което в случая не е оправдано
        bid = self._get_bid(nid, hnid)
        size = self._bid_size(bid)
        entx = self._nbtx[nid].get("subEntries", None)
        if hnid is None:
            if entx is not None:
                size += sum([self.nid_size(nid, x["nid"])
                             for x in entx.values()])
        return size

    def list_nids(self, nid_type):
        def nx_list(nodes, px=None):
            for nx in nodes:
                if nx["typeCode"] == nid_type:
                    yield (px is None and nx["nid"] or px,
                           px is not None and nx["nid"] or None,)
                sbe = nx.get("subEntries", None)
                if sbe is not None:
                    for ex in nx_list(sbe.values(), nx["nid"]):
                        yield ex
        return nx_list(self._nbt)


class NodeContext:
    def __init__(self, ndb, nid, hnid=None):
        self._ndb = ndb
        self._nid = nid
        self._buf = ndb.read_nid(nid, hnid)
        self._parse_HN_HDR(self._buf)
        # self._dump_HN_HDR(self._buf, title="NodeContext[HND]")

    def _parse_HN_HDR(self, buf):
        self._hn_header = UnpackDesc(buf, pos=0).unpack(HN_HDR)
        assert self._hn_header["bSig"] == 0xEC
        self._hn_header["bClientSig"] = hn_header_client_sig[
            self._hn_header["bClientSig"]]

        eng = UnpackDesc(buf, pos=self._hn_header["ibHnpm"])
        self._hn_pagemap = eng.unpack(HN_PAGE_MAP)

        pos = eng.pos
        allocs = []
        for p in range(0, self._hn_pagemap["cAlloc"]+1):
            allocs.append(unpackb("<H", buf, pos)[0])
            pos += 2
        # calculate start-offset, size
        allocs = map(lambda x, y: (y, x-y), allocs[1:], allocs[:-1])
        self._hn_pagemap["rgibAlloc"] = allocs

    def _dump_HN_HDR(self, bx, title=None):
        # dump_hex(buf)
        print "\n%s::heap_on_node:" % title
        pprint((self._hn_header, self._hn_pagemap), indent=4)
        print
        for pos, lx in self._hn_pagemap["rgibAlloc"]:
            dump_hex(bx[pos:pos+lx])

    def _get_hid_pos_lx(self, px):
        hidIndex = get_hid_index(px)
        assert hidIndex <= 2**11, hidIndex
        # zero based, return pos (buffer position), lx (length)
        return self._hn_pagemap["rgibAlloc"][hidIndex-1]

    def _parse_bt_header(self, bth):
        hid = get_hid_index(bth)
        pos, lx = self._hn_pagemap["rgibAlloc"][hid-1]
        eng = UnpackDesc(self._buf[pos:pos+lx])
        bth_header = eng.unpack(BTH_HEADER)
        assert eng.pos == lx
        return bth_header


class PropertyValue:
    def __init__(self, pt, pbuf=None):
        self._pt = pt
        self._buf = pbuf
        unk_pt = ("0x%04X" % self._pt, "UNKNOWN", -1, None)
        self.pt_desc = prop_types.get(self._pt, unk_pt)
        pt_method = "_read_%s" % self.pt_desc[0]
        self._read = getattr(self, pt_method)

    class BinaryValue:
        def __init__(self, data):
            self.data = data

        def __str__(self):
            out = StringIO()
            dump_hex(self.data, out=out)
            return out.getvalue().strip()

        def __len__(self):
            return len(self.data)

    @classmethod
    def _read_String(cls, pbuf):
        s1 = decode(pbuf, "UTF-16LE", "replace")
        ix = s1.find("\0")
        if ix >= 0:
            s1 = s1[0:ix]
        return s1

    @classmethod
    def _read_Binary(cls, pbuf):
        return cls.BinaryValue(pbuf)

    @classmethod
    def _read_Boolean(cls, pbuf):
        return unpackb("<L", pbuf)[0] == 1L

    @classmethod
    def _read_Integer16(cls, pbuf):
        return unpackb("<H", pbuf)

    @classmethod
    def _read_Integer32(cls, pbuf):
        return unpackb("<L", pbuf)

    @classmethod
    def _read_Integer64(cls, pbuf):
        return unpackb("<Q", pbuf)

    @classmethod
    def _read_Time(cls, pbuf):
        stime = unpackb("<Q", pbuf)[0]/10000000  # seconds
        days, seconds = divmod(stime, 24*60*60)
        delta = timedelta(days=days, seconds=seconds)
        return datetime(year=1601, month=1, day=1) + delta

    def get_value(self):
        return self._read(self._buf)


class PropertyContext(NodeContext):
    def __init__(self, ndb, nid, hnid=None):
        NodeContext.__init__(self, ndb, nid, hnid)
        assert self._hn_header["bClientSig"][0] == "bTypePC"
        self._bth_header = self._parse_bt_header(
            self._hn_header["hidUserRoot"])
        self._read_props_map()

    def _read_props_map(self):
        hid = get_hid_index(self._bth_header["hidRoot"])
        pos, lx = self._hn_pagemap["rgibAlloc"][hid-1]
        eng = UnpackDesc(self._buf[pos:pos+lx])
        for p in range(lx / 8):
            eng.unpack(PC_BTH_RECORD)
        self._props = dict([(x["propTag"], x) for x in eng.out])
        enrich_prop_code(self._props.values())

    def get_buffer(self, ptag):
        px = self._props[ptag]
        pt_name, pt_size, _ = prop_types[px["propType"]]
        # 2.3.3.3 PC BTH Record (dwValueHnid, p.60)
        if pt_size > 0 and pt_size <= 4:
            return memoryview(bytearray(px["value"]))
        else:
            hnid = ulong_from_tuple(px["value"])
            nid_type = get_hnid_type(hnid)
            if nid_type == "HID":
                pos, lx = self._get_hid_pos_lx(px["value"])
                return self._buf[pos:pos+lx]
            else:
                return self._ndb.read_nid(self._nid, hnid)

    def _read_entry_id(self, ptag):
        b2 = self._read_binary(ptag)
        # dump_hex(b2)
        STORE_ENTRY_ID = """\
        rgbFlags byte[4]  # Flags
                          # each of these bytes MUST be initialized to zero.
        uid      byte[16] # PidTagRecordKey
        nid      DWORD    # This is the corresponding NID of the underlying
                          # node that represents the object.
        """
        eng = UnpackDesc(b2)
        eng.unpack2(STORE_ENTRY_ID)
        va = dict(eng.out)
        assert va["rgbFlags"] == (0, 0, 0, 0)
        return va


def test_ndb_info(ndb):
    print "="*60, "\nNDB Layer info\n"
    h1 = dict([(a, b) for a, b in ndb._header.iteritems()
               if a in ("ibFileEof", "brefNBT",
                        "brefBBT", "bCryptMethod")])
    print "[{0:s}]:: {1:,d} bytes".format(
        fnm, sum(x["cb"] for x in ndb._bbt)),
    print "in {0:,d} blocks by {1:,d} nids".format(
        len(ndb._bbt), len(ndb._nbt))
    pprint(h1, indent=4)
    print
    nid_type_cnt = {}
    sub_nid_type_cnt = {}

    def append_tab_entry(tab, nx, px=None):
        nt = nx["typeCode"]
        if nt not in tab:
            tab[nt] = [0, 0]
        tab[nt][0] += 1
        if px is not None:
            nx1 = px["nid"]
            nx2 = nx["nid"]
        else:
            nx1 = nx["nid"]
            nx2 = None
        tab[nt][1] += ndb.nid_size(nx1, nx2)

    def print_tab(tab, title):
        print title
        kt = tab.keys()
        kt.sort()
        for nm in kt:
            cnt, size = tab[nm]
            print "  {0:<22s} {1:>7,d} {2:>12,d}".format(
                nm, cnt, size)
        print

    for nx in ndb._nbt:
        append_tab_entry(nid_type_cnt, nx)
        snid = nx.get("subEntries", None)
        if snid is not None:
            for snx in snid.values():
                append_tab_entry(sub_nid_type_cnt, snx, nx)
    print_tab(nid_type_cnt, "Top level")
    print_tab(sub_nid_type_cnt, "Subnodes, o.w.")
    print "done in {0:,.3f} sec".format(ndb._done_time)
    print


def test_PC(ndb, nid, hnid=None, _max_binary_len=1024):
    print "="*60
    print nid, hnid, "\n"
    pc = PropertyContext(ndb, nid, hnid)
    for k, p in pc._props.iteritems():
        value_buf = pc.get_buffer(p['propTag'])
        pv = PropertyValue(p["propType"], value_buf)
        pt_code, pt_size, _, = pv.pt_desc
        ptag = all_props_types.get(p['propTag'], None)
        ptag = ptag and ptag["name"] or p["propCode"]
        try:
            value = pv.get_value()
            BinValue = PropertyValue.BinaryValue
            if isinstance(value, BinValue):
                value = BinValue(value.data[:_max_binary_len])
        except NotImplementedError:
            out = StringIO()
            dump_hex(value_buf[:_max_binary_len], out=out)
            value = out.getvalue().strip()
        print "0x%04X %-10s %4d %6d %-40s" % (
            k, pt_code, pt_size, len(value_buf), ptag, ),
        if value is not None and len(unicode(value)) >= 30:
            print "\n%s\n" % value
        else:
            print "[%s]" % value
    print


def test_nids(ndb, nid_type, fun=None, n=-1, s=0):
    fun = fun or (lambda _, *nx: pprint(nx))
    for nx in ndb.list_nids(nid_type):
        if s == 0:
            fun(ndb, *nx)
        else:
            s -= 1
            continue
        n -= 1
        if n == 0:
            break


def test_list_attachments(ndb):
    def att_info(ndb, nid, hnid):
        pc = PropertyContext(ndb, nid, hnid)
        # TODO проверка дали има дадено property 0x3707 0x3704
        # TODO PropertyValue да бъде implementation detail (private)
        p1 = PropertyValue(0x0003, pc.get_buffer(0x0E20)).get_value()[0]
        p2 = PropertyValue(0x001F, pc.get_buffer(0x3704)).get_value()
        print "{0:9d} {1:9d} {2:12,d} {3:<20}".format(nid, hnid, p1, p2)
    test_nids(ndb, "ATTACHMENT", fun=att_info)


if __name__ == '__main__':
    from pprint import pprint
    from os import path
    from sys import argv
    fnm = len(argv) > 1 and argv[1] or u"test"
    fnm = path.join("pstdata", "%s.pst" % fnm)
    with NDBLayer(fnm) as ndb:
    # with run_profile(NDBLayer, fnm) as ndb:
        test_ndb_info(ndb)
        # test_nids(ndb, "NORMAL_FOLDER", fun=test_PC, n=2, s=1)
        # test_nids(ndb, "NORMAL_MESSAGE", fun=test_PC, n=1)
        # test_nids(ndb, "RECIPIENT_TABLE", fun=test_TC, n=1, s=1)
        # test_list_attachments(ndb)
        test_PC(ndb, 2121252, 36933)
