# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

import logging
import os
import pickle
import time
from codecs import decode
from datetime import datetime, timedelta
from io import StringIO
from pprint import pprint
from struct import calcsize
from struct import unpack_from as unpackb
from traceback import print_exc

from pytz import timezone
from pytz import utc as UTC

from readms.metapst import (
    BBT_ENTRY,
    BLOCK_SIGNATURE,
    BLOCK_TRAILER,
    BT_ENTRY,
    BT_PAGE,
    BTH_HEADER,
    HEADER_1,
    HEADER_2,
    HN_HDR,
    HN_PAGE_MAP,
    NBT_ENTRY,
    PAGE_TRAILER,
    PC_BTH_RECORD,
    SL_ENTRY,
    all_props_types,
    enrich_prop_code,
    get_hid_index,
    get_hnid_type,
    hn_header_client_sig,
    nid_internal_types,
    nid_types,
    page_types,
    prop_types,
)
from readms.readutl import (
    UnpackDesc,
    decode_permute,
    dump_hex,
    ulong_from_tuple,
    uuid_from_buf,
)

log = logging.getLogger(__name__)


def read_ndb_page(fin, bref):
    _, ib = bref
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

    ptype_desc = {"BT": BT_ENTRY, "BBT": BBT_ENTRY, "NBT": NBT_ENTRY}
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
    return {"meta": meta, "entries": entries}


# pylint: disable=too-many-instance-attributes
# Всички атрибути са необходими за описанието на NDB.
class NDBLayer:
    def __init__(self, file_name, index_dir=None):
        self._fin = open(file_name, "rb")
        self._read_header()
        self._bbt = []
        self._nbt = []
        start = time.time()
        self._file_name = file_name
        if index_dir is None:
            index_dir = os.path.join(os.path.dirname(file_name), 'index')
        self._index_dir = index_dir
        if not self._load_index():
            self._read_bbt(self._header["brefBBT"])
            self._read_nbt(self._header["brefNBT"])
            self._save_index()
        # тъй като файлът е read-only, за сега, hash структура също върши работа
        self._prop_internal = None
        self._done_time = time.time() - start

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self.close()
        except:
            print_exc()
        return False

    def close(self):
        self._fin.close()

    def _index_name(self):
        bname = os.path.basename(self._file_name)
        dname = os.path.dirname(self._file_name)
        name, _ext = os.path.splitext(bname)
        iname = f"{name}.idx"
        if self._index_dir is not None:
            if not os.path.exists(self._index_dir):
                os.makedirs(self._index_dir)
            iname = os.path.join(self._index_dir, iname)
        else:
            iname = os.path.join(dname, iname)
        return iname

    def _load_index(self):
        indx = self._index_name()
        if not os.path.exists(indx):
            return False

        fn_mtime = os.stat(self._file_name).st_mtime
        fn_mtime = datetime.fromtimestamp(fn_mtime)
        ix_mtime = os.stat(indx).st_mtime
        ix_mtime = datetime.fromtimestamp(ix_mtime)
        # индекса е по-стар от pst файла
        if fn_mtime > ix_mtime:
            return False

        with open(self._index_name(), "rb") as fin:
            index = pickle.load(fin)
            # TODO: проверка на валидността на cache по полета от header
            # index["header"] = self._header
            self._bbt = index["bbt"]
            self._bbtx = index["bbtx"]
            self._nbt = index["nbt"]
            self._nbtx = index["nbtx"]
        return True

    def _save_index(self):
        with open(self._index_name(), "wb") as fout:
            index = {}
            index["header"] = self._header
            index["bbt"] = self._bbt
            index["bbtx"] = self._bbtx
            index["nbt"] = self._nbt
            index["nbtx"] = self._nbtx
            pickle.dump(index, fout, pickle.HIGHEST_PROTOCOL)

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

        assert eng.pos == len(buf), f"pos={eng.pos:d}, len={len(buf):d}"
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

    @staticmethod
    def _enrich_nid_type(ex):
        ex["type"] = ex["nid"] & 0x1F
        if ex["type"] == 1:
            ez = ex["nid"] & 0x3FF
            type_desc = nid_internal_types.get(ez, None)
        else:
            ez = ex["nid"] & 0x1F
            type_desc = nid_types.get(ez, None)
        if type_desc is not None:
            ex["typeCode"] = type_desc[0]
        else:
            ex["typeCode"] = f"{ex['type']:#04X}"

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
                ex["nid"] = ex["nid"] & 0xFFFFFFFF
            entries = {x["nid"]: x for x in eng.out}
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
            # TODO: 2.2.2.8.3.3.2 SIBLOCKs
            raise NotImplementedError
        else:
            raise KeyError(c_level)
        return entries

    def _read_block(self, bbt):
        bid, ib = bbt["bref"]
        # print "_read_block::bbt", bbt
        # block_size is near greater multiple by 64
        # 16 is the trailer block size
        block_size = (((bbt["cb"] + 16) - 1) // 64 + 1) * 64
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

    @staticmethod
    def _read_block_sign(buf):
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
                bids = unpackb(f"<{sign['cEnt']}Q", data, pos+4)
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

            read_xblock_bids(data)
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

    def list_nids(self, nid_type, start_with=None):
        def nx_list(nodes, px=None):
            for nx in nodes:
                if nx["typeCode"] == nid_type:
                    yield (px is None and nx["nid"] or px,
                           px is not None and nx["nid"] or None,)
                sbe = nx.get("subEntries", None)
                if sbe is not None:
                    for ex in nx_list(sbe.values(), nx["nid"]):
                        yield ex
        if start_with is not None:
            zx = self._nbtx[start_with].get("subEntries", None)
            if zx is not None:
                return nx_list(zx.values(), start_with)
            return nx_list([])

        return nx_list(self._nbt)

    def get_prop_names_map(self):
        if self._prop_internal is None:
            self._prop_internal = PropertyNameMap(self)
        return self._prop_internal


class NodeHeap:
    def __init__(self, ndb, nid, hnid=None):
        self._ndb = ndb
        self._nid = nid
        self._buf = ndb.read_nid(nid, hnid)
        self._parse_HN_HDR(self._buf)
        # self._dump_HN_HDR(self._buf, title="NodeHeap[HND]")

    def _parse_HN_HDR(self, buf):
        self._hn_header = UnpackDesc(buf, pos=0).unpack(HN_HDR)
        assert self._hn_header["bSig"] == 0xEC
        self._hn_header["bClientSig"] = hn_header_client_sig[
            self._hn_header["bClientSig"]]

        eng = UnpackDesc(buf, pos=self._hn_header["ibHnpm"])
        self._hn_pagemap = eng.unpack(HN_PAGE_MAP)

        pos = eng.pos
        allocs = []
        for _ in range(0, self._hn_pagemap["cAlloc"]+1):
            allocs.append(unpackb("<H", buf, pos)[0])
            pos += 2
        # calculate start-offset, size
        allocs = [(y, x-y) for x, y in zip(allocs[1:], allocs[:-1])]
        self._hn_pagemap["rgibAlloc"] = allocs

    def _dump_HN_HDR(self, bx, title=None):
        # dump_hex(buf)
        print(f"\n{title}::heap_on_node:")
        pprint((self._hn_header, self._hn_pagemap), indent=4)
        print()
        for pos, lx in self._hn_pagemap["rgibAlloc"]:
            dump_hex(bx[pos:pos+lx])

    def _get_hid_pos_lx(self, hid):
        hidIndex = get_hid_index(hid)
        # XXX: Не е най-доброто решение; временно, докато не се намери подходящо документация
        # XXX: Сравнително рядко, но доста досадно, индекса е малко по-голям от 2048
        if hidIndex > 2**11:
            log.warning(f'{self._nid}: hidIndex: {hidIndex:08X}; '
                        f'{len(self._hn_pagemap["rgibAlloc"])}')
            hidIndex -= 2**11
        assert hidIndex <= 2**11, hidIndex
        # zero based, return pos (buffer position), lx (length)
        return self._hn_pagemap["rgibAlloc"][hidIndex-1]

    def _parse_btree_header(self, hid):
        hidIndex = get_hid_index(hid)
        pos, lx = self._hn_pagemap["rgibAlloc"][hidIndex-1]
        eng = UnpackDesc(self._buf[pos:pos+lx])
        bth_header = eng.unpack(BTH_HEADER)
        assert eng.pos == lx
        return bth_header


class PropertyValue:
    def __init__(self, pt, pbuf=None):
        self._pt = pt
        self._buf = pbuf
        unk_pt = (f"{self._pt:#04X}", "UNKNOWN", -1, None)
        self.pt_desc = prop_types.get(self._pt, unk_pt)
        pt_method = f"_read_{self.pt_desc[0]}"
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
    def _read_Object(cls, pbuf):
        return cls.BinaryValue(pbuf)

    @classmethod
    def _read_Boolean(cls, pbuf):
        return unpackb("<L", pbuf)[0] == 1

    @classmethod
    def _read_Integer16(cls, pbuf):
        return unpackb("<H", pbuf)[0]

    @classmethod
    def _read_Integer32(cls, pbuf):
        return unpackb("<L", pbuf)[0]

    @classmethod
    def _read_Integer64(cls, pbuf):
        return unpackb("<Q", pbuf)[0]

    @classmethod
    def _read_Floating64(cls, pbuf):
        return unpackb("<d", pbuf)[0]

    @classmethod
    def _read_Time(cls, pbuf):
        stime = unpackb("<Q", pbuf)[0]//10000000  # seconds
        days, seconds = divmod(stime, 24*60*60)
        delta = timedelta(days=days, seconds=seconds)
        result = datetime(year=1601, month=1, day=1, tzinfo=UTC) + delta
        return result.astimezone(timezone("Europe/Sofia"))

    @classmethod
    def _read_PtypMultipleString(cls, pbuf):
        n_strings = unpackb("<L", pbuf)[0]
        start_strings = [unpackb("<L", pbuf[4*be+4:])[0] for be in range(n_strings)]

        result = []
        for ix_ in range(n_strings):
            start_s = start_strings[ix_]
            if ix_ < n_strings - 1:
                end_s = start_strings[ix_+1]
                value = cls._read_String(pbuf[start_s:end_s])
            else:
                value = cls._read_String(pbuf[start_s:])
            result.append(value)
        return result

    @classmethod
    def _read_PtypGuid(cls, pbuf):
        # [MS-DTYP] Windows Data Types 2.3.4 GUID and UUID
        if (len(pbuf) != 16):
            # XXX: Защо има такива, да се прегледа последната версия на документацията
            return cls._read_Binary(pbuf)
        px = (unpackb("<L", pbuf, 0)[0], unpackb("<H", pbuf, 4)[0],
              unpackb("<H", pbuf, 6)[0], unpackb("<8B", pbuf, 8))
        fx1 = '%04X-%02X-%02X' % px[:3]
        fx2 = ('-'.join(('%02X',)*8)) % px[3]
        return '-'.join((fx1, fx2))

    @classmethod
    def _read_PtypMultipleInteger32(cls, pbuf):
        nobj = unpackb("<L", pbuf)[0]
        # log.info('read %d int32', nobj)
        # dump_hex(pbuf)
        result = []
        for ix_ in range(nobj):
            result.append(cls._read_Integer32(pbuf[4*(1+ix_):]))
        return result

    @classmethod
    def _read_PtypMultipleBinary(cls, pbuf):
        return cls._read_Binary(pbuf)

    def get_value(self):
        return self._read(self._buf)


class PropertyContext(NodeHeap):
    def __init__(self, ndb, nid, hnid=None):
        NodeHeap.__init__(self, ndb, nid, hnid)
        assert self._hn_header["bClientSig"][0] == "bTypePC"
        self._bth_header = self._parse_btree_header(self._hn_header["hidUserRoot"])
        self._read_props_map()

    def _read_props_map(self):
        hid = get_hid_index(self._bth_header["hidRoot"])

        # По долния проблем, за целите на разследването
        # print('hid>0x1F: len:%d hid:%d/%s hidRoot:%s' % (
        #     len(self._hn_pagemap["rgibAlloc"]), hid, hex(hid),
        #     hex(self._bth_header["hidRoot"])))
        # print(self._bth_header)
        # self._dump_HN_HDR(self._buf, 'hid>0x1F')

        # NOTE За тези, които са дефиктни, hidBlockIndex (виж 2.3.1.1 HID) е различно от нула
        # Това означава че описанието на атрибутите стоят в отделен блок; така че проверката
        # не трябва да е както беше с 1F (много необосновано) ами както е направена по-долу
        if self._bth_header["hidRoot"] >> 16 != 0:
            # FIXME: В този случай получава IndexError: list index out of range
            # причината е че не се определя правилно таблицата с описанието на атрибутите
            # и те се чeтат от където падне; за този (твърде рядък) случай не се извлича нищо
            self._props = {}
            self._propx = {}
            return

        pos, lx = self._hn_pagemap["rgibAlloc"][hid-1]
        eng = UnpackDesc(self._buf[pos:pos+lx])
        for _ in range(lx // 8):
            eng.unpack(PC_BTH_RECORD)
        self._props = {x["propTag"]: x for x in eng.out}

        enrich_prop_code(self._props.values())
        if not isinstance(self, PropertyNameMap):
            names_map = self._ndb.get_prop_names_map()
            names_map.enrich_props(self._props.values())
        self._propx = {v["propCode"]: k for k, v in self._props.items()}

    def get_buffer(self, ptag):
        px = self._props[ptag]
        _, pt_size, _ = prop_types[px["propType"]]
        # 2.3.3.3 PC BTH Record (dwValueHnid, p.60)
        if 0 < pt_size <= 4:
            return memoryview(bytearray(px["value"]))

        hnid = ulong_from_tuple(px["value"])
        nid_type = get_hnid_type(hnid)
        if nid_type == "HID":
            pos, lx = self._get_hid_pos_lx(px["value"])
            return self._buf[pos:pos+lx]
        return self._ndb.read_nid(self._nid, hnid)

    def get_value(self, prop_name):
        if prop_name is None or prop_name not in self._propx:
            return None
        ptag = self._propx[prop_name]
        pt = self._props[ptag]["propType"]
        pv = PropertyValue(pt, self.get_buffer(ptag))
        return pv.get_value()

    def get_value_safe(self, prop_name, default=None):
        if prop_name in self._propx:
            return self.get_value(prop_name)
        return default

    def alt_name(self, *args):
        for x in args:
            if x in self._propx:
                return x
        return None


class PropertyNameMap(PropertyContext):
    def __init__(self, ndb):
        ntm = [k for k, v in nid_internal_types.items() if v[0] == "NAME_TO_ID_MAP"]
        assert len(ntm) == 1
        PropertyContext.__init__(self, ndb, ntm[0], hnid=None)
        # 2.1.2 Properties (само валидните за контекста)
        # 0x0001 PidTagNameidBucketCount
        # 0x0002 PidTagNameidStreamGuid
        # 0x0003 PidTagNameidStreamEntry
        # 0x0004 PidTagNameidStreamString
        self._guids = self._read_guid_stream()
        names = self._read_name_stream()
        self._props = self._read_string_stream(names)
        self._props = {tag: (name, guid) for tag, guid, name in self._props}

    def _read_guid_stream(self):
        data = self._read_binary_data(0x0002)
        data_len = len(data)
        guids = []
        pos = 0
        while pos < data_len:
            guids.append(uuid_from_buf(data[pos:]))
            pos += 16
        return guids

    def _get_guid(self, guid):
        guid_ix = (guid >> 1) - 3
        if guid_ix >= 0:
            return self._guids[guid_ix]
        return None

    def _read_name_stream(self):
        data = self._read_binary_data(0x0003)
        # 2.4.7.1 NAMEID
        entry_bfmt = "<LHH"
        entry_size = calcsize(entry_bfmt)
        data_len = len(data)
        names = []
        pos = 0
        while pos < data_len:
            prop_id, guid_ix, prop_ix = unpackb(entry_bfmt, data[pos:])
            n_flag = guid_ix & 0x1 == 1
            if n_flag:
                names.append((prop_ix, prop_id, guid_ix))
            pos += entry_size
        return names

    def _read_string_stream(self, names):
        names_data = self._read_binary_data(0x0004)
        allocs = [x[1] for x in names]
        names_w = [decode(names_data[x+4:y], "UTF-16LE", "replace")
                   for x, y in zip(allocs[:-1], allocs[1:])]
        names_w = [x.encode('ascii', errors='ignore') for x in names_w]
        names_w = [x.decode('ascii') for x in names_w]
        names_out = [(idx+0x8000, self._get_guid(guid), desc)
                     for (idx, _, guid), desc in zip(names, names_w)]
        return names_out

    def _read_binary_data(self, tag):
        buf = self.get_buffer(tag)
        val = PropertyValue(0x0102, buf)
        return val.get_value().data

    def enrich_props(self, props):
        for prop in props:
            tag = prop["propTag"]
            if tag < 0x8000 or tag > 0xFFFF:
                continue
            fx = self._props.get(tag, None)
            if fx is not None:
                prop["propCode"] = fx[0]


def test_ndb_info(ndb):
    print("="*60, "\nNDB Layer info\n")
    h1 = {a: b for a, b in ndb._header.items()
          if a in ("ibFileEof", "brefNBT", "brefBBT", "bCryptMethod")}
    print(f"{sum(x['cb'] for x in ndb._bbt):,d} bytes", end=' ')
    print(f"in {len(ndb._bbt):,d} blocks by {len(ndb._nbt):,d} nids")
    pprint(h1, indent=4)
    print()
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
        print(title)
        kt = list(tab.keys())
        kt.sort()
        for nm in kt:
            cnt, size = tab[nm]
            print(f"  {nm:<30s} {cnt:>7,d} {size:>12,d}")
        print()

    for nx in ndb._nbt:
        append_tab_entry(nid_type_cnt, nx)
        snid = nx.get("subEntries", None)
        if snid is not None:
            for snx in snid.values():
                append_tab_entry(sub_nid_type_cnt, snx, nx)
    print_tab(nid_type_cnt, "Top level")
    print_tab(sub_nid_type_cnt, "Subnodes, o.w.")
    print(f"done in {ndb._done_time:,.3f} sec")
    print()


def test_PC(ndb, nid, hnid=None, _max_binary_len=512):
    print("="*60)
    print(nid, hnid, "\n")
    pc = PropertyContext(ndb, nid, hnid)
    for k, p in pc._props.items():
        value_buf = pc.get_buffer(p['propTag'])
        pv = PropertyValue(p["propType"], value_buf)
        pt_code, pt_size, _, = pv.pt_desc
        ptag = all_props_types.get(p['propTag'], None)
        ptag = ptag["name"] if ptag else p["propCode"]
        try:
            value = pv.get_value()
            BinValue = PropertyValue.BinaryValue
            if isinstance(value, BinValue):
                value = BinValue(value.data[:_max_binary_len])
        except NotImplementedError:
            out = StringIO()
            dump_hex(value_buf[:_max_binary_len], out=out)
            value = out.getvalue().strip()
        print(f"{k:#04X} {pt_code:10s} {pt_size:4d} "
              f"{len(value_buf):6d} {ptag:40s}", end='')
        if value is not None and len(str(value)) >= 30:
            print(f"\n{value}\n")
        else:
            print(f"[{value}]")
    print()


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


if __name__ == '__main__':
    from sys import argv
    with NDBLayer(argv[1]) as ndb_:
        test_ndb_info(ndb_)
        test_nids(ndb_, "NORMAL_FOLDER", fun=test_PC, n=3, s=1)
        # test_nids(ndb_, "NORMAL_MESSAGE", fun=test_PC, n=1)
        # test_nids(ndb_, "NAME_TO_ID_MAP", fun=test_PC)
        # pm = PropertyNameMap(ndb_)
        # test_PC(ndb, 2121252, 36933)
