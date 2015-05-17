# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

import gzip
from codecs import decode, encode
from StringIO import StringIO
from datetime import datetime, timedelta
from struct import unpack_from as unpackb
from readutl import (
    dump_hex, decode_permute, ulong_from_tuple, UnpackDesc)
from metapst import (
    page_types, nid_types, prop_types, all_props_types,
    hn_header_client_sig,
    enrich_prop_code, props_tags_codes,
    get_hid_index, get_hnid_type)


def read_header(fin):
    buf = memoryview(fin.read(564))
    # dump_hex(buf)
    eng = UnpackDesc(buf)

    s1 = """\
    dwMagic         byte[4] # MUST be { 0x21, 0x42, 0x44, 0x4E } ("!BDN")
    dwCRCPartial    DWORD
    wMagicClient    byte[2] # MUST be { 0x53, 0x4D }
    wVer            WORD  # File format version. This value MUST be
                          # 15 if the file is an ANSI PST file, and
                          # MUST be 23 if the file is a Unicode PST file.
    wVerClient      WORD  # Client file format version. The version that
                          # corresponds to the format described in this
                          # document is 19.
    bPlatformCreate byte  # This value MUST be set to 0x01
    bPlatformAccess byte  # This value MUST be set to 0x01
    dwOpenDBID      DWORD
    dwOpenClaimID   DWORD
    bidUnused       BID   # Unused padding added when the Unicode PST file
                          # format was created
    bidNextP        BID   # Next page BID. Pages have a special counter for
                          # allocating bidIndex values. The value of bidIndex
                          # for BIDs for pages is allocated from this counter
    # bidNextB        BID   # Next BID. This value is the monotonic counter
    #                       # that indicates the BID to be assigned for the
    #                       # next allocated block. BID values advance in
    #                       # increments of 4. See section 2.2.2.2.
    dwUnique        DWORD
    gnid            DWORD[32] # A fixed array of 32 NIDs, each corresponding
        # to one of the 32 possible NID_TYPEs (section 2.2.2.1). Different
        # NID_TYPEs can have different starting nidIndex values. Each of
        # these NIDs indicates the last nidIndex value that had been
        # allocated for the corresponding NID_TYPE. When a NID of a
        # particular type is assigned, the corresponding slot in rgnind is
        # also incremented by one (1)
    """
    eng.unpack2(s1)
    eng.skip(8)  # skip qwAlign QWORD

    s2 = """\
    cOrphans    DWORD
    ibFileEof   IB    # The size of the PST file, in bytes
    ibAMapLast  IB    # An IB structure (section 2.2.2.3) that contains
                      # the absolute file offset to the last AMap page
                      # of the PST file.
    ibAMapFree  CB    # The total free space in all AMaps, combined
    cbPMapFree  CB    # The total free space in all PMaps, combined.
                      # Because the PMap is deprecated, this value
                      # SHOULD be zero (0).
    brefNBT     BREF  # A BREF structure (section 2.2.2.4) that references
                      # the root page of the Node BTree (NBT)
    brefBBT     BREF  # A BREF structure that references the root page
                      # of the Block BTree (BBT)
    fAMapValid  byte  # Indicates whether all of the AMaps in this PST file
        # are valid. For more details, see section 2.6.1.3.8.  This value
        # MUST be set to one of the pre-defined values specified in the
        # following table.
        # 0x00 One or more AMaps in the PST are INVALID
        # 0x01 Deprecated. The AMaps are VALID.
        # 0x02 The AMaps are VALID.
    bARVec      byte  # Reserved
    cARVec      WORD  # Reserved
    """
    eng.unpack2(s2)
    eng.skip(4)    # skip dwAlign  DWORD
    eng.skip(128)  # skip rgbFMap  byte[128] Deprecated FMap
    eng.skip(128)  # skip rgbFPMap byte[128] Deprecated FPMap

    s4 = """\
    bSentinel         byte     # MUST be set to 0x80
    bCryptMethod      byte     # Indicates how the data within the PST file
        # is encoded. MUST be set to one of the following pre-defined values
        # 0x00 Data blocks are not encoded
        # 0x01 Encoded with Permutation Algorithm (section 5.1)
        # 0x02 Encoded with Cyclic Algorithm (section 5.2)
    bReserved         byte[2]  # Reserved; MUST be set to zero (0)
    bidNextB          BID      # Indicates the next available BID value
    dwCRCFull         DWORD
    rgbVersionEncoded byte[3]
    bLockSemaphore    byte
    rgbLock           byte[32]
    """
    eng.unpack2(s4)
    # print eng.out
    assert eng.pos == len(buf), "pos=%d, len=%d" % (eng.pos, len(buf))

    out = dict(eng.out)
    assert out["dwMagic"] == (0x21, 0x42, 0x44, 0x4E)
    assert out["wMagicClient"] == (0x53, 0x4D)
    assert out["wVer"] == 23, "Unicode PST"
    assert out["bCryptMethod"] in (0x00, 0x01,), "Encrypted PST"
    return out


def read_ndb_page(fin, bref):
    bid, ib = bref
    fin.seek(ib)
    buf = memoryview(fin.read(512))
    # dump_hex(buf)
    eng = UnpackDesc(buf)

    BT_PAGE = """\
    cEnt     byte   # The number of BTree entries stored in the page data
    cEntMax  byte   # The maximum number of entries that can fit inside
                    # the page data
    cbEnt    byte   # The size of each BTree entry, in bytes.
        # Note that in some cases, cbEnt can be greater than the
        # corresponding size of the corresponding rgentries structure
        # because of alignment or other considerations. Implementations
        # MUST use the size specified in cbEnt to advance to the next
        # entry.
    cLevel   byte   # The depth level of this page.
        # Leaf pages have a level of 0, whereas intermediate pages have
        # a level greater than 0.  This value determines the type of the
        # entries in rgentries, and is interpreted as unsigned.
    """
    eng.seek(488)
    eng.unpack2(BT_PAGE)
    eng.skip(4)  # dwPadding DWORD # Padding; MUST be set to zero (0)

    PAGE_TRAILER = """\
    ptype         byte
    ptypeRepeat   byte  # MUST be set to the same value as ptype
    wSig          WORD  # Page signature. This value depends on the
        # value of the ptype field. This value is zero (0x0000) for
        # AMap, PMap, FMap, and FPMap pages.  For BBT, NBT, and DList
        # pages, a page / block signature is computed (see section 5.5).
    dwCRC         DWORD
    bid           BID   # The BID of the page's block
    """
    eng.unpack2(PAGE_TRAILER)
    meta = dict(eng.out)
    assert eng.pos == 512
    assert meta["ptype"] == meta["ptypeRepeat"]

    # BT_ENTRY records contain a key value (NID or BID) and a reference
    # to a child BTPAGE page in the BTree
    BT_ENTRY = """\
    btkey BID   # The key value associated with this BTENTRY.
        # All the entries in the child BTPAGE referenced by BREF have
        # key values greater than or equal to this key value. The btkey
        # is either a NID (zero extended to 8 bytes for Unicode PSTs) or
        # a BID, depending on the ptype of the page.
    bref  BREF  # BREF (section 2.2.2.4) that points to the child BTPAGE.
                # contains {BID, IB (file position)}
    """
    # BBT_ENTRY records contain information about blocks and are found
    # in BT_PAGES with cLevel equal to 0, with the ptype of ptypeBBT.
    # These are the leaf entries of the BBT.
    BBT_ENTRY = """\
    bref BREF # BREF structure (section 2.2.2.4) that contains the BID
              # and IB of the block that the BBTENTRY references.
    cb   WORD # The count of bytes of the raw data contained in the
              # block referenced by BREF excluding the block trailer and
              # alignment padding, if any.
    cRef WORD # Reference count indicating the count of references to
              # this block. See section 2.2.2.7.7.3.1 regarding how
              # reference counts work.
    """
    # NBTENTRY records contain information about nodes and are found in
    # BTPAGES with cLevel equal to 0, with the ptype of ptypeNBT. These
    # are the leaf entries of the NBT.
    NBT_ENTRY = """\
    nid         NID   # The NID (section 2.2.2.1) of the entry.
        # Note that the NID is a 4-byte value for both Unicode and ANSI
        # formats. However, to stay consistent with the size of the
        # btkey member in BTENTRY, the 4-byte NID is extended to its
        # 8-byte equivalent for Unicode PST files.
    bidData     BID   # The BID of the data block for this node
    bidSub      BID   # The BID of the subnode block for this node.
        # If this value is zero (0), then a subnode block does not exist
        # for this node
    nidParent   DWORD # If this node represents a child of a Folder object
        # defined in the Messaging Layer, then this value is nonzero and
        # contains the NID of the parent Folder object's node.
        # Otherwise, this value is zero (0). See section 2.2.2.7.7.4.1
        # for more information. This field is not interpreted by any
        # structure defined at the NDB Layer.
    """

    ptype_desc = dict(BT=BT_ENTRY, BBT=BBT_ENTRY, NBT=NBT_ENTRY)
    ptype_code = page_types[meta["ptype"]][0]
    assert ptype_code in ("NBT", "BBT"), hex(meta["ptype"])
    if ptype_code == "NBT":
        if meta["cLevel"] == 0:
            sdesc = "NBT"
        else:
            sdesc = "BT"
    else:
        if meta["cLevel"] == 0:
            sdesc = "BBT"
        else:
            sdesc = "BT"
    meta["entriesType"] = sdesc
    entries = []
    for p in range(0, meta["cEnt"]):
        eng = UnpackDesc(buf, pos=p*meta["cbEnt"])
        eng.unpack2(ptype_desc[sdesc])
        entries.append(dict(eng.out))

    return dict(meta=meta, entries=entries)


class NDBLayer:
    def __init__(self, fin, header):
        self._header = header
        self._bbt = []
        self._nbt = []
        self._read_bbt(self._header["brefBBT"])
        self._read_nbt(self._header["brefNBT"])
        # TODO create tree structutes for BBT and NBT
        # тъй като файлът е read-only, за сега,
        # hash структура също върши работа

    def _read_bbt(self, bref):
        bbt = read_ndb_page(fin, bref)
        if bbt["meta"]["entriesType"] == "BT":
            for bt in bbt["entries"]:
                ent = read_ndb_page(fin, bt["bref"])
                for ex in ent["entries"]:
                    ex["internal"] = ex["bref"][0] & 2 != 0
                self._bbt.extend(ent["entries"])
        self._bbtx = {}
        for bx in self._bbt:
            bid, bbt = bx["bref"]
            self._bbtx[bid] = bx

    def _read_nbt(self, bref):
        nbt = read_ndb_page(fin, bref)
        if nbt["meta"]["entriesType"] == "BT":
            for bt in nbt["entries"]:
                ent = read_ndb_page(fin, bt["bref"])
                self._nbt.extend(ent["entries"])
        self._nbtx = {}
        for nx in self._nbt:
            self._nbtx[nx["nid"]] = nx

    def _read_block(self, bbt):
        bid, ib = bbt["bref"]
        print "_read_block::bbt", bbt
        # block_size is near greater multiple by 64
        # 16 is the trailer block size
        block_size = (((bbt["cb"] + 16) - 1) / 64 + 1) * 64
        assert block_size <= 8192  # 8176 + block trailer(16)
        fin.seek(ib)
        buf = memoryview(fin.read(block_size))
        # dump_hex(buf)
        BLOCK_TRAILER = """\
        cb    WORD  # The amount of data, in bytes, contained within
                    # the data section of the block.
                    # This value does not include the block trailer or any
                    # unused bytes that can exist after the end of the data
                    # and before the start of the block trailer.
        wSig  WORD  # Block signature (calculated)
        dwCRC DWORD # 32-bit CRC of the cb bytes (calculated)
        bid   BID   # The BID (section 2.2.2.2) of the data block
        """
        # block trailer is the last 16 bytes
        eng = UnpackDesc(buf, pos=block_size-16)
        eng.unpack2(BLOCK_TRAILER)
        block_trailer = dict(eng.out)
        print "_read_block::block_trailer", block_trailer
        assert block_trailer["cb"] == bbt["cb"]
        assert block_trailer["bid"] == bid
        data = buf[0:block_trailer["cb"]]
        if not bbt["internal"]:
            # decode with Permutation Algorithm (section 5.1)
            # only for user data blocks
            if header["bCryptMethod"] == 0x01:
                data = decode_permute(data)
        return data

    def _read_block_sign(self, buf):
        BLOCK_SIGNATURE = """\
        btype  byte # Block type
                    # 0x01 to indicate an XBLOCK or XXBLOCK.
                    # 0x02 to indicate an SLBLOCK or SIBLOCK
        cLevel byte # Block subtype
                    # 0x01 XBLOCK, 0x02 XXBLOCK
                    # 0x00 SLBLOCK, 0x01 SIBLOCK
        cEnt   WORD # The number of entries, depends on type
        """
        eng = UnpackDesc(buf)
        eng.unpack2(BLOCK_SIGNATURE)
        return dict(eng.out), eng.pos

    def _read_data_block(self, bid):
        bx = self._bbtx[bid]
        data = self._read_block(bx)
        if bx["internal"]:
            # 2.2.2.8.3.2 Data Tree XBLOCKS, XXBLOCKS
            data_bids = []

            def read_xblock_bids(data):
                dump_hex(data)
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
            print data_bids, totb
            out_data = bytearray()
            for bix in data_bids:
                data = self._read_data_block(bix)
                out_data.extend(data)
            data = memoryview(out_data)
        return data

    def read_nid(self, nid):
        nx = self._nbtx[nid]
        return self._read_data_block(nx["bidData"])

    def read_nid_sub(self, nid, hnid):
        nx = self._nbtx[nid]
        bid = nx["subEntries"][hnid]["bid"]
        return self._read_data_block(bid)


def parse_heap_on_node(buf):
    HN_HDR = """\
    ibHnpm       WORD # The byte offset to the HN page Map record
                      # section 2.3.1.5), with respect to the beginning
                      # of the HNHDR structure
    bSig         byte # Block signature;
                      # MUST be set to 0xEC to indicate a HN
    bClientSig   byte # Client signature.
        # This value describes the higher-level structure that is
        # implemented on top of the HN. This value is intended as a hint
        # for a higher-level structure and has no meaning for structures
        # defined at the HN level. The following values are pre-defined
        # for bClientSig. All other values not described in the
        # following table are reserved and MUST NOT be assigned or used.
        # See hn_header_client_sig.
    hidUserRoot  DWORD # HID that points to the User Root record.
    rgbFillLevel byte[4] # Per-block Fill Level Map.
        # This array consists of eight 4-bit values that indicate the
        # fill level for each of the first 8 data blocks (including this
        # header block).
    """
    eng = UnpackDesc(buf, pos=0)
    eng.unpack2(HN_HDR)
    hn_header = dict(eng.out)
    assert hn_header["bSig"] == 0xEC
    hn_header["bClientSig"] = hn_header_client_sig[hn_header["bClientSig"]]

    HN_PAGE_MAP = """\
    cAlloc WORD # Allocation count
    cFree  WORD # Free count
    """
    eng = UnpackDesc(buf, pos=hn_header["ibHnpm"])
    eng.unpack2(HN_PAGE_MAP)
    hn_page_map = dict(eng.out)

    eng = UnpackDesc(buf, pos=eng.pos)
    for p in range(0, hn_page_map["cAlloc"]+1):
        eng.unpack2("_ WORD")
    # calculate start-offset, size
    allocs = [v for n, v in eng.out]
    allocs = map(lambda x, y: (y, x-y), allocs[1:], allocs[:-1])
    hn_page_map["rgibAlloc"] = allocs
    return (hn_header, hn_page_map, )


def parser_bt_header(buf):
    PC_BTH_HEADER = """\
    bType byte # MUST be bTypeBTH (0xB5)
    cbKey byte # Size of the BTree Key value, in bytes.
               # This value MUST be set to 2, 4, 8, or 16
    cbEnt byte # Size of the data value, in bytes.
               # This MUST be greater than zero (0)
               # and less than or equal to 32.
    bIdxLevels byte  # Index depth.
    hidRoot    DWORD # This is the HID that points to the BTH entries
        # for this BTHHEADER. The data consists of an array of BTH Records.
        # This value is set to zero (0) if the BTH is empty.
    """
    eng = UnpackDesc(buf)
    eng.unpack2(PC_BTH_HEADER)
    assert eng.pos == len(buf)
    return dict(eng.out)


def dump_heap_on_node(bx, title=None, full_dump=False):
    if full_dump:
        dump_hex(buf)
    hn_header, hn_pagemap = parse_heap_on_node(bx)
    print "\n%s::heap_on_node:" % title, hn_header, hn_pagemap, "\n"
    for pos, lx in hn_pagemap["rgibAlloc"]:
        dump_hex(bx[pos:pos+lx])


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


class PropertyContext:
    # FIXME реализира и част от общата функционалност на BTH
    def __init__(self, nid, _debug=0):
        self.buf = ndb.read_nid(nid)  # read message store description
        self.hn_header, self.hn_pagemap = parse_heap_on_node(self.buf)
        assert self.hn_header["bClientSig"][0] == "bTypePC"
        self._debug = _debug
        if self._debug > 0:
            dump_heap_on_node(self.buf, title="PropertyContext[HND]")
        self._read_props_map()

    def _read_props_map(self):
        hid = get_hid_index(self.hn_header["hidUserRoot"])
        pos, lx = self.hn_pagemap["rgibAlloc"][hid-1]
        self._bth_header = parser_bt_header(self.buf[pos:pos+lx])
        print "self._bth_header:::", self._bth_header

        hid = get_hid_index(self._bth_header["hidRoot"])
        pos, lx = self.hn_pagemap["rgibAlloc"][hid-1]
        b1 = self.buf[pos:pos+lx]
        if self._debug > 1:
            dump_hex(b1)
        PC_BTH = """\
        propTag  WORD
        propType WORD
        value    byte[4]
        """
        eng = UnpackDesc(b1)
        for p in range(lx / 8):
            eng.unpack2(PC_BTH)
            self._props = [dict(eng.out[3*p:3*(p+1)])
                           for p in range(len(eng.out)/3)]
            self._props = dict([(x["propTag"], x)
                                for x in self._props])
        enrich_prop_code(self._props.values())

    def _get_hid_pos_lx(self, px):
        hidIndex = get_hid_index(px["value"])
        assert hidIndex <= 2**11, hidIndex
        # zero based, return pos (buffer position), lx (length)
        return self.hn_pagemap["rgibAlloc"][hidIndex-1]

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
                pos, lx = self._get_hid_pos_lx(px)
                return self.buf[pos:pos+lx]
            else:
                # TODO by NID subnode
                sx = encode("NID::NotImplementedError", "UTF-16LE")
                return memoryview(bytearray(sx))

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


class TableContext:
    # FIXME реализира и част от общата функционалност на BTH
    def __init__(self, nid):
        self.nid = nid
        self.buf = ndb.read_nid(nid)  # read message store description
        self.hn_header, self.hn_pagemap = parse_heap_on_node(self.buf)
        assert self.hn_header["bClientSig"][0] == "bTypeTC"
        dump_heap_on_node(self.buf, title="TableContext[HND]")
        self._read_table_info()
        self._read_row_index()

    def _read_table_info(self):
        hid = get_hid_index(self.hn_header["hidUserRoot"])
        pos, lx = self.hn_pagemap["rgibAlloc"][hid-1]  # zero-based
        b1 = self.buf[pos:pos+lx]
        TC_INFO = """\
        bType       byte # TC signature; MUST be set to bTypeTC (0x7C)
        cCols       byte # Column count.
        rgib        WORD[4] # This is an array of 4 16-bit values that
            # specify the offsets of various groups of data in the actual
            # row data. The application of this array is specified in
            # section 2.3.4.4, which covers the data layout of
            # the Row Matrix.
        hidRowIndex DWORD # HID to the Row ID BTH
        hnidRows    DWORD # HNID to the Row Matrix (actual table data).
            # This value is set to zero (0) if the TC contains no rows.
        hidIndex    DWORD # Deprecated.
        """
        eng = UnpackDesc(b1)
        eng.unpack2(TC_INFO)
        self._info = dict(eng.out)

        TCOL_DESC = """\
        propType WORD # This field specifies that 32-bit tag
                      # that is associated with the column
        propTag  WORD # Tag and type are split
        ibData   WORD # Data Offset.
            # This field indicates the offset from the beginning of the row
            # data (in the Row Matrix) where the data for this column can be
            # retrieved. Because each data row is laid out the same way in
            # the Row Matrix, the Column data for each row can be found at
            # the same offset.
        cbData byte   # Data size.
            # This field specifies the size of the data associated with this
            # column (that is, "width" of the column), in bytes per row.
            # However, in the case of variable-sized data, this value is set
            # to the size of an HNID instead.
        iBit   byte   # Cell Existence Bitmap Index.
            # This value is the 0-based index into the CEB bit that
            # corresponds to this Column.
        """
        eng = UnpackDesc(b1, pos=eng.pos)
        for p in range(self._info["cCols"]):
            eng.unpack2(TCOL_DESC)
        self._col_desc = []
        nmem = 5  # structure members
        for p in range(len(eng.out) / nmem):
            self._col_desc.append(dict(eng.out[nmem*p:nmem*(p+1)]))
        enrich_prop_code(self._col_desc)

    def _read_row_index(self):
        def read_hid_data(hid_id):
            hid = get_hid_index(hid_id)
            pos, lx = self.hn_pagemap["rgibAlloc"][hid-1]
            return self.buf[pos:pos+lx]
        bth_row_index = read_hid_data(self._info["hidRowIndex"])
        bth_row_index = parser_bt_header(bth_row_index)
        print "TableContex:::_read_row_index::bth", bth_row_index
        print "TableContex:::_read_row_index::TC_INFO", self._info
        row_index_buf = read_hid_data(bth_row_index["hidRoot"])
        dump_hex(row_index_buf)
        # TODO read rowIndex and rowId

        data_hnid = self._info["hnidRows"]
        assert get_hnid_type(data_hnid) == "HID"  # FIXME NID or HID
        rows_data = read_hid_data(data_hnid)
        dump_hex(rows_data)
        # TODO read row data


def test_dump_ndb(ndb):
    for bx in ndb._bbt:
        print "bx", bx
        print "="*60, "\nAll blocks dump\n"
        ndb._read_block(bx)
        print "="*60, "\nNBT structure\n"
        pprint(ndb._nbt)


def test_ndb_info(ndb):
    print "="*60, "\nNDB Layer info\n"
    h1 = dict([(a, b) for a, b in ndb._header.iteritems()
               if a in ("ibFileEof", "brefNBT",
                        "brefBBT", "bCryptMethod")])
    print "file name [%s], usable data [%d] bytes\n%s" % (
        fnm, sum(x["cb"] for x in ndb._bbt), h1, )
    print


def test_root_storage(ndb):
    print "="*60, "\nRoot Storage Folders\n"

    def pc_info(pc):
        pprint([("0x%04X %s" % (
            k, pc._props[k]["propCode"]), pc.read_prop(k))
                for k in pc._props])

    pc_root = PropertyContext(0x21)
    pc_info(pc_root)

    root_folder = [pc_root._read_entry_id(props_tags_codes[x])
                   for x in ("IpmSuBTreeEntryId",
                             "IpmWastebasketEntryId",
                             "FinderEntryId")]
    print "\n", "="*60
    # pprint(fc1, width=110)
    for fc in root_folder[:1]:
        nid = fc["nid"]
        nidType = (nid & 0x1F)
        print "nidType:: 0x%08X %d %s" % (
            nid, nidType, nid_types[nidType])
        # dump_hex(ndb.read_nid(nid))
        pc = PropertyContext(nid)
        pc_info(pc)

        tc_nid_types = []
        for ntyp, (code, desc) in nid_types.iteritems():
            if code in ("HIERARCHY_TABLE", "CONTENTS_TABLE",
                        "ASSOC_CONTENTS_TABLE"):
                tc_nid_types.append(ntyp)
        print "tc_nid_types::", tc_nid_types
        for tc_nid_type in tc_nid_types[:1]:
            print "\n", "="*15
            print "nid_type:::", nid_types[tc_nid_type]
            tc_nid = nid & 0xFFFFFFE0 | tc_nid_type
            # buf = ndb.read_nid(tc_nid)
            # dump_heap_on_node(buf)
            tc = TableContext(tc_nid)
            print(tc._info)
            # pprint(tc._col_desc, width=110)


def test_PC_list(ndb):
    def test(pc_nid_type, _debug=0):
        print "="*60, "\n", nid_types[pc_nid_type], "\n"
        for nx in ndb._nbt:
            nid_type = nx["nid"] & 0x1F
            if nid_type != pc_nid_type:
                continue
            if _debug > 0:
                pc = PropertyContext(nx["nid"])
                if _debug > 1:
                    print "="*60, "\n", nx, "\n"
                    pprint([("0x%04X %s" % (
                        k, pc._props[k]["propCode"]), pc.read_prop(k))
                            for k in pc._props])
            else:
                print nx
    test(0x02)  # normal folders
    test(0x05)  # attachments
    test(0x04)  # normal message
    test(0x08)  # assoc message


def test_PC(nid):
    pc = PropertyContext(nid)
    for k, p in pc._props.iteritems():
        value_buf = pc.get_buffer(p['propTag'])
        pv = PropertyValue(p["propType"], value_buf)
        pt_code, pt_size, _, = pv.pt_desc
        ptag = all_props_types.get(p['propTag'], None)
        ptag = ptag and ptag["name"] or p["propCode"]
        try:
            value = pv.get_value()
        except NotImplementedError:
            out = StringIO()
            dump_hex(value_buf, out=out)
            value = out.getvalue().strip()
        print "0x%04X %-10s %4d %6d %-40s" % (
            k, pt_code, pt_size, len(value_buf), ptag, ),
        if value is not None and len(unicode(value)) >= 30:
            print "\n%s\n" % value
        else:
            print "[%s]" % value
    print


def test_PC_dump_type(pc_nid_type):
    def filter(nx):
        nid_type = nx["nid"] & 0x1F
        return nid_type == pc_nid_type

    nx_list = [x for x in ndb._nbt if filter(x)]
    for nx in nx_list[1:]:
        test_PC(nx["nid"])


if __name__ == '__main__':
    from pprint import pprint
    # fnm = u"test"
    fnm = u"Други__backup"
    with gzip.open("%s.pst.gz" % fnm, "rb") as fin:
        header = read_header(fin)
        ndb = NDBLayer(fin, header)
        test_ndb_info(ndb)
        # test_dump_ndb(ndb)
        # test_root_storage(ndb)
        # test_PC_list(ndb)
        test_PC(0x00200024)  # normal message
        # test_PC(0x00008082)  # normal foder
        # test_PC_dump_type(0x02)  # normal folders
        # test_PC_dump_type(0x04)  # normal message
