# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

from readms.readutl import ulong_from_tuple, UnpackDesc

# Описанията са от файла [MS-PST] — v20100627
# Outlook Personal Folders File Format (.pst) Structure Specification
# =========================================================================
# 2.2.2.1 NID (Node ID)
# nidType (5 bits): Identifies the type of the node represented by the NID.
# The following table specifies a list of values for nidType. However,
# it is worth noting that nidType has no meaning to the structures defined
# in the NDB Layer.
_nid_types = """\
0x00 HID Heap node
0x01 INTERNAL Internal node (section 2.4.1)
0x02 NORMAL_FOLDER Normal Folder object (PC)
0x03 SEARCH_FOLDER Search Folder object (PC)
0x04 NORMAL_MESSAGE Normal Message object (PC)
0x05 ATTACHMENT Attachment object (PC)
0x06 SEARCH_UPDATE_QUEUE Queue of changed objects for search Folder objects
0x07 SEARCH_CRITERIA_OBJECT Defines search criteria for a search Folder object
0x08 ASSOC_MESSAGE Folder associated information (FAI) Message object (PC)
0x0A CONTENTS_TABLE_INDEX Internal, persisted view-related
0X0B RECEIVE_FOLDER_TABLE Receive Folder object (Inbox)
0x0C OUTGOING_QUEUE_TABLE Outbound queue (Outbox)
0x0D HIERARCHY_TABLE Hierarchy table (TC)
0x0E CONTENTS_TABLE Contents table (TC)
0x0F ASSOC_CONTENTS_TABLE FAI contents table (TC)
0x10 SEARCH_CONTENTS_TABLE Contents table (TC) of a search Folder object
0x11 ATTACHMENT_TABLE Attachment table (TC)
0x12 RECIPIENT_TABLE Recipient table (TC)
0x13 SEARCH_TABLE_INDEX Internal, persisted view-related
0x1F LTP LTP
"""
nid_types = {}
for _line in _nid_types.splitlines():
    _numh, _desc = _line.split(" ", 1)
    _desc = _desc.split(" ", 1)
    nid_types[int(_numh, 16)] = tuple(_desc)
del _line, _numh, _desc, _nid_types  # pylint: disable=undefined-loop-variable

# 2.4.1 Special Internal NIDs
_nid_internal_types = """\
0x021 MESSAGE_STORE Message store node (section 2.4.3)
0x061 NAME_TO_ID_MAP Named Properties Map (section 2.4.7)
0x0A1 NORMAL_FOLDER_TEMPLATE Template node for an empty Folder
0x0C1 SEARCH_FOLDER_TEMPLATE Template node for an empty search Folder
0x122 ROOT_FOLDER Root Mailbox Folder object of PST
0x1E1 SEARCH_MANAGEMENT_QUEUE Queue of Pending Search-related updates
0x201 SEARCH_ACTIVITY_LIST Folder object NIDs with active Search activity
0x261 SEARCH_DOMAIN_OBJECT List of all Folder referenced by Search Criteria
0x281 SEARCH_GATHERER_QUEUE Search Gatherer Queue
0x2A1 SEARCH_GATHERER_DESCR Search Gatherer Descriptor
0x321 SEARCH_GATHERER_FOLDER_QUEUE Search Gatherer Folder Queue
"""
nid_internal_types = {}
for _line in _nid_internal_types.splitlines():
    _numh, _desc = _line.split(" ", 1)
    _desc = _desc.split(" ", 1)
    nid_internal_types[int(_numh, 16)] = tuple(_desc)
del _line, _numh, _desc, _nid_internal_types  # pylint: disable=undefined-loop-variable

# 2.2.2.7.1 PAGETRAILER, p.29
_page_types = """\
0x80 BBT Block BTree page block / page Signature (section 5.5)
0x81 NBT Node BTree page block / page Signature (section 5.5)
0x82 FMap Free Map page 0x0000
0x83 PMap Allocation Page Map page 0x0000
0x84 AMap Allocation Map page 0x0000
0x85 FPMap Free Page Map page 0x0000
0x86 DL Density List page block / page Signature (section 5.5)
"""
page_types = {}
for _line in _page_types.splitlines():
    _numh, _desc = _line.split(" ", 1)
    _desc = _desc.split(" ", 1)
    page_types[int(_numh, 16)] = tuple(_desc)
del _line, _numh, _desc, _page_types  # pylint: disable=undefined-loop-variable

# Heap Node Client Signatures, see 2.3.1.2 HNHDR, bClientSig, p53
_hn_header_client_sig = """\
0x6C bTypeReserved1 Reserved
0x7C bTypeTC Table Context (TC/HN)
0x8C bTypeReserved2 Reserved
0x9C bTypeReserved3 Reserved
0xA5 bTypeReserved4 Reserved
0xAC bTypeReserved5 Reserved
0xB5 bTypeBTH BTree-on-Heap (BTH)
0xBC bTypePC Property Context (PC/BTH)
0xCC bTypeReserved6 Reserved
"""
hn_header_client_sig = {}
for _line in _hn_header_client_sig.splitlines():
    _numh, _desc = _line.split(" ", 1)
    _desc = _desc.split(" ", 1)
    hn_header_client_sig[int(_numh, 16)] = tuple(_desc)
del _line, _numh, _desc, _hn_header_client_sig  # pylint: disable=undefined-loop-variable

# 2.4.3.1   Minimum Set of Required Properties (Root Storage Folder)
# 2.4.4.1.1 Property Schema of a Folder object PC
# 2.4.4.4.1 Hierarchy Table Template
# 2.4.4.5.1 Contents Table Template
_props_tags = """\
0x0FF9 RecordKey Record Key. This is the Provider UID of this PST.
0x35E0 IpmSuBTreeEntryId EntryID of the Root Mailbox Folder object
0x35E3 IpmWastebasketEntryId EntryID of the Deleted Items Folder object
0x35E7 FinderEntryId EntryID of the search Folder object
0x3001 DisplayNameW Display name of the Folder object
0x3602 ContentCount Total number of items in the Folder object
0x3603 ContentUnreadCount Number of unread items in the Folder object
0x360A Subfolders Whether the Folder object has any sub-Folder objects
0x00E3 ReplItemid Replication Item ID
0x0E33 ReplChangenum Replication Change Number
0x0E34 ReplVersionHistory Replication Version History
0x0E38 ReplFlags Replication flags
0x3613 ContainerClass Container class of the sub-Folder object
0x6635 PstHiddenCount Total number of hidden Items in sub-Folder object
0x6636 PstHiddenUnread Unread hidden items in sub-Folder object
0x67F2 LtpRowId LTP Row ID
0x67F3 LtpRowVer LTP Row Version
0x0017 Importance Importance
0x001A MessageClassW Message class
0x0036 Sensitivity Sensitivity
0x0037 SubjectW Subject
0x0039 ClientSubmitTime Submit timestamp
0x0042 SentRepresentingNameW Sender representative name
0x0057 MessageToMe Whether recipient is in To: line
0x0058 MessageCcMe Whether recipient is in Cc: line
0x0070 ConversationTopicW Conversation topic
0x0071 ConversationIndex Conversation index
0x0E03 DisplayCcW Cc: line
0x0E04 DisplayToW To: line
0x0E06 MessageDeliveryTime Message delivery timestamp
0x0E07 MessageFlags Message flags
0x0E08 MessageSize Message size
0x0E17 MessageStatus Message status
0x0E30 ReplItemid Replication item ID
0x0E3C ReplCopiedfromVersionhistory Replication version information
0x0E3D ReplCopiedfromItemid Replication item ID information
0x1097 ItemTemporaryFlags Temporary flags
0x3008 LastModificationTime Last modification time of Message object
0x65C6 SecureSubmitFlags Secure submit flags
"""
props_tags = {}
for _line in _props_tags.splitlines():
    _numh, _desc = _line.split(" ", 1)
    _desc = _desc.split(" ", 1)
    props_tags[int(_numh, 16)] = tuple(_desc)
del _line, _numh, _desc, _props_tags  # pylint: disable=undefined-loop-variable

props_tags_codes = {}
for tag_, (tcode, tdesc) in props_tags.items():
    props_tags_codes[tcode] = tag_

# [MS-OXCDATA] Data Structures (selected)
_prop_types = """\
0x001F String 0 String of Unicode characters in UTF-16LE
0x0102 Binary 0 COUNT field followed by that many bytes
0x000B Boolean 1 restricted to 1 or 0
0x0002 Integer16 2 16-bit integer
0x0003 Integer32 4 32-bit integer
0x0005 Floating64 8 64-bit floating point number
0x000D Object 0 The property value is a Component Object Model object
0x0040 Time 8 64-bit integer representing the number
              of 100-nanosecond intervals since January 1, 1601
0x0014 Integer64 8 64-bit integer
0x101F PtypMultipleString 0 Multiple String
"""
prop_types = {}
for _line in _prop_types.splitlines():
    if not _line.startswith(" "):
        _numh, _ptyp, _bytes, _desc = _line.split(" ", 3)
        _numh = int(_numh, 16)
        prop_types[_numh] = _ptyp, int(_bytes), _desc
    else:
        _ptyp, _bytes, _desc = prop_types[_numh]
        prop_types[_numh] = _ptyp, _bytes, " ".join((_desc, _line.strip()))
del _line, _numh, _ptyp, _bytes, _desc, _prop_types  # pylint: disable=undefined-loop-variable

# 2.2.2.6 HEADER
_HEADER_1 = """\
dwMagic         byte[4]   # MUST be { 0x21, 0x42, 0x44, 0x4E } ("!BDN")
dwCRCPartial    DWORD
wMagicClient    byte[2]   # MUST be { 0x53, 0x4D }
wVer            WORD      # File format version. This value MUST be
                          # 15 if the file is an ANSI PST file, and MUST be
                          # 23 if the file is a Unicode PST file.
wVerClient      WORD      # Client file format version. The version that
                          # corresponds to the format described in this
                          # document is 19.
bPlatformCreate byte      # This value MUST be set to 0x01
bPlatformAccess byte      # This value MUST be set to 0x01
dwOpenDBID      DWORD
dwOpenClaimID   DWORD
bidUnused       BID       # Unused padding added when the Unicode PST file
                          # format was created
bidNextP        BID       # Next page BID. Pages have a special counter for
                          # allocating bidIndex values. The value of bidIndex
                          # for BIDs for pages is allocated from this counter
# bidNextB      BID       # Next BID. This value is the monotonic counter
#                         # that indicates the BID to be assigned for the
#                         # next allocated block. BID values advance in
#                         # increments of 4. See section 2.2.2.2.
dwUnique        DWORD
gnid            DWORD[32] # A fixed array of 32 NIDs, each corresponding
                          # to one of the 32 possible NID_TYPEs (section
                          # 2.2.2.1). Different NID_TYPEs can have different
                          # starting nidIndex values. Each of these NIDs
                          # indicates the last nidIndex value that had been
                          # allocated for the corresponding NID_TYPE. When a
                          # NID of a particular type is assigned, the
                          # corresponding slot in rgnind is also incremented
                          # by one (1)
qwAlign         byte[8]   # skip
cOrphans        DWORD
ibFileEof       IB        # The size of the PST file, in bytes
ibAMapLast      IB        # An IB structure (section 2.2.2.3) that contains
                          # the absolute file offset to the last AMap page
                          # of the PST file.
ibAMapFree      CB        # The total free space in all AMaps, combined
cbPMapFree      CB        # The total free space in all PMaps, combined.
                          # Because the PMap is deprecated, this value
                          # SHOULD be zero (0).
brefNBT         BREF      # A BREF structure that references the root page
                          # of the Node BTree (NBT)
brefBBT         BREF      # A BREF structure that references the root page
                          # of the Block BTree (BBT)
fAMapValid      byte      # Indicates whether all of the AMaps in this PST file
                          # are valid. For more details, see section
                          # 2.6.1.3.8.  This value MUST be set to one of the
                          # pre-defined values specified in the following
                          # table.
                          # 0x00 One or more AMaps in the PST are INVALID
                          # 0x01 Deprecated. The AMaps are VALID.
                          # 0x02 The AMaps are VALID.
bARVec          byte      # Reserved
cARVec          WORD      # Reserved
"""
_HEADER_2 = """\
bSentinel      byte       # MUST be set to 0x80
bCryptMethod   byte       # Indicates how the data within the PST
                          # file is encoded. MUST be set to one of the
                          # following pre-defined values
                          # 0x00 Data blocks are not encoded
                          # 0x01 Permutation Algorithm (section 5.1)
                          # 0x02 Cyclic Algorithm (section 5.2)
bReserved      byte[2]    # Reserved; MUST be set to zero (0)
bidNextB       BID        # Indicates the next available BID value
dwCRCFull      DWORD
rgbVersion     byte[3]
bLockSemaphore byte
rgbLock        byte[32]
"""
HEADER_1 = UnpackDesc.struct_model(_HEADER_1)
HEADER_2 = UnpackDesc.struct_model(_HEADER_2)

# 2.2.2.7.1 PAGETRAILER
_PAGE_TRAILER = """\
ptype         byte
ptypeRepeat   byte  # MUST be set to the same value as ptype
wSig          WORD  # Page signature. This value depends on the
                    # value of the ptype field. This value is zero (0x0000)
                    # for AMap, PMap, FMap, and FPMap pages.  For BBT, NBT,
                    # and DList pages, a page / block signature is computed
                    # (see section 5.5).
dwCRC         DWORD
bid           BID   # The BID of the page's block
"""
# 2.2.2.7.7.1 BTPAGE
_BT_PAGE = """\
cEnt     byte   # The number of BTree entries stored in the page data
cEntMax  byte   # The maximum number of entries that can fit inside
                # the page data
cbEnt    byte   # The size of each BTree entry, in bytes.
                # Note that in some cases, cbEnt can be greater than the
                # corresponding size of the corresponding rgentries
                # structure because of alignment or other considerations.
                # Implementations MUST use the size specified in cbEnt to
                # advance to the next entry.
cLevel   byte   # The depth level of this page.
                # Leaf pages have a level of 0, whereas intermediate pages
                # have a level greater than 0.  This value determines the
                # type of the entries in rgentries, and is interpreted as
                # unsigned.
"""
# 2.2.2.7.7.2 BTENTRY (Intermediate Entries)
# BT_ENTRY records contain a key value (NID or BID) and a reference
# to a child BTPAGE page in the BTree
_BT_ENTRY = """\
btkey BID   # The key value associated with this BTENTRY.
            # All the entries in the child BTPAGE referenced by BREF have
            # key values greater than or equal to this key value. The btkey
            # is either a NID (zero extended to 8 bytes for Unicode PSTs) or
            # a BID, depending on the ptype of the page.
bref  BREF  # BREF (section 2.2.2.4) that points to the child BTPAGE.
            # contains {BID, IB (file position)}
"""
# 2.2.2.7.7.3 BBTENTRY (Leaf BBT Entry)
# BBT_ENTRY records contain information about blocks and are found
# in BT_PAGES with cLevel equal to 0, with the ptype of ptypeBBT.
# These are the leaf entries of the BBT.
_BBT_ENTRY = """\
bref BREF # BREF structure (section 2.2.2.4) that contains the BID
          # and IB of the block that the BBTENTRY references.
cb   WORD # The count of bytes of the raw data contained in the
          # block referenced by BREF excluding the block trailer and
          # alignment padding, if any.
cRef WORD # Reference count indicating the count of references to
          # this block. See section 2.2.2.7.7.3.1 regarding how
          # reference counts work.
"""
# 2.2.2.7.7.4 NBTENTRY (Leaf NBT Entry)
# NBTENTRY records contain information about nodes and are found in
# BTPAGES with cLevel equal to 0, with the ptype of ptypeNBT. These
# are the leaf entries of the NBT.
_NBT_ENTRY = """\
nid         NID   # The NID (section 2.2.2.1) of the entry.
                  # Note that the NID is a 4-byte value for both Unicode and
                  # ANSI formats. However, to stay consistent with the size
                  # of the btkey member in BTENTRY, the 4-byte NID is
                  # extended to its 8-byte equivalent for Unicode PST files.
bidData     BID   # The BID of the data block for this node
bidSub      BID   # The BID of the subnode block for this node.
                  # If this value is zero (0), then a subnode block does not
                  # exist for this node
nidParent   DWORD # If this node represents a child of a Folder object
                  # defined in the Messaging Layer, then this value is
                  # nonzero and contains the NID of the parent Folder
                  # object's node.  Otherwise, this value is zero (0). See
                  # section 2.2.2.7.7.4.1 for more information. This field
                  # is not interpreted by any structure defined at the NDB
                  # Layer.
"""
PAGE_TRAILER = UnpackDesc.struct_model(_PAGE_TRAILER)
BT_PAGE = UnpackDesc.struct_model(_BT_PAGE)
BT_ENTRY = UnpackDesc.struct_model(_BT_ENTRY)
BBT_ENTRY = UnpackDesc.struct_model(_BBT_ENTRY)
NBT_ENTRY = UnpackDesc.struct_model(_NBT_ENTRY)

# 2.2.2.8.1 BLOCKTRAILER
_BLOCK_TRAILER = """\
cb    WORD  # The amount of data, in bytes, contained within
            # the data section of the block.  This value does not include
            # the block trailer or any unused bytes that can exist after
            # the end of the data and before the start of the block trailer.
wSig  WORD  # Block signature (calculated)
dwCRC DWORD # 32-bit CRC of the cb bytes (calculated)
bid   BID   # The BID (section 2.2.2.2) of the data block
"""
# 2.2.2.8.3 Block Types
_BLOCK_SIGNATURE = """\
btype  byte # Block type
            # 0x01 to indicate an XBLOCK or XXBLOCK.
            # 0x02 to indicate an SLBLOCK or SIBLOCK
cLevel byte # Block subtype
            # 0x01 XBLOCK, 0x02 XXBLOCK
            # 0x00 SLBLOCK, 0x01 SIBLOCK
cEnt   WORD # The number of entries, depends on type
"""
# 2.2.2.8.3.3.1.1 SLENTRY (Leaf Block Entry)
_SL_ENTRY = """\
nid    NID # Local NID of the child subnode.
           # This NID is guaranteed to be unique only within the parent
           # node.
bid    BID # The BID of the data block associated
           # with the child subnode.
bidSub BID # The BID of the child subnode of this child subnode.
"""
BLOCK_TRAILER = UnpackDesc.struct_model(_BLOCK_TRAILER)
BLOCK_SIGNATURE = UnpackDesc.struct_model(_BLOCK_SIGNATURE)
SL_ENTRY = UnpackDesc.struct_model(_SL_ENTRY)

# 2.3.1.2 HNHDR
_HN_HDR = """\
ibHnpm       WORD    # The byte offset to the HN page Map record
                     # section 2.3.1.5), with respect to the beginning
                     # of the HNHDR structure
bSig         byte    # Block signature;
                     # MUST be set to 0xEC to indicate a HN
bClientSig   byte    # Client signature.
                     # This value describes the higher-level structure that
                     # is implemented on top of the HN. This value is
                     # intended as a hint for a higher-level structure and
                     # has no meaning for structures defined at the HN
                     # level.  The following values are pre-defined for
                     # bClientSig.  All other values not described in the
                     # following table are reserved and MUST NOT be assigned
                     # or used. See hn_header_client_sig.
hidUserRoot  DWORD   # HID that points to the User Root record.
rgbFillLevel byte[4] # Per-block Fill Level Map.
                     # This array consists of eight 4-bit values that
                     # indicate the fill level for each of the first 8 data
                     # blocks (including this header block).
"""
# 2.3.1.5 HNPAGEMAP
_HN_PAGE_MAP = """\
cAlloc WORD # Allocation count
cFree  WORD # Free count
"""
# 2.3.2.1 BTHHEADER
_BTH_HEADER = """\
bType byte       # MUST be bTypeBTH (0xB5)
cbKey byte       # Size of the BTree Key value, in bytes.
                 # This value MUST be set to 2, 4, 8, or 16
cbEnt byte       # Size of the data value, in bytes.
                 # This MUST be greater than zero (0) and less than or equal
                 # to 32.
bIdxLevels byte  # Index depth.
hidRoot    DWORD # This is the HID that points to the BTH entries
                 # for this BTHHEADER. The data consists of an array of BTH
                 # Records.  This value is set to zero (0) if the BTH is
                 # empty.
"""
HN_HDR = UnpackDesc.struct_model(_HN_HDR)
HN_PAGE_MAP = UnpackDesc.struct_model(_HN_PAGE_MAP)
BTH_HEADER = UnpackDesc.struct_model(_BTH_HEADER)

# 2.3.3.3 PC BTH Record
_PC_BTH_RECORD = """\
propTag  WORD     # Property ID, as specified in [MS-OXCDATA] section 2.10.
                  # This is the upper 16 bits of the property tag value.
                  # This is a manifestation of the BTH record (section
                  # 2.3.2.3) and constitutes the key of this record.
propType WORD     # Property type.
                  # This is the lower 16 bits of the property tag value,
                  # which identifies the type of data that is associated
                  # with the property. The complete list of property type
                  # values and their data sizes are specified in
                  # [MS-OXCDATA] section 2.12.1.
value    byte[4]  # Depending on the data size of the property type
                  # indicated by wPropType and a few other factors, this
                  # field represents different values.
                  # (Variable Size, Fixed Size, NID Type, value)
                  # N | <=4 bytes | NA  | data value
                  # N | > 4 bytes | HID | HID
                  # Y | NA        | HID | HID <=3580 bytes
                  # Y | NA        | NID | NID subnode, >3580 bytes
"""
PC_BTH_RECORD = UnpackDesc.struct_model(_PC_BTH_RECORD)

# https://msdn.microsoft.com/en-us/library/office/ff860730.aspx
_CODE_PAGES_INTERNET_MAP = """\
1250    windows-1250
1251    windows-1251
1252    Windows-1252
1253    windows-1253
1254    windows-1254
1255    windows-1255
1256    windows-1256
1257    windows-1257
1258    windows-1258
20127   us-ascii
20866   koi8-r
21866   koi8-u
28591   iso-8859-1
28592   iso-8859-2
28593   iso-8859-3
28594   iso-8859-4
28595   iso-8859-5
28596   iso-8859-6
28597   iso-8859-7
28599   iso-8859-9
28605   iso-8859-15
38598   iso-8859-8-i
50220   iso-2022-jp
50221   csISO2022JP
51932   euc-jp
51949   euc-kr
52936   hz-gb-2312
65000   utf-7
65001   utf-8
874     windows-874
932     iso-2022-jp
936     gb2312
949     ks_c_5601-1987
950     big5
"""
_code_pages_internet_map = {}
for _line in _CODE_PAGES_INTERNET_MAP.splitlines():
    _numh, _, _desc = _line.split(" ", 2)
    _numh = int(_numh)
    _code_pages_internet_map[_numh] = _desc.strip()
del _line, _numh, _desc, _CODE_PAGES_INTERNET_MAP  # pylint: disable=undefined-loop-variable


def get_internet_code_page(ms_code_page):
    return _code_pages_internet_map.get(ms_code_page, None)


def enrich_prop_code(props):
    for prop in props:
        tag = prop["propTag"]
        tag_info = all_props_types.get(tag, None)
        tag_code = tag_info["name"] if tag_info is not None else "0x%04X" % tag
        prop["propCode"] = tag_code


def get_hid_index(value):
    if isinstance(value, (int,)):
        hid = value
    else:
        hid = ulong_from_tuple(value)
    assert hid & 0x1F == 0
    return hid >> 5


def get_hnid_type(hnid):
    """An HNID is a 32-bit hybrid value that represents either a HID or a
    NID. The determination is made by examining the hidType (or
    equivalently, nidType) value. The HNID refers to a HID if the hidType
    is NID_TYPE_HID. Otherwise, the HNID refers to a NID.
    See Section 2.3.3.2.
    """
    return "HID" if hnid & 0x1F == 0 else "NID"


def parse_ms_oxprops(_silent=False):
    from pkgutil import get_data

    def read_events():
        in_range, in_cont = False, False
        next_id = 1
        resource_fnm = "papers/MS-OXPROPS.txt"
        try:
            data = get_data("readms.metapst", resource_fnm).decode('cp1251')
        except IOError:
            yield "END", "Missing %s" % resource_fnm
            return

        if data is not None:
            for _line in data.splitlines():
                _line = _line.strip()
                if len(_line) == 0:
                    if in_cont:
                        in_cont = False
                        # pylint: disable=used-before-assignment
                        # логиката установява in_cont на True, за да покаже
                        # че променливите att и desc са установени
                        yield "DESC", (att, desc, )
                        continue
                if _line == "2 Structures":
                    in_range = True
                    yield "START", None
                if _line == "3 Structure Examples":
                    break
                if not in_range:
                    continue
                if _line.startswith("2.%d " % next_id):
                    _, name = _line.split(" ", 1)
                    yield "PROP", (name, )
                    next_id += 1
                px = _line.find(":")
                if px >= 0:
                    att, desc = _line[:px].strip(), _line[(px+1):].strip()
                    in_cont = True
                else:
                    if in_cont:
                        desc = " ".join((desc, _line))
            yield "END", "Successfuly loaded %s" % resource_fnm

    parsed_prop_types = []
    result = {}
    for etag, info in read_events():
        if etag == "PROP":
            name, = info
            prop = dict(name=name.replace("PidTag", ""))
            parsed_prop_types.append(prop)
        if etag == "DESC":
            att, desc = info
            prop[att] = desc
        if etag == "END":
            def append_desc(id_name):
                dx = {int(x[id_name], 16): x for x in parsed_prop_types if id_name in x}
                result.update(dx)
                if not _silent:
                    print("%5d hashed by %s" % (len(dx), id_name))
            if not _silent:
                print(info)
                print("%5d properties found" % len(parsed_prop_types))
            id_names = ("Property long ID (LID)", "Property ID")
            for id_name in id_names:
                append_desc(id_name)
            if not _silent:
                lost = [x["name"] for x in parsed_prop_types
                        if all([(z not in x) for z in id_names])]
                print("%5d lost for no ID defined" % len(lost))
    return result

all_props_types = parse_ms_oxprops(_silent=False)

if __name__ == '__main__':
    from pprint import pprint
    # pt = parse_ms_oxprops()
    # pprint(pt.values()[:5])
    # pprint(nid_internal_types)
    pprint(_code_pages_internet_map)
