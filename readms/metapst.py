# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

from readutl import ulong_from_tuple

# Описанията са от файла [MS-PST] — v20100627
# Outlook Personal Folders File Format (.pst) Structure Specification
# =========================================================================
# 2.2.2.1 NID (Node ID)
# nidType (5 bits): Identifies the type of the node represented by the NID.
# The # following table specifies a list of values for nidType. However,
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
del _line, _numh, _desc, _nid_types

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
del _line, _numh, _desc, _page_types

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
del _line, _numh, _desc, _hn_header_client_sig

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
del _line, _numh, _desc, _props_tags

props_tags_codes = {}
for tag, (tcode, tdesc) in props_tags.iteritems():
    props_tags_codes[tcode] = tag

# [MS-OXCDATA] Data Structures (selected)
_prop_types = """\
0x001F String 0 String of Unicode characters in UTF-16LE
0x0102 Binary 0 COUNT field followed by that many bytes
0x000B Boolean 1 restricted to 1 or 0
0x0003 Integer32 4 32-bit integer
0x0040 Time 8 64-bit integer representing the number
              of 100-nanosecond intervals since January 1, 1601
0x0014 Integer64 8 64-bit integer
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
del _line, _numh, _ptyp, _bytes, _desc, _prop_types


def enrich_prop_code(props):
    for prop in props:
        tag = prop["propTag"]
        tag_info = props_tags.get(tag, None)
        tag_code = tag_info is not None and tag_info[0] or "0x%04X" % tag
        prop["propCode"] = tag_code


def get_hid_index(value):
    if isinstance(value, (int, long)):
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
    return hnid & 0x1F == 0 and "HID" or "NID"


def parse_ms_oxprops(fnm=None, _silent=False):
    from pkgutil import get_data

    def read_events():
        in_range, in_cont = False, False
        next_id = 1
        resource_fnm = "papers/MS-OXPROPS.txt"
        try:
            data = get_data("readms.metapst", resource_fnm)
        except IOError:
            yield "END", "Missing %s" % resource_fnm
            return

        if data is not None:
            for _line in data.splitlines():
                _line = _line.strip()
                if len(_line) == 0:
                    if in_cont:
                        in_cont = False
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
                    # if next_id + 1 > 10:
                    #     break
                    num, name = _line.split(" ", 1)
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

    prop_types = []
    for etag, info in read_events():
        if etag == "PROP":
            name, = info
            prop = dict(name=name.replace("PidTag", ""))
            prop_types.append(prop)
        if etag == "DESC":
            att, desc = info
            prop[att] = desc
        if etag == "END":
            def append_desc(id_name):
                dx = dict([(int(x[id_name], 16), x)
                           for x in prop_types if id_name in x])
                result.update(dx)
                if not _silent:
                    print "%5d hashed by %s" % (len(dx), id_name)
            result = {}
            if not _silent:
                print info
                print "%5d properties found" % len(prop_types)
            id_names = ("Property long ID (LID)", "Property ID")
            for id_name in id_names:
                append_desc(id_name)
            if not _silent:
                lost = [x["name"] for x in prop_types
                        if all([(z not in x) for z in id_names])]
                print "%5d lost for no ID defined" % len(lost)
    return result

all_props_types = parse_ms_oxprops(_silent=False)

if __name__ == '__main__':
    from pprint import pprint
    # pt = parse_ms_oxprops()
    # pprint(pt.values()[:5])
