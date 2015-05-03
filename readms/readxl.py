# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

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
# ==========================================================================
# Описанията за BIFF на Excel са изведени от
# http://www.digitalpreservation.gov/formats/digformatspecs/Excel97-2007BinaryFileFormat(xls)Specification.pdf
# В описанието от OpenOffice липсва описания за коментарите по клетките.
# ==========================================================================

from readutl import dump_hex
from struct import unpack, unpack_from as unpackb
from codecs import decode
import re

# BIFF Records Names, p.28-33
_biff_rec_names = """\
0x000A EOF: End of File
0x000C CALCCOUNT: Iteration Count
0x000D CALCMODE: Calculation Mode
0x000E PRECISION: Precision
0x000F REFMODE: Reference Mode
0x0010 DELTA: Iteration Increment
0x0011 ITERATION: Iteration Mode
0x0012 PROTECT: Protection Flag
0x0013 PASSWORD: Protection Password
0x0014 HEADER: Print Header on Each Page
0x0015 FOOTER: Print Footer on Each Page
0x0016 EXTERNCOUNT: Number of External References
0x0017 EXTERNSHEET: External Reference
0x0019 WINDOWPROTECT: Windows Are Protected
0x001A VERTICALPAGEBREAKS: Explicit Column Page Breaks
0x001B HORIZONTALPAGEBREAKS: Explicit Row Page Breaks
0x001C NOTE: Comment Associated with a Cell
0x001D SELECTION: Current Selection
0x0022 1904: 1904 Date System
0x0026 LEFTMARGIN: Left Margin Measurement
0x0027 RIGHTMARGIN: Right Margin Measurement
0x0028 TOPMARGIN: Top Margin Measurement
0x0029 BOTTOMMARGIN: Bottom Margin Measurement
0x002A PRINTHEADERS: Print Row/Column Labels
0x002B PRINTGRIDLINES: Print Gridlines Flag
0x002F FILEPASS: File Is Password-Protected
0x003C CONTINUE: Continues Long Records
0x003D WINDOW1: Window Information
0x0040 BACKUP: Save Backup Version of the File
0x0041 PANE: Number of Panes and Their Position
0x0042 CODENAME: VBE Object Name
0x0042 CODEPAGE: Default Code Page
0x004D PLS: Environment-Specific Print Record
0x0050 DCON: Data Consolidation Information
0x0051 DCONREF: Data Consolidation References
0x0052 DCONNAME: Data Consolidation Named References
0x0055 DEFCOLWIDTH: Default Width for Columns
0x0059 XCT: CRN Record Count
0x005A CRN: Nonresident Operands
0x005B FILESHARING: File-Sharing Information
0x005C WRITEACCESS: Write Access User Name
0x005D OBJ: Describes a Graphic Object
0x005E UNCALCED: Recalculation Status
0x005F SAVERECALC: Recalculate Before Save
0x0060 TEMPLATE: Workbook Is a Template
0x0063 OBJPROTECT: Objects Are Protected
0x007D COLINFO: Column Formatting Information
0x007E RK: Cell Value, RK Number
0x007F IMDATA: Image Data
0x0080 GUTS: Size of Row and Column Gutters
0x0081 WSBOOL: Additional Workspace Information
0x0082 GRIDSET: State Change of Gridlines Option
0x0083 HCENTER: Center Between Horizontal Margins
0x0084 VCENTER: Center Between Vertical Margins
0x0085 BOUNDSHEET: Sheet Information
0x0086 WRITEPROT: Workbook Is Write-Protected
0x0087 ADDIN: Workbook Is an Add-in Macro
0x0088 EDG: Edition Globals
0x0089 PUB: Publisher
0x008C COUNTRY: Default Country and WIN.INI Country
0x008D HIDEOBJ: Object Display Options
0x0090 SORT: Sorting Options
0x0091 SUB: Subscriber
0x0092 PALETTE: Color Palette Definition
0x0094 LHRECORD: .WK? File Conversion Information
0x0095 LHNGRAPH: Named Graph Information
0x0096 SOUND: Sound Note
0x0098 LPR: Sheet Was Printed Using LINE.PRINT(
0x0099 STANDARDWIDTH: Standard Column Width
0x009A FNGROUPNAME: Function Group Name
0x009B FILTERMODE: Sheet Contains Filtered List
0x009C FNGROUPCOUNT: Built-in Function Group Count
0x009D AUTOFILTERINFO: Drop-Down Arrow Count
0x009E AUTOFILTER: AutoFilter Data
0x00A0 SCL: Window Zoom Magnification
0x00A1 SETUP: Page Setup
0x00A9 COORDLIST: Polygon Object Vertex Coordinates
0x00AB GCW: Global Column-Width Flags
0x00AE SCENMAN: Scenario Output Data
0x00AF SCENARIO: Scenario Data
0x00B0 SXVIEW: View Definition
0x00B1 SXVD: View Fields
0x00B2 SXVI: View Item
0x00B4 SXIVD: Row/Column Field IDs
0x00B5 SXLI: Line Item Array
0x00B6 SXPI: Page Item
0x00B8 DOCROUTE: Routing Slip Information
0x00B9 RECIPNAME: Recipient Name
0x00BC SHRFMLA: Shared Formula
0x00BD MULRK: Multiple RK Cells
0x00BE MULBLANK: Multiple Blank Cells
0x00C1 MMS: ADDMENU/DELMENU Record Group Count
0x00C2 ADDMENU: Menu Addition
0x00C3 DELMENU: Menu Deletion
0x00C5 SXDI: Data Item
0x00C6 SXDB: PivotTable Cache Data
0x00CD SXSTRING: String
0x00D0 SXTBL: Multiple Consolidation Source Info
0x00D1 SXTBRGIITM: Page Item Name Count
0x00D2 SXTBPG: Page Item Indexes
0x00D3 OBPROJ: Visual Basic Project
0x00D5 SXIDSTM: Stream ID
0x00D6 RSTRING: Cell with Character Formatting
0x00D7 DBCELL: Stream Offsets
0x00DA BOOKBOOL: Workbook Option Flag
0x00DC PARAMQRY: Query Parameters
0x00DC SXEXT: External Source Information
0x00DD SCENPROTECT: Scenario Protection
0x00DE OLESIZE: Size of OLE Object
0x00DF UDDESC: Description String for Chart Autoformat
0x00E0 XF: Extended Format
0x00E1 INTERFACEHDR: Beginning of User Interface Records
0x00E2 INTERFACEEND: End of User Interface Records
0x00E3 SXVS: View Source
0x00E5 MERGECELLS: Merged Cells
0x00EA TABIDCONF: Sheet Tab ID of Conflict History
0x00EB MSODRAWINGGROUP: Microsoft Office Drawing Group
0x00EC MSODRAWING: Microsoft Office Drawing
0x00ED MSODRAWINGSELECTION: Microsoft Office Drawing Selection
0x00F0 SXRULE: PivotTable Rule Data
0x00F1 SXEX: PivotTable View Extended Information
0x00F2 SXFILT: PivotTable Rule Filter
0x00F4 SXDXF: Pivot Table Formatting
0x00F5 SXITM: Pivot Table Item Indexes
0x00F6 SXNAME: PivotTable Name
0x00F7 SXSELECT: PivotTable Selection Information
0x00F8 SXPAIR: PivotTable Name Pair
0x00F9 SXFMLA: Pivot Table Parsed Expression
0x00FB SXFORMAT: PivotTable Format Record
0x00FC SST: Shared String Table
0x00FD LABELSST: Cell Value, String Constant/SST
0x00FF EXTSST: Extended Shared String Table
0x0100 SXVDEX: Extended PivotTable View Fields
0x0103 SXFORMULA: PivotTable Formula Record
0x0122 SXDBEX: PivotTable Cache Data
0x013D TABID: Sheet Tab Index Array
0x0160 USESELFS: Natural Language Formulas Flag
0x0161 DSF: Double Stream File
0x0162 XL5MODIFY: Flag for DSF
0x01A5 FILESHARING2: File-Sharing Information for Shared Lists
0x01A9 USERBVIEW: Workbook Custom View Settings
0x01AA USERSVIEWBEGIN: Custom View Settings
0x01AB USERSVIEWEND: End of Custom View Records
0x01AD QSI: External Data Range
0x01AE SUPBOOK: Supporting Workbook
0x01AF PROT4REV: Shared Workbook Protection Flag
0x01B0 CONDFMT: Conditional Formatting Range Information
0x01B1 CF: Conditional Formatting Conditions
0x01B2 DVAL: Data Validation Information
0x01B5 DCONBIN: Data Consolidation Information
0x01B6 TXO: Text Object
0x01B7 REFRESHALL: Refresh Flag
0x01B8 HLINK: Hyperlink
0x01BB SXFDBTYPE: SQL Datatype Identifier
0x01BC PROT4REVPASS: Shared Workbook Protection Password
0x01BE DV: Data Validation Criteria
0x01C0 EXCEL9FILE: Excel 9 File
0x01C1 RECALCID: Recalc Information
0x0200 DIMENSIONS: Cell Table Size
0x0201 BLANK: Cell Value, Blank Cell
0x0203 NUMBER: Cell Value, Floating-Point Number
0x0204 LABEL: Cell Value, String Constant
0x0205 BOOLERR: Cell Value, Boolean or Error
0x0207 STRING: String Value of a Formula
0x0208 ROW: Describes a Row
0x020B INDEX: Index Record
0x0218 NAME: Defined Name
0x0221 ARRAY: Array-Entered Formula
0x0223 EXTERNNAME: Externally Referenced Name
0x0225 DEFAULTROWHEIGHT: Default Row Height
0x0231 FONT: Font Description
0x0236 TABLE: Data Table
0x023E WINDOW2: Sheet Window Information
0x0293 STYLE: Style Information
0x0406 FORMULA: Cell Formula
0x041E FORMAT: Number Format
0x0800 HLINKTOOLTIP: Hyperlink Tooltip
0x0801 WEBPUB: Web Publish Item
0x0802 QSISXTAG: PivotTable and Query Table Extensions
0x0803 DBQUERYEXT: Database Query Extensions
0x0804 EXTSTRING: FRT String
0x0805 TXTQUERY: Text Query Information
0x0806 QSIR: Query Table Formatting
0x0807 QSIF: Query Table Field Formatting
0x0809 BOF: Beginning of File
0x080A OLEDBCONN: OLE Database Connection
0x080B WOPT: Web Options
0x080C SXVIEWEX: Pivot Table OLAP Extensions
0x080D SXTH: PivotTable OLAP Hierarchy
0x080E SXPIEX: OLAP Page Item Extensions
0x080F SXVDTEX: View Dimension OLAP Extensions
0x0810 SXVIEWEX9: Pivot Table Extensions
0x0812 CONTINUEFRT: Continued FRT
0x0813 REALTIMEDATA: Real-Time Data (RTD)
0x0862 SHEETEXT: Extra Sheet Info
0x0863 BOOKEXT: Extra Book Info
0x0864 SXADDL: Pivot Table Additional Info
0x0865 CRASHRECERR: Crash Recovery Error
0x0866 HFPicture: Header / Footer Picture
0x0867 FEATHEADR: Shared Feature Header
0x0868 FEAT: Shared Feature Record
0x086A DATALABEXT: Chart Data Label Extension
0x086B DATALABEXTCONTENTS: Chart Data Label Extension Contents
0x086C CELLWATCH: Cell Watch
0x086d FEATINFO: Shared Feature Info Record
0x0871 FEATHEADR11: Shared Feature Header 11
0x0872 FEAT11: Shared Feature 11 Record
0x0873 FEATINFO11: Shared Feature Info 11 Record
0x0874 DROPDOWNOBJIDS: Drop Down Object
0x0875 CONTINUEFRT11: Continue FRT 11
0x0876 DCONN: Data Connection
0x0892 STYLEEXT: Named Cell Style Extension
0x0893 NAMEPUBLISH: Publish To Excel Server Data for Name
0x0894 NAMECMT: Name Comment
0x0895 SORTDATA12: Sort Data 12
0x0896 THEME: Theme
0x0897 GUIDTYPELIB: VB Project Typelib GUID
0x0898 FNGRP12: Function Group
0x0899 NAMEFNGRP12: Extra Function Group
0x089A MTRSETTINGS: Multi-Threaded Calculation Settings
0x089B COMPRESSPICTURES: Automatic Picture Compression Mode
0x089C HEADERFOOTER: Header Footer
0x08A3 FORCEFULLCALCULATION: Force Full Calculation Settings
0x08C1 LISTOBJ: List Object
0x08C2 LISTFIELD: List Field
0x08C3 LISTDV: List Data Validation
0x08C4 LISTCONDFMT: List Conditional Formatting
0x08C5 LISTCF: List Cell Formatting
0x08C6 FMQRY: Filemaker queries
0x08C7 FMSQRY: File maker queries
0x08C8 PLV: Page Layout View in Mac Excel 11
0x08C9 LNEXT: Extension information for borders in Mac Office 11
0x08CA MKREXT: Extension information for markers in Mac Office 11
0x08CB CRTCOOPT: Color options for Chart series in Mac Office 11
"""
biff_rec_names = {}
for _buff in _biff_rec_names.splitlines():
    _numh, _name = _buff.split(" ", 1)
    _name = _name.split(": ", 1)
    biff_rec_names[int(_numh, 16)] = tuple(_name)
del _buff, _name, _biff_rec_names


def biff_rec_name(rtag):
    return biff_rec_names.get(rtag, ("UNKNOWN", "TAG:%04X" % rtag),)


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
        assert(magic == (0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1))
        assert(endian == (0xFE, 0xFF))  # little-endian
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
        from StringIO import StringIO
        out = StringIO()
        print >>out, "<%s instance at 0x%08X>" % (
            self.__class__, id(self))
        print >>out, "  long-sector-size: %6d" % self._lssize
        print >>out, "  short-sector-size:%6d" % self._sssize
        print >>out, "  short-max-size:   %6d" % self._max_ssize
        print >>out, "  DIR first SecID:  %6d" % self._dirs_fsid
        print >>out, "  SSAT first SecID: %6d" % self._ssat_fsid
        print >>out, "  MSAT first SecID: %6d" % self._msat_fsid
        print >>out, "  MSAT list: %s" % (self._msat_list,)
        print >>out, "  SAT  list: %s" % (self._sat_list,)
        print >>out, "  SSAT list: %s" % (self._ssat_list,)
        for de in self._dire:
            print >>out, de
        return out.getvalue()

    def _read_ss(self, dire):
        if not isinstance(dire, OLE.DIRE):
            assert(dire <= len(self._dire))
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
            assert(dire <= len(self._dire) or root)
            dire = self._dire[dire]
        assert(dire._size >= self._max_ssize or root)
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
            from StringIO import StringIO
            out = StringIO()
            print >>out, "<%s instance at 0x%08X>" % (
                self.__class__, id(self))
            print >>out, "  type: %02X" % self._type
            print >>out, "  name: %s" % self._name
            print >>out, "  fsid: %6d" % self._fsid
            print >>out, "  size: %6d" % self._size
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
            rtag, size = unpackb("<hh", buf, pos)
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


def test1(cx=0):
    def test_read(ole, stream_name, maxlen=200):
        dire = ole.find_dire(stream_name)
        obuf = ole.read_dire(dire)
        print "%s, len=%d" % (stream_name, len(obuf))
        dump_hex(obuf[:maxlen])

    with OLE(test_file(cx)) as ole:
        print ole
        print dir(ole)
        test_read(ole, "Workbook")
        test_read(ole, ".DocumentSummaryInformation")
        test_read(ole, ".SummaryInformation")
        test_read(ole, ".CompObj")
        test_read(ole, ".Ole")


def test2(cx=1, _debug=False):
    fnm = test_file(cx)
    for (rtag, buf,) in read_workbook(fnm):
        if _debug:
            print "%4d %s" % (len(buf), rtag,)
            if len(buf) > 0:
                dump_hex(buf)


if __name__ == '__main__':
    test1()
    # test2(0, _debug=True)
