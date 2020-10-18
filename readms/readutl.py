# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

import re
import os
from struct import unpack_from as unpackb, calcsize


def dump_hex(buf, lx=16, out=None):
    from sys import stdout
    out = out or stdout
    bn = 0
    b1 = []
    for x in buf.tolist():
        if bn % lx == 0:
            out.write("%08X " % bn)
        out.write("%02X " % x)
        if x < 128 and x >= 32:
            b1.append(chr(x))
        else:
            b1.append(".")
        bn += 1
        if bn % lx == 0:
            out.write("".join(b1))
            out.write("\n")
            b1 = []
    if len(b1) > 0:
        out.write(" "*3*(lx-len(b1)))
        out.write("".join(b1))
        out.write("\n")
    out.write("\n")

# 5.1 Permutative Encoding
_mpbbCrypt = [
    71,  241, 180, 230,  11, 106, 114,  72,
    133,  78, 158, 235, 226, 248, 148,  83,
    224, 187, 160,   2, 232,  90,   9, 171,
    219, 227, 186, 198, 124, 195,  16, 221,
    57,    5, 150,  48, 245,  55,  96, 130,
    140, 201,  19,  74, 107,  29, 243, 251,
    143,  38, 151, 202, 145,  23,   1, 196,
    50,   45, 110,  49, 149, 255, 217,  35,
    209,   0,  94, 121, 220,  68,  59,  26,
    40,  197,  97,  87,  32, 144,  61, 131,
    185,  67, 190, 103, 210,  70,  66, 118,
    192, 109,  91, 126, 178,  15,  22,  41,
    60,  169,   3,  84,  13, 218,  93, 223,
    246, 183, 199,  98, 205, 141,   6, 211,
    105,  92, 134, 214,  20, 247, 165, 102,
    117, 172, 177, 233,  69,  33, 112,  12,
    135, 159, 116, 164,  34,  76, 111, 191,
    31,   86, 170,  46, 179, 120,  51,  80,
    176, 163, 146, 188, 207,  25,  28, 167,
    99,  203,  30,  77,  62,  75,  27, 155,
    79,  231, 240, 238, 173,  58, 181,  89,
    4,   234,  64,  85,  37,  81, 229, 122,
    137,  56, 104,  82, 123, 252,  39, 174,
    215, 189, 250,   7, 244, 204, 142,  95,
    239,  53, 156, 132,  43,  21, 213, 119,
    52,   73, 182,  18,  10, 127, 113, 136,
    253, 157,  24,  65, 125, 147, 216,  88,
    44,  206, 254,  36, 175, 222, 184,  54,
    200, 161, 128, 166, 153, 152, 168,  47,
    14,  129, 101, 115, 228, 194, 162, 138,
    212, 225,  17, 208,   8, 139,  42, 242,
    237, 154, 100,  63, 193, 108, 249, 236]


def decode_permute(data):
    out = [_mpbbCrypt[x] for x in data.tolist()]
    out = memoryview(bytearray(out))
    return out


class UnpackDesc:
    def __init__(self, buf, pos=0):
        self.buf = buf
        self.pos = pos
        self.out = []

    @staticmethod
    def struct_map(desc):
        strmap = dict(byte="B", WORD="H", DWORD="L",
                      BID="Q", IB="Q", CB="Q", NID="Q", BREF="2Q")
        patt = re.compile(r"""^(?P<ctype>\w{1,})\s+
                               (?P<stf>\w{1,})
                               (?:\s*[[](?P<sz>\d+)[]]){0,1}
                               (?:\s*[#].*){0,1}$""", re.X)
        patt_sz = re.compile(r"(?P<bsz>\d+){0,1}(?:.*)")
        sd = []
        for s in desc.splitlines():
            g1 = patt.match(s.strip())
            if g1 is None:
                continue
            name, typz, size = g1.groups()
            px = strmap[typz]
            if size is not None:
                cnt = int(size)
                typz = "%d%s" % (cnt, px,)
            else:
                cnt = 1
                typz = px
            bsz = patt_sz.match(px).group("bsz")
            bsz = int(bsz) if bsz is not None else 1
            sd.append((name, typz, bsz * cnt))
        return sd

    @staticmethod
    def struct_model(desc):
        sd = UnpackDesc.struct_map(desc)
        stf = "<%s" % "".join([stz for _, stz, _ in sd])
        return (stf, calcsize(stf),
                tuple([(name, size) for name, _, size in sd]))

    def skip(self, n):
        self.pos += n

    def seek(self, pos):
        self.pos = pos

    def unpack(self, model):
        stf, sz, nx = model
        data = unpackb(stf, self.buf, self.pos)
        data_out = {}
        pos = 0
        for name, size in nx:
            if size == 1:
                data_out[name] = data[pos]
            else:
                data_out[name] = data[pos:pos+size]
            pos += size
        self.out.append(data_out)
        self.pos += sz
        return data_out

    def unpack2(self, desc):
        sd = UnpackDesc.struct_map(desc)
        for nm, stf in [(nm, "<%s" % stz,) for nm, stz, _ in sd]:
            data = unpackb(stf, self.buf, self.pos)
            if len(data) == 1:
                self.out.append((nm, data[0]))
            else:
                self.out.append((nm, data))
            self.pos += calcsize(stf)


def run_profile(fun, *argv, **kwargv):
    from cProfile import Profile
    from pstats import Stats
    prof = Profile()
    prof.enable()
    result = fun(*argv, **kwargv)
    prof.disable()
    stat = Stats(prof).strip_dirs()
    stat = stat.sort_stats("tottime")
    stat.print_stats(20)
    return result


def ulong_from_tuple(value):
    return sum(256**x*y for x, y in zip((0, 1, 2, 3), value))


def uncommpress_rtf(body):
    # [MS-OXRTFCP] http://download.microsoft.com/download/5/D/D/
    # 5DD33FDF-91F5-496D-9884-0A0B0EE698BB/%5BMS-OXRTFCP%5D.pdf
    # http://www.freeutils.net/source/jtnef/rtfcompressed.jsp
    _local_debug = 0
    # header на RtfCompressed 16 bytes
    if _local_debug:
        dump_hex(body[:16])
    cb_rawsize = unpackb("<L", body[4:8])[0]
    if _local_debug > 0:
        cb_size = unpackb("<L", body[0:4])[0]
        dw_magic = unpackb("4c", body[8:12])
        dw_crc = unpackb("<L", body[12:16])[0]
        print("header:", cb_size, cb_rawsize, dw_magic, dw_crc, len(body))
        assert len(body) == cb_size + 4, (len(body), cb_size)

    # инициализация на речника/резултата
    prefix_ = r"".join([r"{\rtf1\ansi\mac\deff0\deftab720{\fonttbl;}",
                        r"{\f0\fnil<SP>\froman<SP>\fswiss<SP>\fmodern<SP>",
                        r"\fscript<SP>\fdecor<SP>MS<SP>Sans<SP>",
                        r"SerifSymbolArialTimes<SP>New<SP>RomanCourier{",
                        r"\colortbl\red0\green0\blue0<CR><LF>\par<SP>",
                        r"\pard\plain\f0\fs20\b\i\u\tab\tx"])
    prefix_ = prefix_.replace("<SP>", chr(0x20))
    prefix_ = prefix_.replace("<CR>", chr(0x0D))
    prefix_ = prefix_.replace("<LF>", chr(0x0A))
    prefix_ = list(prefix_)
    wp = len(prefix_)
    prefix_len = wp
    out = (prefix_len + cb_rawsize) * ["?"]
    out[:prefix_len] = prefix_

    bp, rx_ctrl, rx_run = 16, 0, 0
    while True:
        if rx_run % 8 == 0:
            rx_ctrl = unpackb("<B", body[bp])[0]
            bp += 1
            if _local_debug > 1:
                print(format(rx_ctrl, "08b"))
        if rx_ctrl & 0x1 == 1:
            # референция към речника
            lx = unpackb(">H", body[bp:(bp+2)])[0]
            lx_off = (lx >> 4) & 0xFFF
            lx_len = (lx & 0xF) + 2
            lx_off = wp & 0xFFFFF000 | lx_off
            if lx_off == wp:
                break
            if lx_off >= wp:
                lx_off -= 4096

            ox = out[lx_off:(lx_off+lx_len)]
            if _local_debug > 1:
                print("  1 %8d %2d %8d [ %s ]" % (
                    lx_off, lx_len, wp-prefix_len, "".join(ox)))
            if len(ox) < lx_len:
                print("RTFC: FIXME len(ox) < lx_len:", len(ox), lx_len)
            out[wp:(wp+lx_len)] = ox
            bp += 2
            wp += lx_len
        else:
            # директно копиране
            ox = unpackb("c", body[bp:(bp+1)])[0]
            if _local_debug > 1:
                print("  0 %s %8d [ %c ]" % (11*" ", wp-prefix_len, ox))
            out[wp] = ox
            bp += 1
            wp += 1
        rx_run += 1
        rx_ctrl >>= 1
    return out[prefix_len:]


def test_compressed_rtf(test_fnm):

    def test_file(fnm):
        print("test_file:", fnm, end='')
        fnm_out = os.path.basename(fnm).rsplit(".", 1)
        fnm_out = fnm_out[0]
        fnm_out = os.path.join(os.path.dirname(fnm), "%s.rtf" % fnm_out)
        with open(fnm, "rb") as fin:
            body = memoryview(bytearray(fin.read()))
            out = uncommpress_rtf(body)
            print("len(out):", len(out))
            with open(fnm_out, "wb") as fout:
                fout.write("".join(out))

    if os.path.isdir(test_fnm):
        for fnx in os.listdir(test_fnm):
            if not fnx.endswith(".rtc"):
                continue
            fnx = os.path.join(test_fnm, fnx)
            test_file(fnx)
    else:
        test_file(test_fnm)


if __name__ == '__main__':
    from sys import argv
    test_compressed_rtf(argv[1])
