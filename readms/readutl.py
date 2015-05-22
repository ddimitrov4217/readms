# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

import re
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

    @classmethod
    def struct_map(clazz, desc):
        strmap = dict(byte="B", WORD="H", DWORD="L",
                      BID="Q", IB="Q", CB="Q", NID="Q", BREF="2Q")
        patt = re.compile(r"""^(?P<ctype>\w{1,})\s+
                               (?P<stf>\w{1,})
                               (?:\s*[[](?P<sz>\d+)[]]){0,1}
                               (?:\s*[#].*){0,1}$""", re.X)
        sd = []
        for s in desc.splitlines():
            g1 = patt.match(s.strip())
            if g1 is None:
                continue
            name, typz, size = g1.groups()
            if size is not None:
                typz = "%d%s" % (int(size), strmap[typz],)
            else:
                typz = strmap[typz]
            sd.append((name, typz,))
        return sd

    def skip(self, n):
        self.pos += n

    def seek(self, pos):
        self.pos = pos

    def unpack1(self, desc):
        sd = UnpackDesc.struct_map(desc)
        stf = "<%s" % "".join([stz for name, stz in sd])
        self.out.extend(zip([name for name, stz in sd],
                            unpackb(stf, self.buf, self.pos)))
        sef.pos += calcsize(stf)

    def unpack2(self, desc):
        sd = UnpackDesc.struct_map(desc)
        for nm, stf in [(nm, "<%s" % stz,) for nm, stz in sd]:
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
    stat.print_stats()
    return result


def ulong_from_tuple(value):
    return sum(map(lambda x, y: 256**x*y, (0, 1, 2, 3), value))
