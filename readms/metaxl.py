# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

import re


def _read_desc_resource():
    from pkgutil import get_data
    resource_fnm = "papers/Excel97-2007-Binary-Format.txt"
    data = get_data("readms.metapst", resource_fnm).splitlines()
    lno = 0
    while lno < len(data):
        lno = _read_cell_records_list(data, lno)
        lno = _read_records_desc(data, lno)
        lno += 1


def _read_cell_records_list(data, lno):
    tag_ = "# *** BIFF Records: Alphabetical Order (%s)"
    if not data[lno].startswith(tag_ % "START"):
        return lno
    lno += 1
    state_ = 0
    names_ = [[], []]
    while not data[lno].startswith(tag_ % "END") and lno < len(data):
        line_ = data[lno].strip()
        if (len(line_) == 0 or line_.startswith("# ***") or
                line_ == "Record" or line_ == "Number"):
            lno += 1
            continue
        names_[state_ % 2].append(line_)
        state_ += 1
        lno += 1

    numh_ = [int(x.strip("h"), 16) for x in names_[1]]
    name_ = [tuple(x.split(": ", 1)) for x in names_[0]]
    biff_rec_names.update(dict(zip(numh_, name_)))
    return lno


class _joined_lines():
    """Обединяване на редовете.

    Последвователни редове се обединяват в един общ. За начало на ново
    обединение се счита напълно празен ред. Един или повече празни редове
    се докладват само веднъж. Редовете за нова страница се игнорира.
    Редовете с тагове се докладват без обединение.
    """

    def __init__(self, lno, data, tag):
        self._lx = lno
        self._dx = data
        self._end_tag = tag % "END"

    def __iter__(self):
        out_ = []
        sent_empty = False
        while self._lx < len(self._dx):
            line_ = self._dx[self._lx].strip()
            if line_ == chr(12):
                continue
            if self._dx[self._lx].startswith(self._end_tag):
                if len(out_) > 0:
                    yield " ".join(out_)
                break
            if len(line_) == 0:
                if len(out_) == 0:
                    if not sent_empty:
                        yield ""
                        sent_empty = True
                else:
                    yield " ".join(out_)
                    out_ = []
            else:
                if line_.startswith("# ***"):
                    yield line_
                else:
                    out_.append(line_)
                    sent_empty = False
            self._lx += 1

    def last_pos(self):
        return self._lx


def _read_records_desc(data, lno):
    tag_ = "# *** Record Descriptions (%s)"
    if not data[lno].startswith(tag_ % "START"):
        return lno
    rx_heading = re.compile(r"""(?P<code>[A-Z0-9]+?):\s+(?P<name>.+?)\s+
                            [(](?P<hnum>[0-9a-fA-F]+?)h[)]""", re.X)
    h_model = ("Offset", "Field Name", "Size", "Contents")
    h_index, d_index = 0, 0
    rec_desc, rec_desc_out, rec_status = None, None, 0
    lines = _joined_lines(lno+1, data, tag_)

    def safe_as_int(x):
        return [int(_) if _.isdigit() else -1 for _ in x]

    for line_ in lines:
        heading_ = rx_heading.match(line_)
        if heading_ is not None:
            if rec_desc is not None:
                rec_desc_out.extend(zip(
                    safe_as_int(rec_desc[0]), safe_as_int(rec_desc[2]),
                    rec_desc[1], rec_desc[3]))
            h_index, d_index, rec_status = 0, 0, 0
            rec_desc = [], [], [], []
            rec_desc_out = []
            biff_rec_descr[heading_.group("code")] = (
                int(heading_.group("hnum"), 16),
                heading_.group("code"), heading_.group("name"),
                rec_desc_out)
        else:
            if len(line_) == 0:
                h_index, d_index = 0, 0
                continue
            if h_index == 4 and rec_status < 2:
                rec_desc[d_index % 4].append(line_)
                d_index += 1
            else:
                if line_ == h_model[h_index]:
                    h_index += 1
                    if h_index == 4:
                        rec_status = 1
                else:
                    if rec_status == 1:
                        rec_status = 2
                    h_index = 0
    return lines.last_pos()


def biff_rec_name(rtag):
    return biff_rec_names.get(rtag, ("UNKNOWN", "TAG:%04X" % rtag),)


def test_rec_desc_plain():
    from pprint import pprint
    # pprint(biff_rec_names)
    # pprint(biff_rec_descr)
    pprint(biff_rec_descr["AUTOFILTER"])
    pprint(biff_rec_descr["SELECTION"])


def test_rec_desc():
    from pprint import pprint
    print "\nEmpty descriptions\n"
    for numh, code, name, desc in biff_rec_descr.values():
        if len(desc) == 0:
            print "%4X %s: %s" % (numh, code, name)
    print "\nNon ordered offset\n"
    for numh, code, name, desc in biff_rec_descr.values():
        offset = [off for off, _, _, _ in desc if off > 0]
        if sorted(offset) != offset:
            print "%4X %s: %s" % (numh, code, name)
            pprint(biff_rec_descr[code], width=110)
            print


biff_rec_names = {}
biff_rec_descr = {}

_read_desc_resource()


if __name__ == '__main__':
    # test_rec_desc_plain()
    test_rec_desc()

