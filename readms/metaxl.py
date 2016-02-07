# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai


def _read_desc_resource():
    from pkgutil import get_data
    resource_fnm = "papers/Excel97-2007-Binary-Format.txt"
    data = get_data("readms.metapst", resource_fnm).splitlines()
    lno = 0
    while lno < len(data):
        lno = _read_cell_records_list(data, lno)
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


def biff_rec_name(rtag):
    return biff_rec_names.get(rtag, ("UNKNOWN", "TAG:%04X" % rtag),)


biff_rec_names = {}

_read_desc_resource()


if __name__ == '__main__':
    from pprint import pprint
    pprint(biff_rec_names)
