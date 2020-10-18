# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

import argparse
import codecs
from sys import argv, stdout
from os import path, mkdir, rmdir
from io import StringIO
from readms.readpst import NDBLayer, PropertyContext, PropertyValue
from readms.readutl import run_profile, dump_hex


def command_line_parser():
    parser = argparse.ArgumentParser(
        description="", prog="mboxpst",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("pstfile", type=str,
                        help="Path to Outlook PST file")
    parser.add_argument(
        "--profile", action="store_true", default=False,
        help="run with cProfile with no output")
    # list contents
    parser.add_argument(
        "--list", action="store_true", default=False,
        help="list folders")
    parser.add_argument(
        "--list-messages", action="store_true", default=False,
        help="list messages")
    parser.add_argument(
        "--list-attachments", action="store_true", default=False,
        help="list messages attachements")
    parser.add_argument(
        "--list-all", action="store_true", default=False,
        help="list folders, messages and attachements")
    # export messages
    parser.add_argument(
        "--print-messages", dest="nids", metavar="nid", type=int,
        nargs="+", default=None,
        help="print messages content")
    parser.add_argument(
        "--with-binary", action="store_true", default=False,
        help="process binaries")
    parser.add_argument(
        "--binary-limit", type=int, metavar="limit", default=1024,
        help="skip above that limit or save into external file")
    parser.add_argument(
        "--with-attachments", action="store_true", default=False,
        help="export attachments`")
    parser.add_argument(
        "--save", action="store_true", default=False,
        help="save messages into external files")
    return parser


def list_content(ndb, params):
    folders_fmt = (("ContentCount", "%5d"),
                   ("Subfolders", "%-7s"),
                   ("DisplayName", "%-30s"),)
    message_fmt = (("MessageSizeExtended", "%8d"),
                   ("MessageDeliveryTime", "%20s"),
                   ("Subject", "%-30s"),)

    if not (params.list or
            params.list_messages or
            params.list_attachments):
        return

    if params.save:
        bnm = path.basename(params.pstfile).split(".")[0]
        dnm = path.dirname(params.pstfile)
        out = codecs.open(path.join(dnm, "%s_list.txt" % bnm),
                          "w+", "UTF-8")
    else:
        out = stdout

    def list_pc(pc_type, fields):
        if not params.profile:
            print("="*60, file=out)
            print(pc_type, "\n", file=out)
        for nx in ndb._nbt:
            if nx["typeCode"] != pc_type:
                continue
            pc = PropertyContext(ndb, nx["nid"])
            if not params.profile:
                print("%9d %7d" % (nx["nid"], nx["nidParent"]), file=out, end='')
            for code, fmt in fields:
                value = pc.get_value(code)
                if not params.profile:
                    print(("%s " % fmt) % value, file=out, end='')
            if not params.profile:
                print(file=out)
        if not params.profile:
            print(file=out)

    if params.list:
        list_pc("NORMAL_FOLDER", folders_fmt)
    if params.list_messages:
        list_pc("NORMAL_MESSAGE", message_fmt)
    if params.list_attachments:
        if not params.profile:
            print("="*60, file=out)
            print("ATTACHMENT\n", file=out)
        for nid, hnid in ndb.list_nids("ATTACHMENT"):
            pc = PropertyContext(ndb, nid, hnid)
            p1 = pc.get_value("AttachSize")
            p2 = pc.get_value(pc.alt_name("DisplayName", "AttachFilename"))
            p2 = p2 or '--липсва--'
            if not params.profile:
                print("{0:9d} {1:7d} {2:12,d} {3:<20}".format(nid, hnid, p1, p2), file=out)


def print_messages(ndb, params):
    if params.nids is None:
        return
    for nid in params.nids:
        bnm = path.basename(params.pstfile).split(".")[0]
        dnm = path.dirname(params.pstfile)
        if params.save:
            out = codecs.open(path.join(dnm, "%s_%d.txt" % (bnm, nid)),
                              "w+", "UTF-8")
        else:
            out = stdout
        if params.save or params.with_attachments:
            odir = path.join(dnm, "%s_%d" % (bnm, nid))
            if not path.exists(odir):
                mkdir(odir)

        if not params.profile:
            print("="*60, file=out)
            print("NID:", nid, "\n", file=out)

        pc = PropertyContext(ndb, nid)
        for k, p in pc._props.items():
            value_buf = pc.get_buffer(p['propTag'])
            pv = PropertyValue(p["propType"], value_buf)
            pt_code, pt_size, _, = pv.pt_desc
            ptag = p['propCode']
            try:
                value = pv.get_value()
            except NotImplementedError:
                if params.with_binary:
                    outx = StringIO()
                    dump_hex(value_buf, out=outx)
                    value = outx.getvalue().strip()
            if not params.profile:
                print("0x%04X %-10s %4d %6d %-40s" % (
                    k, pt_code, pt_size, len(value_buf), ptag, ), file=out, end='')
                if pt_code == "Binary":
                    if params.with_binary:
                        if params.save:
                            if (not ptag.startswith("0x") and
                                    len(value.data) > params.binary_limit):
                                onm = path.join(odir, "%s.out" % (ptag,))
                                with open(onm, "wb+") as fout:
                                    fout.write(value.data)
                                print(file=out)
                                continue
                            value = PropertyValue.BinaryValue(value.data[:params.binary_limit])
                        else:
                            value = PropertyValue.BinaryValue(value.data[:params.binary_limit])
                    else:
                        print(file=out)
                        continue
                if value is not None and len(str(value)) >= 30:
                    print("\n%s\n" % value, file=out)
                else:
                    print("[%s]" % value, file=out)
        if not params.profile:
            print(file=out)

        if params.with_attachments:
            for anid, snid in ndb.list_nids("ATTACHMENT", nid):
                pa = PropertyContext(ndb, anid, snid)
                att_name = pa.alt_name("AttachLongFilename", "DisplayName",
                                       "AttachFilename")
                att_name = pa.get_value(att_name)
                if not params.profile:
                    print("{0:10,d} {1:<60s}".format(
                        pa.get_value("AttachSize"), att_name), file=out)
                att = pa.get_value("AttachDataObject")
                if not params.profile:
                    with open(path.join(odir, att_name), "wb+") as fout:
                        fout.write(att.data)

        if params.save:
            out.close()
            try:
                rmdir(odir)
            except OSError:
                pass  # not empty


class PstBox:
    def __init__(self, file_name):
        self.file_name = file_name
        self.ndb = NDBLayer(file_name)

    def reader(self, *args):
        parser = command_line_parser()
        args = list(args)
        args.insert(0, self.file_name)
        args = parser.parse_args(args)
        if args.list_all:
            args.list = True
            args.list_messages = True
            args.list_attachments = True
        list_content(self.ndb, args)
        print_messages(self.ndb, args)

    def close(self):
        self.ndb.close()


def command_line(inp_args=None):
    inp_args = inp_args or argv[1:]
    parser = command_line_parser()
    args = parser.parse_args(inp_args)
    if args.list_all:
        args.list = True
        args.list_messages = True
        args.list_attachments = True

    def run(args):
        with NDBLayer(args.pstfile) as ndb:
            list_content(ndb, args)
            print_messages(ndb, args)

    if args.profile:
        run_profile(run, args)
    else:
        run(args)


if __name__ == "__main__":
    command_line(argv[1:])
