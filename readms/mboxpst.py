# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

import argparse
import codecs
from sys import argv, stderr, stdout
from os import path, mkdir
from traceback import print_exc
from readpst import NDBLayer, PropertyContext, PropertyValue
from metapst import all_props_types
from readutl import run_profile


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
        help="list messages, implies [--list]")
    # export messages
    parser.add_argument(
        "--print-messages", dest="nids", metavar="nid", type=int,
        nargs="+", default=None,
        help="print messages content")
    parser.add_argument(
        "--with-binary", action="store_true", default=False,
        help="skip binary hex dumps")
    parser.add_argument(
        "--save", action="store_true", default=False,
        help="save messages into external files")
    return parser


def list_content(ndb, params):
    folders_fmt = (("ContentCount", "%4d"),
                   ("Subfolders", "%-5s"),
                   ("DisplayNameW", "%-30s"),)
    message_fmt = (("MessageSize", "%8d"),
                   ("MessageDeliveryTime", "%20s"),
                   ("SubjectW", "%-30s"),)

    if params.save:
        bnm = path.basename(params.pstfile).split(".")[0]
        dnm = path.dirname(params.pstfile)
        out = codecs.open(path.join(dnm, "%s_list.txt" % bnm),
                          "w+", "UTF-8")
    else:
        out = stdout

    class props:
        def __init__(self):
            self.empty = True

        def setup(self, pc):
            self.empty = False
            self.props = {}
            for tag, desc in pc._props.iteritems():
                # print desc
                self.props[desc["propCode"]] = desc

        def tag(self, name):
            return self.props[name]

        def value(self, pc, name):
            ax = self.tag(name)
            bu = pc.get_buffer(ax["propTag"])
            pv = PropertyValue(ax["propType"], bu)
            return pv.get_value()

    def list_pc(pc_type, fields):
        att = props()
        if not params.profile:
            print >>out, "="*60
            print >>out, pc_type, "\n"
        for nx in ndb._nbt:
            if nx["typeCode"] != pc_type:
                continue
            pc = PropertyContext(ndb, nx["nid"])
            if att.empty:
                att.setup(pc)
            if not params.profile:
                print >>out, "%9d %7d" % (nx["nid"], nx["nidParent"]),
            for code, fmt in fields:
                value = att.value(pc, code)
                if not params.profile:
                    print >>out, ("%s" % fmt) % value,
            if not params.profile:
                print >>out
        if not params.profile:
            print >>out

    if params.list:
        list_pc("NORMAL_FOLDER", folders_fmt)
    if params.list_messages:
        list_pc("NORMAL_MESSAGE", message_fmt)


def print_messages(ndb, params):
    if params.nids is None:
        return
    for nid in params.nids:
        if params.save:
            bnm = path.basename(params.pstfile).split(".")[0]
            dnm = path.dirname(params.pstfile)
            out = codecs.open(path.join(dnm, "%s_%d.txt" % (bnm, nid)),
                              "w+", "UTF-8")
            odir = path.join(dnm, "%s_%d" % (bnm, nid))
            if not path.exists(odir):
                if params.with_binary:
                    mkdir(odir)
        else:
            out = stdout

        if not params.profile:
            print >>out, "="*60
            print >>out, "NID:", nid, "\n"

        pc = PropertyContext(ndb, nid)
        for k, p in pc._props.iteritems():
            value_buf = pc.get_buffer(p['propTag'])
            pv = PropertyValue(p["propType"], value_buf)
            pt_code, pt_size, _, = pv.pt_desc
            ptag = all_props_types.get(p["propTag"], None)
            ptag = ptag and ptag["name"] or p["propCode"]
            try:
                value = pv.get_value()
            except NotImplementedError:
                if params.with_binary:
                    outx = StringIO()
                    dump_hex(value_buf, out=outx)
                    value = outx.getvalue().strip()
            if not params.profile:
                print >>out, "0x%04X %-10s %4d %6d %-40s" % (
                    k, pt_code, pt_size, len(value_buf), ptag, ),
                if pt_code == "Binary":
                    if params.with_binary:
                        if params.save:
                            if not ptag.startswith("0x"):
                                onm = path.join(odir, "%s.out" % (ptag,))
                                with open(onm, "wb+") as fout:
                                    fout.write(value.data)
                            print >>out
                            continue
                    else:
                        print >>out
                        continue
                if value is not None and len(unicode(value)) >= 30:
                    print >>out, "\n%s\n" % value
                else:
                    print >>out, "[%s]" % value
        if not params.profile:
            print >>out
        if params.save:
            out.close()


def command_line(inp_args=None):
    inp_args = inp_args or argv[1:]
    parser = command_line_parser()
    args = parser.parse_args(inp_args)

    def run(args):
        with NDBLayer(args.pstfile) as ndb:
            list_content(ndb, args)
            print_messages(ndb,  args)

    if args.profile:
        run_profile(run, args)
    else:
        run(args)


if __name__ == "__main__":
    command_line(argv[1:])
