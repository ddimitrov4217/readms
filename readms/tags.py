# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

import os
import zipfile
import pickle

from paste.script.command import Command
from paste.deploy import appconfig
from leasweb.wsgiapp import load_environment
from leasweb.model import MboxCacheEntry


class ArchiveMessagesTags(Command):

    min_args = 1
    max_args = 1
    here_dir = os.getcwd()
    usage = "CONFIG_FILE"
    summary = "Save messages tags into zip file"
    group_name = "Tags"

    parser = Command.standard_parser(verbose=True)
    parser.add_option("--outdir", action="store",
                      dest="outdir", default=here_dir,
                      help="Output dir [%default]")

    def command(self):
        config_file = self.args[0]
        config_name = "config:%s" % config_file
        appconf = appconfig(config_name, relative_to=self.here_dir)
        appconf.global_conf["history.enabled"] = False
        self.archive_tags(appconf)

    def archive_tags(self, appconf):
        output_file = "leasweb_tags_index.zip"
        output_file = os.path.join(self.options.outdir, output_file)
        index_dir = appconf["pstmbox_index_dir"]
        zf = zipfile.ZipFile(output_file, "w", zipfile.ZIP_DEFLATED)
        for fnm in os.listdir(index_dir):
            if fnm.endswith("_tags.idx") or fnm.endswith("_msgids.idx"):
                print(fnm)
                zf.write(os.path.join(index_dir, fnm), fnm)
        zf.close()
        return output_file


class MergeMessagesTags(Command):

    min_args = 2
    max_args = 2
    here_dir = os.getcwd()
    usage = "CONFIG_FILE dir_with_tags_to_merge"
    summary = "Import (merge) messages tags into leasweb index"
    group_name = "Tags"
    parser = Command.standard_parser(verbose=True)

    def command(self):
        config_file = self.args[0]
        config_name = "config:%s" % config_file
        appconf = appconfig(config_name, relative_to=self.here_dir)
        appconf.global_conf["history.enabled"] = False
        load_environment(appconf.global_conf, appconf.local_conf)
        import_dir = self.args[1]
        for mbox_name in self.list_mbox(import_dir):
            print("\n", mbox_name)
            self.apply_tags_file(appconf, import_dir, mbox_name)

    @staticmethod
    def list_mbox(import_dir):
        for fnm in os.listdir(import_dir):
            if not fnm.endswith("_tags.idx"):
                continue
            yield fnm.replace("_tags.idx", "")

    @staticmethod
    def apply_tags_file(appconf, import_dir, mbox_name):
        mbox_file = os.path.join(appconf["pstmbox_dir"], "%s.pst" % mbox_name)
        msgids_import = os.path.join(import_dir, "%s_msgids.idx" % mbox_name)
        tags_import = os.path.join(import_dir, "%s_tags.idx" % mbox_name)
        if (not os.path.exists(msgids_import) or
                not os.path.exists(tags_import) or
                not os.path.exists(mbox_file)):
            return False

        with open(msgids_import, "rb") as fin:
            msgids = pickle.load(fin)
            msgids = dict(msgids)

        with open(tags_import, "rb") as fin:
            tags = pickle.load(fin)

        mx = None  # lazy отваряне, за по-бързо ако няма маркери
        target_msgids = None
        for tag, nids in tags.iteritems():
            print("за маркер [%s], %d nid(s)" % (tag, len(nids)))
            for nid in nids:
                msgid = msgids.get(nid, None)
                if msgid is not None:
                    if mx is None:
                        mx = MboxCacheEntry(mbox_file,
                                            appconf["pstmbox_index_dir"])
                        target_msgids = dict((msgid, nid)
                                             for nid, msgid in mx._msgids)
                    target_nid = target_msgids.get(msgid, None)
                    if target_nid is not None:
                        if target_nid not in mx.get_tag_nids(tag):
                            print(nid, target_nid, msgid)
                            mx.tags_list.add_tag(tag, None)
                            mx.add_tag(tag, target_nid)
                    else:
                        print(nid, "target not found", msgid)
                else:
                    print(nid, "source not found")
        if mx is not None:
            mx.close()
        return True
