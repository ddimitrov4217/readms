# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

from os import listdir, path
from zipfile import ZipFile, ZIP_DEFLATED
import pickle
import click

from readms.pstmbox import MboxCacheEntry

# TODO Да се добавят и фукциите от pstmbox

@click.group()
@click.option('--store', default='outlook/index', help='Директория за индексиране на pst файловете')
@click.pass_context
def manage_tags(ctx=None, store=None):
    ctx.ensure_object(dict)
    ctx.obj['store'] = store


@manage_tags.command('export', help='Архивира таговете на съобщенията')
@click.option('--archive', default='tags_archive.zip', help='Име на файла за архива')
@click.pass_context
def export_tags(ctx, archive):
    zf = ZipFile(path.join(ctx.obj['store'], archive), "w", ZIP_DEFLATED)
    for fnm in listdir(ctx.obj['store']):
        if fnm.endswith("_tags.idx") or fnm.endswith("_msgids.idx"):
            print('...', fnm)
            zf.write(path.join(ctx.obj['store'], fnm), fnm)
    zf.close()


@manage_tags.command('merge', help='Добавя архивирани таговете към съобщенията')
@click.option('--archive-dir', help='Директория където е разпакетиран на файла за архива')
@click.option('--pstpath', default='outlook', help='Директория в която са pst файловете')
@click.pass_context
def merge_tags(ctx, archive, pstpath):
    def list_mbox():
        for fnm in listdir(ctx.obj['store']):
            if not fnm.endswith("_tags.idx"):
                continue
            yield fnm.replace("_tags.idx", "")

    def apply_tags_file(mbox_name):
        mbox_file = path.join(pstpath, "%s.pst" % mbox_name)
        # TODO Да работи директно с архивирания файл
        msgids_import = path.join(archive, "%s_msgids.idx" % mbox_name)
        tags_import = path.join(archive, "%s_tags.idx" % mbox_name)
        if (not path.exists(msgids_import) or
                not path.exists(tags_import) or
                not path.exists(mbox_file)):
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
                        mx = MboxCacheEntry(mbox_file, ctx.obj['store'])
                        target_msgids = dict((msgid, nid) for nid, msgid in mx._msgids)
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

    for mbox_name in list_mbox():
        print("\n", mbox_name)
        apply_tags_file(mbox_name)


if __name__ == '__main__':
    manage_tags()
