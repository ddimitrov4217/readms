# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

import pickle
from os import listdir, path
from zipfile import ZIP_DEFLATED, ZipFile

import click

from readms.pstmbox import MboxCacheEntry, TagsList


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
        mbox_file = path.join(pstpath, f"{mbox_name}.pst")
        # TODO: Да работи директно с архивирания файл
        msgids_import = path.join(archive, f"{mbox_name}_msgids.idx")
        tags_import = path.join(archive, f"{mbox_name}_tags.idx")
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
            print(f"за маркер [{tag}], {len(nids):,d} nid(s)")
            for nid in nids:
                msgid = msgids.get(nid, None)
                if msgid is not None:
                    if mx is None:
                        mx = MboxCacheEntry(mbox_file, ctx.obj['store'])
                        target_msgids = {msgid: nid for nid, msgid in mx._msgids}
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


@manage_tags.command('list', help='Извежда регистрираните маркери')
@click.pass_context
def list_tags(ctx):
    tags = TagsList(ctx.obj['store'])
    tags_codes = ', '.join([x_[0] for x_ in tags.get_tags()])
    print('\nРегистрирани до момента тагове: ', tags_codes)


@manage_tags.command('add', help='Добавя маркери за използване по съобщенията')
@click.argument('codes', nargs=-1, required=False)
@click.pass_context
def addtags(ctx, codes):
    if codes is None:
        return
    tags = TagsList(ctx.obj['store'])
    for tag in codes:
        tags.add_tag(tag, tag)


@manage_tags.command('del', help='Изтрива регистрирани маркери за използване по съобщенията')
@click.argument('codes', nargs=-1, required=False)
@click.pass_context
def deltags(ctx, codes):
    if codes is None:
        return
    tags = TagsList(ctx.obj['store'])
    for tag in codes:
        tags.del_tag(tag)


if __name__ == '__main__':
    manage_tags()
