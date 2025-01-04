# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

import codecs
from io import StringIO
from sys import stderr

import click

from readms.readpst import NDBLayer, PropertyContext, PropertyValue
from readms.readutl import dump_hex


@click.group()
@click.argument('pstfile')
@click.pass_context
def cli(ctx, pstfile):
    ctx.ensure_object(dict)
    ctx.obj['pstfile'] = pstfile


@cli.command('content', help='Извежда съдържанието на pst файла')
@click.option('--list-folders', is_flag=True, show_default=False, help='папки')
@click.option('--list-messages', is_flag=True, show_default=False, help='съобщения')
@click.option('--list-attachments', is_flag=True, show_default=False, help='приложени файлове')
@click.option('--list-all', is_flag=True, show_default=False, help='извежда всичко')
@click.pass_context
def list_content(ctx, list_folders, list_messages, list_attachments, list_all):
    def format_int_func(x):
        if x is not None:
            return f"{x:,d}"
        return "None"

    if list_all:
        list_folders = True
        list_messages = True
        list_attachments = True

    if not (list_folders or list_messages or list_attachments):
        return

    folders_fmt = (("ContentCount", format_int_func, "{0:>7s} ", "Count"),
                   ("Subfolders",  str, "{0:<10s} ", None),
                   ("DisplayName", str, "{0:<30s} ", None),)

    message_fmt = (("MessageSizeExtended", format_int_func, "{0:>12s} ", "Size"),
                   ("MessageDeliveryTime", str, "{0:25s} ", None),
                   ("Subject", str, "{0:30s}", None),)

    def list_pc(ndb, pc_type, fields):
        print("="*60)
        print(pc_type, "\n")

        print(f"{'nid':>9s} {'parent':>7s}", end='')
        for code, _func, fmt, title in fields:
            print(fmt.format(title or code), end='')
        print()

        for nx in ndb._nbt:
            if nx["typeCode"] != pc_type:
                continue
            pc = PropertyContext(ndb, nx["nid"])
            print(f'{nx["nid"]:#9d} {nx["nidParent"]:#7d}', end='')

            for code, func, fmt, _title in fields:
                value = pc.get_value(code)
                print(fmt.format(func(value)), end='')
            print()
        print()

    with NDBLayer(ctx.obj['pstfile']) as ndb:
        if list_folders:
            list_pc(ndb, "NORMAL_FOLDER", folders_fmt)

        if list_messages:
            list_pc(ndb, "NORMAL_MESSAGE", message_fmt)

        if list_attachments:
            print("="*60)
            print("ATTACHMENT\n")
            print(f"{'nid':>9} {'hnid':>7} {'size':>12} {'name':<20}")

            for nid, hnid in ndb.list_nids("ATTACHMENT"):
                pc = PropertyContext(ndb, nid, hnid)
                p1 = pc.get_value("AttachSize")
                p2 = pc.get_value(pc.alt_name("DisplayName", "AttachFilename"))
                p2 = p2 or '--липсва--'
                print(f"{nid:#9d} {hnid:#7d} {p1:#12,d} {p2:<20}")


@cli.command('messages', help='Извежда едно или повече съобщения')
@click.argument('nids', nargs=-1, type=int)
@click.option('--binary-limit', type=int, show_default=True, default=0,
              help='извежда най-много толкова байта за binary атрибути')
@click.pass_context
def print_messages(ctx, nids, binary_limit):
    with NDBLayer(ctx.obj['pstfile']) as ndb:
        for nid in nids:
            print("="*60)
            print("NID:", nid, "\n")

            pc = PropertyContext(ndb, nid)
            for k, p in pc._props.items():
                value_buf = pc.get_buffer(p['propTag'])
                pv = PropertyValue(p["propType"], value_buf)
                pt_code, pt_size, _, = pv.pt_desc
                ptag = p['propCode']

                try:
                    value = pv.get_value()
                except NotImplementedError:
                    if binary_limit > 0:
                        outx = StringIO()
                        dump_hex(value_buf, out=outx)
                        value = outx.getvalue().strip()

                print(f"{k:#04X} {pt_code:10s} {pt_size:#4d} "
                      f"{len(value_buf):#6d} {ptag:40s}", end='')
                if pt_code == "Binary":
                    if binary_limit > 0:
                       value = PropertyValue.BinaryValue(value.data[:binary_limit])
                    else:
                        print()
                        continue
                if value is not None and len(str(value)) >= 30:
                    print(f"\n{value}\n")
                else:
                    print(f"[{value}]")
            print()

            for anid, snid in ndb.list_nids("ATTACHMENT", nid):
                pa = PropertyContext(ndb, anid, snid)
                att_name = pa.alt_name("AttachLongFilename", "DisplayName", "AttachFilename")
                att_name = pa.get_value(att_name)
                print(f'{pa.get_value("AttachSize"):>10,d} {att_name:<60s}')

@cli.command('nltk', help='Извежда текста на съобщенията подходящо за NLTK')
@click.argument('outfile', type=click.STRING)
@click.pass_context
def print_stat_messages(ctx, outfile):
    progress = 0
    with (NDBLayer(ctx.obj['pstfile']) as ndb,
            codecs.open(outfile, "w+", "UTF-8") as out):
        for nx in ndb._nbt:
            if nx['typeCode'] != 'NORMAL_MESSAGE':
                continue
            pc = PropertyContext(ndb, nx['nid'])
            print('-------BEGIN MESSAGE HEADER-------', file=out)
            print(nx['nid'], file=out)
            print(pc.get_value('MessageDeliveryTime'), file=out)
            print(pc.get_value('ConversationTopic'), file=out)
            print('-------BEGIN MESSAGE BODY-------', file=out)
            print(pc.get_value('Body'), file=out)
            print('-------END MESSAGE BODY-------', file=out)
            progress += 1
            if progress % 10 == 0:
                print('.', file=stderr, end='', flush=True)
    print(file=stderr)


# https://docs.fileformat.com/email/
# https://datatracker.ietf.org/doc/html/rfc5322.html
@cli.command('export', help='Извежда съобщения в широко изпозлвани формати')
@click.argument('nids', nargs=-1, type=int)
@click.option('--path', type=click.Path(exists=True, dir_okay=True),
              default='data', show_default=True,
              help='папка, в която да се записват файловете')
@click.option('--files', is_flag=True, show_default=False, help='като файлове (нестандартно)')
@click.option('--eml', is_flag=True, show_default=False, help='TODO като eml RFC-822')
@click.option('--outlook', is_flag=True, show_default=False, help='TODO като Outlook msg')
@click.pass_context
def export_messages(ctx, nids, path, files):
    # TODO: Извеждане като файлове (нестандартно)
    # TODO: Извеждане като eml RFC-822
    # TODO: Извеждане като Outlook msg
    pass


if __name__ == "__main__":
    cli()
