# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

import codecs
import mimetypes
import re
from email.headerregistry import Address
from email.message import EmailMessage
from email.policy import SMTP
from io import StringIO
from os import mkdir, path
from sys import stderr
from urllib.parse import quote as urlquote

import click

from readms.metapst import get_internet_code_page
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
@cli.command('export', help='Извежда съобщения в широко изпозлвани формати')
@click.argument('opath', type=click.Path(exists=True, dir_okay=True))
@click.argument('nids', nargs=-1, type=int)
@click.option('--folders', is_flag=True, show_default=True,
              help='извежда всички съобщения като счита зададените nids за идентификатори на папки')
@click.option('--plain', is_flag=True, show_default=True,
              help='като сглобени файлове в папка (нестандартно)')
@click.option('--eml', is_flag=True, show_default=True, help='като eml RFC-822')
@click.option('--outlook', is_flag=True, show_default=True, help='TODO като Outlook msg')
@click.pass_context
def export_messages(ctx, nids, folders, opath, plain, eml, outlook):
    with NDBLayer(ctx.obj['pstfile']) as ndb:
        all_nids = {}
        if folders:
            for nx in ndb._nbt:
                if nx["typeCode"] != 'NORMAL_MESSAGE':
                    continue
                if nx["nidParent"] in nids:
                    parent = str(nx["nidParent"])
                    if parent not in all_nids:
                        all_nids[parent] = []
                    all_nids[parent].append(nx["nid"])
        else:
            all_nids[''] = nids

        index = {}
        for pdir, nids in all_nids.items():
            odir = path.join(opath, pdir)
            if not path.exists(odir):
                mkdir(odir)
            for nid in nids:
                ofile = path.join(odir, f"{nid}")
                print(f"... export {nid} -> {ofile}")

                if plain:
                    index_data = export_plain(ndb, ofile, nid)
                    if folders:
                        if pdir not in index:
                            index[pdir] = []
                        index[pdir].append(index_data)
                if eml:
                    export_eml(ndb, ofile, nid)
                if outlook:
                    export_outlook(ndb, ofile, nid)

        # Извеждане на индекса
        if index:
            for pdir, pdir_index in index.items():
                with open(path.join(opath, pdir, "index.html"), "w", encoding="UTF-8") as fout:
                    print("<html><body><ul>", file=fout)
                    for entry in pdir_index:
                        print("<li>"
                              f"<a href='{entry['nid']}/{entry['link']}'>"
                              f"{entry['subject']}</a>"
                              "</li>",
                              file=fout)
                    print("</ul></body></html>", file=fout)


class EmailExport:
    def __init__(self, pc):
        self.pc = pc

    def find_attr(self, *names):
        for name in names:
            pv = self.pc.get_value(name)
            if pv is not None:
                return pv
        return None

    def get_sender(self):
        return (self.find_attr(self.pc, "SenderName", "SentRepresentingName"),
                self.find_attr(self.pc, "SenderSmtpAddress", "SentRepresentingSmtpAddress"))

    def get_recipients(self):
        return self.pc.get_value("DisplayTo"), self.pc.get_value("DisplayCc")

    def get_encoding(self):
        ec = self.pc.get_value("InternetCodepage")
        if ec is not None:
            code_page = get_internet_code_page(ec)
        return code_page or "UTF-8"

    def get_html(self):
        pv = self.pc.get_value("Html")
        if pv is not None:
            return codecs.decode(pv.data, self.get_encoding(), "replace")
        return None

    def get_attachments(self, ndb, nid):
        for anid, snid in ndb.list_nids("ATTACHMENT", nid):
            pa = PropertyContext(ndb, anid, snid)
            att_name = pa.alt_name("AttachLongFilename", "DisplayName", "AttachFilename")
            att_name = pa.get_value(att_name)
            att = pa.get_value("AttachDataObject")
            cid = pa.get_value('AttachContentId')
            yield att_name, cid, anid, att


def export_plain(ndb, odir, nid):
    pc = PropertyContext(ndb, nid)
    ee = EmailExport(pc)
    index_data = {'nid': nid}

    def format_email_addr(name, addr):
        result = []
        if name is not None:
            result.append(f' {name}')
        if addr is not None:
            result.append(f' &lt;{addr}&gt;')
        return ' '.join(result)

    # (1) Plain text на съобщението
    pv = pc.get_value("Body")
    if pv is not None:
        with open(path.join(odir, "body.txt"), "w", encoding="UTF-8") as fout:
            fout.write(pv)
            index_data['link'] = 'body.txt'

    # (2) Приложени файлове
    attached_cid = {}
    for att_name, cid, anid, att in ee.get_attachments(ndb, nid):
        with open(path.join(odir, att_name), "wb+") as fout:
            fout.write(att.data)
        attached_cid[cid or anid] = att_name

    # (3) Съобщението като HTML
    html_text = ee.get_html()
    if html_text is not None:
        with open(path.join(odir, "body.html"), "w",
                  encoding=ee.get_encoding(),
                  errors='replace') as fout:

            def fout_print(x):
                if x is not None:
                    print(x, file=fout)

            fout_print("<html><body>")

            # (3.1) Тема на писмото
            attr = pc.get_value_safe("ConversationTopic")
            if attr is not None:
                fout_print(f"<b>Subject:</b> {attr}<br/>")

            # (3.2) Автор на писмото
            name, addr = ee.get_sender()
            if name is not None or addr is not None:
                fout_print(f"<b>From:</b> {format_email_addr(name, addr)}<br/>")

            # (3.3) Получатели
            name_to, name_cc = ee.get_recipients()
            if name_to is not None:
                fout_print(f"<b>To:</b> {name_to}<br/>")
            if name_cc is not None:
                fout_print(f"<b>CC:</b> {name_cc}<br/>")

            # (3.4) Дата и час на получаване
            attr = pc.get_value("MessageDeliveryTime")
            if attr is not None:
                fout_print(f"<b>MessageDeliveryTime:</b> {attr:%d.%m.%Y %H:%M:%S %Z}<br/>")

            # (3.5) Приложени файлове
            attached_files = []
            for cid, refname in attached_cid.items():
                if html_text.find(f"cid:{cid}") < 0:
                    attached_files.append(refname)
            if attached_files:
                fout_print("<b>Attached files: </b>")
                for refname in attached_files:
                    fout_print(f'<a href="{urlquote(refname)}">{refname}</a>; ')

            fout_print("<hr/></body></html>")

            # (3.6) Inline картинки
            if html_text is not None:
                for cid, refname in attached_cid.items():
                    html_text = html_text.replace(f"cid:{cid}", refname)
                fout_print(html_text)
                index_data['link'] = 'body.html'

    attr = pc.get_value_safe("ConversationTopic")
    index_data['subject'] = attr or "No Subject"
    return index_data


# https://datatracker.ietf.org/doc/html/rfc5322.html
def export_eml(ndb, ofile, nid):
    index_data = {'nid': nid}
    pc = PropertyContext(ndb, nid)
    ee = EmailExport(pc)

    out = EmailMessage()

    # (1) Тема на писмото
    attr = pc.get_value_safe("ConversationTopic")
    if attr is not None:
        out["Subject"] = re.sub("[\r\n]", " ", attr)
    index_data['subject'] = attr or "No Subject"

    # (2) Автор на писмото
    name, addr = ee.get_sender()
    if name is not None or addr is not None:
        out["From"] = Address(name, addr_spec=addr)

    # (3) Получатели
    name_to, name_cc = ee.get_recipients()
    if name_to is not None:
        out["To"] = name_to
    if name_cc is not None:
        out["Cc"] = name_cc

    # (4) Дата и час на получаване
    attr = pc.get_value("MessageDeliveryTime")
    if attr is not None:
        out["Date"] = attr

    pv = pc.get_value("Body")
    if pv is not None:
        out.set_content(pv)

    # (5) Алтернативата в HTML
    html_text = ee.get_html()
    html_part = None
    if html_text is not None:
        out.add_alternative(html_text, subtype="html")
        html_part = out.get_payload()[-1]

    # (6) Приложените файлове и връзка с inline картинки
    for att_name, cid, _anid, att in ee.get_attachments(ndb, nid):
        ctype, encoding = mimetypes.guess_type(att_name)

        if ctype is None or encoding is not None:
            ctype = 'application/octet-stream'
        is_inline = html_text.find(f"cid:{cid}") >= 0
        maintype, subtype = ctype.split('/', 1)

        if html_part is not None and is_inline and ctype is not None:
            ftype, fext = ctype.split("/")
            html_part.add_related(att.data, ftype, fext, cid=cid)
        else:
            out.add_attachment(att.data, maintype=maintype, subtype=subtype, filename=att_name)

    index_data["link"] = f"{ofile}.eml"
    with open(index_data["link"], 'wb') as fout:
        fout.write(out.as_bytes(policy=SMTP))

    return index_data


def export_outlook(ndb, ofile, nid):  # noqa:ARG001
    # TODO: Извеждане като Outlook msg
    raise NotImplementedError


if __name__ == "__main__":
    cli()
