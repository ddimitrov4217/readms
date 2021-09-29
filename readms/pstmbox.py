# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

import os
from datetime import datetime
from time import time
from string import whitespace
from pkgutil import get_data

import hashlib
import pickle
import email
import email.header as email_header
import re
import logging

from readms.readpst import NDBLayer, PropertyContext

log = logging.getLogger(__name__)


# pylint: disable=too-many-instance-attributes
# Всички атрибути са необхдими за организирането на cache.
class MboxCacheEntry:
    """Прочетен архив с поща."""

    def __init__(self, ifile, index_dir):
        self._ifile = ifile
        self._index_dir = index_dir
        self._since = None
        self._mbox = None
        self._topic = None
        self._search_index = None
        self._search_match_nids = None
        self._sorted_nid = {}
        self._folders = []
        self._message = []
        self.update(_force=True)
        self.tags_list = TagsList(self._index_dir)
        self._load_tags()
        self._index_message_ids()

    def update(self, _force=False):
        if not _force:
            ot_mtime = os.stat(self._ifile).st_mtime
            ot_mtime = datetime.fromtimestamp(ot_mtime)
            if self._since is None or self._since < ot_mtime:
                _force = True
        if _force:
            log.info("load NDBLayer from %s", self._ifile)
            self._mbox = NDBLayer(self._ifile, self._index_dir)
            self._index_content()
            # pylint: disable=protected-access
            # тук е само за logging
            done_sec = "in {0:,.3f} sec".format(self._mbox._done_time)
            stat_info = "nbbt={0:,d}, nnbt={1:,d}".format(
                len(self._mbox._bbt), len(self._mbox._nbt))
            log.info("done %s, %s", done_sec, stat_info)
        self._since = datetime.now()

    def _index_pc(self, pc_type, use_filter=False):
        pc_list = []
        for nx in self._mbox._nbt:
            if nx["typeCode"] != pc_type:
                continue
            with_filter = use_filter and self._search_match_nids is not None
            if with_filter and nx["nid"] in self._search_match_nids or not with_filter:
                pc_list.append((nx["nid"], nx["nidParent"]))
        return pc_list

    def _index_content(self):
        self._folders = self._index_pc("NORMAL_FOLDER")
        self._message = self._index_pc("NORMAL_MESSAGE", use_filter=True)
        self._sorted_nid = {}

    def _is_uptodate_index(self, idx_fnm):
        if not os.path.exists(idx_fnm):
            return False
        fn_mtime = os.stat(self._ifile).st_mtime
        fn_mtime = datetime.fromtimestamp(fn_mtime)
        ix_mtime = os.stat(idx_fnm).st_mtime
        ix_mtime = datetime.fromtimestamp(ix_mtime)
        return fn_mtime <= ix_mtime

    def get_mbox(self):
        return self._mbox

    def close(self):
        if self._mbox is not None:
            self._mbox.close()

    def count_messages(self, folder):
        result = 0
        for _nid, nidp in self._message:
            if nidp == folder:
                result += 1
        return result

    def list_messages(self, folder, fields, skip=0, page=20, order_by=None, order_reverse=True):
        """Връща списъка със съобщения, които са в избраната папка.

        Резултатът е списък, елементите на който са tuple (списък)
        с nid на съобщението и стойности на атрибутите от fields в
        същата последователност.
        """

        order_by = order_by if order_by is not None else 'MessageDeliveryTime'
        cache_key = folder, order_by, order_reverse
        nid_list = self._sorted_nid.get(cache_key)
        if nid_list is None:
            nid_list = []
            for nid, nidp in self._message:
                if nidp != folder:
                    continue
                pc = PropertyContext(self._mbox, nid)
                dttm = pc.get_value(order_by)
                nid_list.append((nid, dttm))

            nid_list.sort(key=lambda x: (x[1] is None, x[1]), reverse=order_reverse)
            self._sorted_nid[cache_key] = nid_list

        result = []
        skipped, nout = 0, 0
        for nid, _ in nid_list:
            if skipped < skip:
                skipped += 1
                continue
            if page > 0 and nout == page:
                return result
            nout += 1
            pv = [nid]
            result.append(pv)
            pc = PropertyContext(self._mbox, nid)
            for att in fields:
                if pc.alt_name(att) is not None:
                    value = pc.get_value(att)
                else:
                    value = None
                pv.append(value)
        return result

    @staticmethod
    def _mime_type(pa):
        mime_name = pa.alt_name("AttachMimeTag")
        if mime_name is not None:
            mime = pa.get_value("AttachMimeTag")
        else:
            mime = "application/binary"
        return mime

    def list_attachments(self, mnid):
        result = []
        for nid, snid in self._mbox.list_nids("ATTACHMENT", mnid):
            pa = PropertyContext(self._mbox, nid, snid)
            att_name = pa.alt_name("AttachLongFilename", "DisplayName", "AttachFilename")
            if att_name is not None:
                filename = pa.get_value(att_name)
            else:
                # pylint: disable=protected-access
                filename = "NONAME"
                log.error("pa._propx(%d,%d): missing attachment name %s",
                          nid, snid, pa._propx)
            result.append((nid, snid, filename,
                           pa.get_value("AttachSize"),
                           self._mime_type(pa),
                           pa.get_value_safe("AttachMimeTag"),
                           pa.get_value_safe("AttachContentId")))
        return result

    def get_attachment(self, nid, anid):
        pa = PropertyContext(self._mbox, nid, anid)
        att_name = pa.alt_name("AttachLongFilename", "DisplayName", "AttachFilename")
        if att_name is not None:
            filename = pa.get_value(att_name)
        else:
            filename = "attachemnt_%d_%d" % (nid, anid)
        att = pa.get_value("AttachDataObject")
        return self._mime_type(pa), filename, att.data

    @staticmethod
    def topic_key_hash(topic):
        md5 = hashlib.md5()
        md5.update(topic.encode("UTF-8"))
        return md5.hexdigest()

    def topic_key(self, pc):
        if pc.alt_name("ConversationTopic") is None:
            return None
        topic_ = pc.get_value("ConversationTopic")
        return self.topic_key_hash(topic_)

    def topic_index(self):
        if self._topic is not None:
            return self._topic
        name, _ex = os.path.splitext(os.path.basename(self._ifile))
        topic_idx = "%s_topic.idx" % name
        topic_idx = os.path.join(self._index_dir, topic_idx)
        if not self._is_uptodate_index(topic_idx):
            start_ = time()
            log.info("create topic map")
            topic_map = {}
            for nid, nidp in self._message:
                pc = PropertyContext(self._mbox, nid)
                topic_ = self.topic_key(pc)
                if topic_ is None:
                    continue
                topic_list_ = topic_map.get(topic_)
                if topic_list_ is None:
                    topic_list_ = []
                    topic_map[topic_] = topic_list_
                topic_list_.append((nid, nidp))

            with open(topic_idx, "wb") as fout:
                pickle.dump(topic_map, fout, pickle.HIGHEST_PROTOCOL)
            done_sec = "done in {0:,.3f} sec".format(time()-start_)
            log.info(done_sec)
            return topic_map

        with open(topic_idx, "rb") as fin:
            return pickle.load(fin)

    def categories_index(self):
        name, _ex = os.path.splitext(os.path.basename(self._ifile))
        cat_idx = "%s_categories.idx" % name
        cat_idx = os.path.join(self._index_dir, cat_idx)
        if not self._is_uptodate_index(cat_idx):
            start_ = time()
            log.info("create categories map")
            cat_nids = []
            for nid, _nidp in self._message:
                pc = PropertyContext(self._mbox, nid)
                kw = pc.get_value("Keywords")
                if kw is not None:
                    cat_nids.append(nid)

            with open(cat_idx, "wb") as fout:
                pickle.dump(cat_nids, fout, pickle.HIGHEST_PROTOCOL)
            log.info("done in {0:,.3f} sec".format(time()-start_))

        with open(cat_idx, "rb") as fin:
            return pickle.load(fin)

    def simple_search(self, patterns):
        """Най-просто AND търсене по критерии.

        Критериите представляват (text,[fields+]). Търси се текста в
        зададените полета. Всички критерии се комбинират с AND. Търсенето
        по отделните полета (fields) се прави с OR. Резултатът представлява
        списък (nid,nidp,dttm) подреден обратно хронологично.
        """

        start_ = time()
        result = []
        for nid_, nidp_ in self._message:
            pc = PropertyContext(self._mbox, nid_)
            found = True
            for text_, fields_ in patterns:
                match = False
                text_ = text_.upper()
                for field_ in fields_:
                    value = pc.get_value_safe(field_)
                    if value is not None and text_ in value.upper():
                        match = True
                        break
                found = found and match
                if not found:
                    break
            if found:
                dttm = pc.get_value("MessageDeliveryTime")
                result.append((nid_, nidp_, dttm))

        result.sort(key=lambda x: x[2], reverse=True)
        done_sec = "{1:,d} item(s) in {0:,.3f} sec".format(
            time()-start_, len(result))
        log.info(done_sec)
        return result

    def _tags_filename(self):
        name, _ex = os.path.splitext(os.path.basename(self._ifile))
        tags_idx = "%s_tags.idx" % name
        return os.path.join(self._index_dir, tags_idx)

    def _load_tags(self):
        """Зареждане на съобщенията с маркери.

        Във външния файл се съхранява само tag:[nid1, nid2, ..., nidN].
        За улесненяване на работата, допълнително се конструира и обратното:
        nid:[tag1, ..., tagN]. Двете структури се поддържат синхронизирани.
        """

        tags_fnm = self._tags_filename()
        if os.path.exists(tags_fnm):
            with open(tags_fnm, "rb") as fin:
                self._tags = pickle.load(fin)
        else:
            self._tags = {}
            self._save_tags()

        self._tags_nid = {}
        for tag, nid in self._tags.items():
            for nx in nid:
                self._sync_tag_nid(tag, nx)

    def _sync_tag_nid(self, tag, nid):
        nx = self._tags_nid.get(nid, None)
        if nx is None:
            nx = self._tags_nid[nid] = set()
        nx.add(tag)

    def _save_tags(self):
        with open(self._tags_filename(), "wb") as fout:
            pickle.dump(self._tags, fout, pickle.HIGHEST_PROTOCOL)

    def _index_message_ids(self):
        """Индексиране по InternetMessageId.

        Допълнителната информация (като маркери по съобщенията) се съхранява
        по nid. Тъй като nid е е вътрешен идентификатор в рамките на pst файла,
        ако се направят нови export-и той ще се промени. За да се прехвърли
        допълнителната информация в новите export-и е необходимо да се
        съхраняват връзката между nid и универсален (външен) идентификатор
        на съобщенията. За тази цел се използва InternetMessageId.

        Индекса не се използва за работата на програмата, а само в инструменти
        за прехвърляне на допълнителна информация.
        """

        name, _ex = os.path.splitext(os.path.basename(self._ifile))
        msgids_idx = "%s_msgids.idx" % name
        msgids_fnm = os.path.join(self._index_dir, msgids_idx)
        if self._is_uptodate_index(msgids_fnm):
            with open(msgids_fnm, "rb") as fin:
                self._msgids = pickle.load(fin)
        else:
            start_ = time()
            self._msgids = []
            ndb = self._mbox
            for nx in ndb._nbt:
                if nx["typeCode"] != "NORMAL_MESSAGE":
                    continue
                pc = PropertyContext(ndb, nx["nid"])
                msgid = pc.get_value_safe("InternetMessageId", None)
                if msgid is not None:
                    self._msgids.append((nx["nid"], msgid))

            with open(msgids_fnm, "wb") as fout:
                pickle.dump(self._msgids, fout, pickle.HIGHEST_PROTOCOL)

            done_sec = "index {1:,d} messages(s) in {0:,.3f} sec".format(
                time()-start_, len(self._msgids))
            log.info(done_sec)

    def add_tag(self, tag, nid):
        if not self.tags_list.exist_tag(tag):
            raise KeyError(u"Невалиден маркер [%s]" % tag)
        tx = self._tags.get(tag, None)
        if tx is None:
            tx = self._tags[tag] = set()
        tx.add(nid)
        self._sync_tag_nid(tag, nid)
        self._save_tags()

    def del_tag(self, tag, nid):
        if tag in self._tags:
            self._tags[tag].discard(nid)
            self._tags_nid[nid].discard(tag)
            self._save_tags()

    def get_nid_tags(self, nid):
        nx = self._tags_nid.get(nid, None)
        if nx is not None:
            nx1 = list(nx)
            nx1.sort()
            return nx1
        return None

    def get_tag_nids(self, tag):
        return self._tags.get(tag, None)

    def get_search_index(self, refresh=False):
        if refresh:
            self._search_index = None

        if self._search_index is None:
            name, _ex = os.path.splitext(os.path.basename(self._ifile))
            search_idx = "%s_search_body.idx" % name
            search_idx = os.path.join(self._index_dir, search_idx)

            if not self._is_uptodate_index(search_idx) or refresh:
                search = SearchTextIndex(attrs=("Subject", "Body", ))
                search.create(self.get_mbox())
                search.save(search_idx)
            else:
                search = SearchTextIndex()
                search.read(search_idx)
            self._search_index = search.index

        return self._search_index

    def set_filter(self, search_string, match_mode=1, apply_mode=1):
        """Търси по една или повече думи.

        match_mode - (1) започва като, (2) съдържа, (3) точно като
        apply_mode - (1) коя да е дума, (2) всички думи
        """

        if search_string is None or len(search_string) == 0:
            self._search_match_nids = None
        else:
            index = self.get_search_index()
            self._search_match_nids = set()
            search_words = search_string.lower().split()

            for search_word in search_words:
                found_set = set()
                for word, nids in index.items():
                    # pylint: disable=too-many-boolean-expressions
                    # проверката е по типовете търсене и съответстващия критерий
                    if (match_mode == 1 and word.startswith(search_word) or
                            match_mode == 2 and search_word in word or
                            match_mode == 3 and word == search_word):
                        found_set.update(nids)

                if apply_mode == 1:
                    self._search_match_nids.update(found_set)
                elif apply_mode == 2:
                    if len(self._search_match_nids) == 0:
                        self._search_match_nids.update(found_set)
                    else:
                        self._search_match_nids.intersection_update(found_set)
                    if len(self._search_match_nids) == 0:
                        break
        self._index_content()
        return {'nid': self._message[0][1]} if len(self._message) > 0 else None

    def search_linked_messages(self, nid):
        log.info('linked to %d', nid)
        pc = PropertyContext(self.get_mbox(), int(nid))
        topic_list = self.topic_index().get(self.topic_key(pc))
        self._search_match_nids = {x_[0] for x_ in topic_list}
        self._index_content()
        # папката (една от всички) в която има свързани съобщения
        return {'nid': topic_list[0][1]} if len(topic_list) > 0 else None

    def search_tags(self):
        self._search_match_nids = self._tags_nid.keys()
        self._index_content()
        return {'nid': self._message[0][1]} if len(self._message) > 0 else None

    def search_categories(self):
        self._search_match_nids = self.categories_index()
        self._index_content()
        return {'nid': self._message[0][1]} if len(self._message) > 0 else None


class HiddenField:
    """Скрити полета от съобщенията"""

    def __init__(self, store_dir):
        self.file_name = os.path.join(store_dir, "hidden_fields.pickle")
        self.hiddens = set()
        if os.path.exists(self.file_name):
            with open(self.file_name, "rb") as fin:
                self.hiddens = pickle.load(fin)

    def _save(self):
        with open(self.file_name, "wb") as fout:
            pickle.dump(self.hiddens, fout, pickle.HIGHEST_PROTOCOL)

    def get_fields(self):
        return self.hiddens

    def show_field(self, field_name):
        self.hiddens.discard(field_name)
        self._save()

    def hide_field(self, field_name):
        self.hiddens.add(field_name)
        self._save()


# pylint: disable=too-few-public-methods
# Това е идеята на този клас: създава се подходящ достъп до съдържанието.
# Няма нужда от повече методи, освен извличане на съдържанието.
class MimeData:
    """Данни от smime attachments"""

    def __init__(self, data):
        self.message = email.message_from_string(data)
        self.parts = []
        ono = 1
        for part in self.message.walk():
            if part.is_multipart():
                continue
            name = part.get_param("name")
            if name is None:
                name = "part_%i" % ono
                ono += 1
            else:
                name, enc = email_header.decode_header(name)[0]
                if enc is not None:
                    name = name.decode(enc)
            self.parts.append((name, part))

    @staticmethod
    def content(part):
        data = part.get_payload(decode=True)
        if part.get_content_type().startswith("text/"):
            charset = part.get_param("charset")
            if charset is not None:
                data = data.decode(charset)
        return data


class MboxFilters:
    """Филтри върху съобщенията"""

    def __init__(self, store_dir):
        self.file_name = os.path.join(store_dir, "mbox_filters.pickle")
        self.filters = []
        if os.path.exists(self.file_name):
            with open(self.file_name, "rb") as fin:
                self.filters = pickle.load(fin)
        self.opers = dict(A=u"Добави", F=u"Остави само", M=u"Махни")
        self.opers_sort = ["A", "F", "M"]

    def append(self, oper, **kwargs):
        found = any(ox == oper and px == kwargs
                    for ox, px in self.filters)
        if not found:
            self.filters.append((oper, kwargs))
            self._save()

    def remove(self, index):
        del self.filters[index]
        self._save()

    def clear(self):
        self.filters = []
        self._save()

    def descr(self):
        result = []
        for fx in self.filters:
            oper, params = fx
            result.append(((oper, self.opers[oper]), params))
        return result

    def _save(self):
        with open(self.file_name, "wb") as fout:
            pickle.dump(self.filters, fout, pickle.HIGHEST_PROTOCOL)


class TagsList:
    """Маркери (tags) за поставяне по имейлите."""

    def __init__(self, store_dir):
        self._storage = os.path.join(store_dir, "tags.pickle")
        self._tags = {}
        if os.path.exists(self._storage):
            with open(self._storage, "rb") as fin:
                self._tags = pickle.load(fin)

    def get_tags(self):
        tags = list(self._tags.keys())
        tags.sort()
        for tag in tags:
            yield (tag, self._tags[tag])

    def add_tag(self, code, descr):
        if len(code) == 0:
            raise ValueError(u"Кода на маркера е задължителен")
        if any([x in code for x in whitespace]):
            raise ValueError(u"Кода на маркера не трябва да съдържа интервали")
        if code in self._tags and (descr is None or len(descr) == 0):
            pass
        else:
            self._tags[code] = descr
            self._save()

    def del_tag(self, code):
        if code in self._tags:
            del self._tags[code]
            self._save()
            return True
        return False

    def exist_tag(self, code):
        return code in self._tags

    def _save(self):
        with open(self._storage, "wb") as fout:
            pickle.dump(self._tags, fout, pickle.HIGHEST_PROTOCOL)


class SearchTextIndex:
    """Индекс на срещаните в пощенска кутия думи.

    Разбиването на думи и изчистването е реализирано тук без да се използват
    допълнителни пакети (например като nltk). Не е най-качественото, но за
    целта на търсене, може би, е напълно достатъчно.
    """

    def __init__(self, attrs=("Subject",), _min_len=4):
        self.index = {}
        self._attrs = attrs
        self._min_len = _min_len
        self._stop_words = set()
        # само истински думи - с букви
        self._words_split_re = '([a-zA-Zа-яА-Я]{%d,})' % self._min_len
        self._words_split_re = re.compile(self._words_split_re, re.MULTILINE | re.UNICODE)

    def save(self, file_name):
        with open(file_name, "wb") as fout:
            pickle.dump((self._attrs, self.index),
                        fout, pickle.HIGHEST_PROTOCOL)

    def read(self, file_name):
        with open(file_name, "rb") as fin:
            self._attrs, self.index = pickle.load(fin)
        log.debug(u"%s", u"прочетен е индекс за търсене с {0:,d} елемента".
                  format(len(self.index)))

    def create(self, ndb):
        self._stop_words = self._load_stop_words()
        self._process_mbox(ndb)

    def _process_mbox(self, ndb):
        start = time()
        for nx in ndb._nbt:
            if nx["typeCode"] == "NORMAL_MESSAGE":
                nid = nx["nid"]
                self._update(PropertyContext(ndb, nid), nid)
        self._sweep_analyze()
        self._debug_index()
        log.info(u"%s", u"индексирането за търсене завърши за {0:,.3f} сек.".
                 format(time()-start))

    def _update(self, pc, nid):
        for attr in self._attrs:
            text = pc.get_value_safe(attr)

            # извличане на списъка с думи
            if attr == "Subject":
                text = text[2:] if text is not None else None
            text = self._split_words(text)
            text = self._sweep_stop_worlds(text)

            # актуализиране на индекса за всяка дума
            if text is not None:
                for word in text:
                    nids = self.index.get(word, None)
                    if nids is None:
                        nids = set()
                        self.index[word] = nids
                    nids.add(nid)

    def _split_words(self, text):
        result = set()
        if text is not None:
            for word in self._words_split_re.findall(text):
                word = word.lower()
                result.add(word)
        return result

    def _sweep_stop_worlds(self, text):
        return text - self._stop_words

    @staticmethod
    def _load_stop_words():
        try:
            result = set()
            resource_fnm = "papers/stopwords.txt"
            data = get_data("readms.metapst", resource_fnm).decode('UTF-8')
            if data is not None:
                for line_ in data.splitlines():
                    line_ = line_.strip()
                    if len(line_) == 0 or line_.startswith("#"):
                        continue
                    result.add(line_)
            log.info("заредени са {0:,d} stop words".format(len(result)))
            return result
        except IOError:
            log.warning('няма файл %s', resource_fnm)
            return set()

    def _sweep_analyze(self):
        nids = set()
        for ix in self.index.values():
            nids.update(ix)
        len_nids = len(nids)
        log.debug(u"%s", u"елементи в индекса: {0:,d}".format(len(self.index)))
        log.debug(u"%s", u"индексирани съобщения: {0:,d}".format(len_nids))

        s1, s2 = set(), 0
        for nx, ix in self.index.items():
            lx = len(ix)
            if lx >= len_nids/3:  # TODO това 3 да се обоснове
                s1.add((nx, lx))
            s2 = max(s2, lx)

        log.debug("%s", u"брой неселективни думи: {0:,d}".format(len(s1)))
        if log.isEnabledFor(logging.DEBUG):
            for word, lx in s1:
                log.debug("    %s", u"{0} ({1:,d}) ({2:,.3f})".
                          format(word, lx, 1.0*lx/len_nids))
        log.debug("%s", u"най-дълъг индекс: {0:,d}".format(s2))

    def _debug_index(self):
        if log.isEnabledFor(logging.DEBUG):
            from codecs import open as open_enc
            with open_enc("search_index_debug.txt", "wb", "UTF-8") as fout:
                for ex, nids in self.index.items():
                    print(ex, nids, file=fout)
