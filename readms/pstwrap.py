# -*- coding: UTF-8 -*-
# vim:ft=python:et:ts=4:sw=4:ai

from os import path, getcwd, listdir, rmdir, unlink, fdopen, environ
from tempfile import mkdtemp, mkstemp
from configparser import ConfigParser

import logging
import logging.config

from readms.pstmbox import MboxCacheEntry


class MboxWrapper:
    """Текуща пощенска кутия.
    """

    def __init__(self):
        self.mbox = None
        self._pst_home = getcwd()
        self._index_dir = self._pst_home
        self.pst_file = None

    def open_mbox(self, pst_file):
        self.pst_file = pst_file
        if not path.isabs(pst_file):
            pst_file = path.join(self._pst_home, pst_file)
        self.mbox = MboxCacheEntry(pst_file, self._index_dir)

    def close_mbox(self):
        if self.mbox is not None:
            self.mbox.close()
        self.pst_file = None

    def set_index_dir(self, index_dir):
        self._index_dir = index_dir

    def set_pst_home(self, pst_home):
        self._pst_home = pst_home

    def init_mbox_wrapper(self, config):
        pst = config.get("app", "pstmbox_dir")
        idx = config.get("app", "pstmbox_index_dir")
        self.set_index_dir(idx)
        self.set_pst_home(pst)


class EnvConfig:
    def __init__(self):
        self.config = None
        self.last_save_dir = getcwd()

    ENV_PST_FILES_NAME = 'WXPST_OUTLOOK_FILES'

    def setup_env(self, cfg_file):
        logging.config.fileConfig(cfg_file)
        log = logging.getLogger(__name__)
        self.config = ConfigParser(defaults=dict(here=path.dirname(path.abspath(cfg_file))))
        log.info("Using config %s", cfg_file)
        self.config.read(cfg_file)
        if EnvConfig.ENV_PST_FILES_NAME in environ:
            pstmbox_dir = environ[EnvConfig.ENV_PST_FILES_NAME]
            self.config.set('app', 'pstmbox_dir', pstmbox_dir)
        log.info('Using pst_mbox_dir: %s', self.config.get('app', 'pstmbox_dir'))

    def get_option(self, section, option, default=None):
        if not self.config.has_option(section, option):
            return default
        return self.config.get(section, option)

    def get_fonts_config(self):
        font_prop = self.get_option("app", "font.prop", "Arial")
        font_mono = self.get_option("app", "font.mono", "Liberation Mono")
        font_size = self.get_option("app", "font.size", "9")
        return font_prop, font_mono, int(font_size)

    def get_fonts_html(self):
        font_html = self.get_option("app", "font.html", "7,8,9,10,11,12,14")
        return list([int(x_) for x_ in font_html.split(",")])


class TempFiles:
    def __init__(self):
        self._temp_dir = mkdtemp(prefix="wxpst_")
        self._log = logging.getLogger(__name__)

    def tempfile(self, suffix=""):
        handle, name = mkstemp(dir=self._temp_dir, suffix=suffix)
        return fdopen(handle, "wb"), name

    def write_temp(self, data, suffix=""):
        out, name = self.tempfile(suffix)
        try:
            out.write(data)
            out.flush()
        finally:
            out.close()
        return name

    def cleanup(self):
        for fnm in listdir(self._temp_dir):
            fnm = path.join(self._temp_dir, fnm)
            self._log.debug("cleanup %s", fnm)
            try:
                unlink(fnm)
            except OSError as ex:
                self._log.error(ex)
        try:
            self._log.debug("cleanup %s", self._temp_dir)
            rmdir(self._temp_dir)
        except OSError as ex:
            self._log.error(ex)


mbox_wrapper = MboxWrapper()
global_env = EnvConfig()
temp_file = TempFiles()
