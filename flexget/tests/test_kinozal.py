from __future__ import unicode_literals, division, absolute_import
from builtins import *  # noqa pylint: disable=unused-import, redefined-builtin

import pytest

from flexget.plugins.sites.kinozal import *


class Test_Kinozal(object):

    def setup(self):
        self.link = 'https://kinozal-tv.appspot.com/details.php?l1ZjAx&id=1535337'

    @pytest.mark.online
    def test_get_item_id_success(self):
        expected_id = '1535337'
        k = Kinozal()
        id = k.get_item_id(self.link)
        assert expected_id == id

    @pytest.mark.online
    def test_rewrite_link_success(self):
        expected_link = 'https://kinozal-tv.appspot.com/dl./download.php?id=1535337'
        k = Kinozal()
        rewrited_link = k.rewrite_download_url(self.link)
        assert rewrited_link == expected_link

    @pytest.mark.online
    def test_rewrite_link_failed(self):
        k = Kinozal()
        rewrited_link = k.rewrite_download_url(self.link)
        assert rewrited_link != self.link

    @pytest.mark.online
    def test_rewrite_link_none(self):
        k = Kinozal()
        rewrited_link = k.rewrite_download_url(None)
        assert rewrited_link is None
