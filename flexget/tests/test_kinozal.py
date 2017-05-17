from __future__ import unicode_literals, division, absolute_import
from builtins import *  # noqa pylint: disable=unused-import, redefined-builtin

import pytest

from flexget.plugins.sites.kinozal import *


class Test_Kinozal(object):

    @pytest.mark.online
    def test_get_item_id(self):
        link = 'https://kinozal-tv.appspot.com/details.php?l1ZjAx&id=1535337'
        expected_id = '1535337'
        k = Kinozal()
        id = k.get_item_id(link)
        assert expected_id == id