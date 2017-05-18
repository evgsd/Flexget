# -*- coding: utf-8 -*-

from __future__ import unicode_literals, division, absolute_import
from builtins import *

import logging
import json
import re

import feedparser
import requests

from time import sleep
from datetime import datetime, timedelta

from sqlalchemy import Column, Unicode, Integer, DateTime
from sqlalchemy.types import TypeDecorator, VARCHAR

from flexget import plugin
from flexget.entry import Entry
from flexget.event import event
from flexget.plugin import PluginError
from flexget.db_schema import versioned_base
from flexget.utils.requests import RequestException
from flexget.utils.soup import get_soup
from flexget.manager import Session

from requests import Session as RSession
from requests.auth import AuthBase
from requests.utils import dict_from_cookiejar

__author__ = 'evgsd'
__plugin_name__ = 'kinozal'

log = logging.getLogger(__plugin_name__)
Base = versioned_base(__plugin_name__, 0)

ID_MATCH = re.compile('(?<=id=)\d+')
QUALITY_MATCH = re.compile('\d+\w|\w+-?\w+')
NAME_MATCH = re.compile('\(.*\)')

MIRRORS = ['https://kinozal-tv.appspot.com',
           'http://kinozal.tv',
           'http://kinozal.me']


def update_base_url():
    url = None
    for mirror in MIRRORS:
        try:
            s = RSession()
            response = s.get(mirror, timeout=2)
            if response.ok:
                url = mirror
                break
        except RequestException as err:
            log.debug('Connection error. %s', str(err))

    if url:
        return url
    else:
        raise PluginError('Host unreachable.')


class JSONEncodedDict(TypeDecorator):
    """Represents an immutable structure as a json-encoded string.

    Usage:

        JSONEncodedDict(255)

    """

    impl = VARCHAR

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = json.dumps(value)

        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = json.loads(value)
        return value


class KinozalAccount(Base):
    __tablename__ = 'kinozal_accoounts'
    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    login = Column(Unicode, index=True)
    cookies = Column(JSONEncodedDict)
    expiry_time = Column(DateTime)


class KinozalAuth(AuthBase):
    def __init__(self, login, password, cookies=None, db_session=None):
        self.base_url = update_base_url()
        if cookies is None:
            log.debug('kinozal cookie not found. Requesting new one')
            payload = {'username': login, 'password': password, 'returnto': ''}
            self.cookies = self.try_authenticate(payload)
            if db_session:
                db_session.add(
                    KinozalAccount(
                        login=login, cookies=dict_from_cookiejar(
                            self.cookies),
                        expiry_time=datetime.now() + timedelta(days=1)))
                db_session.commit()
            else:
                raise ValueError('db_session can not be None if cookies is None')
        else:
            log.debug('Using previously saved cookie')
            self.cookies = cookies

    def try_authenticate(self, payload):
        for _ in range(5):
            s = RSession()
            s.post('{}/takelogin.php'.format(self.base_url), data=payload)
            if s.cookies and len(s.cookies) > 0:
                return s.cookies
            else:
                sleep(3)
        raise PluginError('unable to obtain cookies from kinozal')


class Kinozal(object):
    """Usage:

    kinozal:
      username: 'username_here'
      password: 'password_here'
    """
    schema = {'type': 'object',
              'properties': {
                  'username': {'type': 'string'},
                  'password': {'type': 'string'}
              },
              'additionalProperties': False}

    auth_cache = {}

    def __init__(self):
        self.base_url = update_base_url()

    def get_item_id(self, link):
        id = ID_MATCH.findall(link)[0]
        return id

    def get_item_full_title(self, item):
        id = self.get_item_id(item.link)
        if id is not None:
            url = '{}/details.php?id={}'.format(self.base_url, id)
            r = requests.get(url)
            if r.ok:
                content = r.text
                soup = get_soup(content)
                full_title = soup.h1.text
                if full_title is not None:
                    item.title = full_title

    def get_feed(self, url):
        try:
            rss = feedparser.parse(url)
        except:
            raise PluginError('Can\'t parse rss feed.')
        if rss.get('status') and rss.get('status') != 200:
            raise RequestException('Receive not (OK) 200 status')
        if rss.get('bozo') == 1:
            log.error('Bozo error found ({}). Trying decode feed manualy.'.format(rss.get('bozo_exception')))
            decoded_feed = self.decode_feed(url)
            return self.get_feed(decoded_feed)
        return rss

    def decode_feed(self, feed_url):
        r = requests.get(feed_url)
        if not r.ok:
            raise RequestException('Can\'t get feed.')
        try:
            feed = r.content.decode('utf-8', 'ignore')
        except Exception as e:
            raise PluginError('Can\'t uncode feed. {}'.format(e))
        return feed

    def on_task_input(self, task, config):
        url = '{}/rss.xml'.format(MIRRORS[0])
        feed = self.get_feed(url)
        entries = list()
        for item in feed.entries:
            if item.title.endswith('...'):
                self.get_item_full_title(item)

            title_arr = list(map(str.strip, item.title.split('/')))

            name_rus = NAME_MATCH.sub('', title_arr[0]).strip()
            name_eng = NAME_MATCH.sub('', title_arr[1]).strip()
            quality = QUALITY_MATCH.findall(title_arr[-1])
            quality_str = '.'.join(quality)

            new_title = '.'.join([name_eng, __plugin_name__, quality_str, 'torrent']).replace(' ', '.')

            entry = Entry()
            entry['url'] = item.link
            entry['title'] = new_title
            entry['series_name_rus'] = name_rus
            entry['series_name_eng'] = name_eng
            entries.append(entry)

        return entries

    @staticmethod
    def try_find_cookie(db_session, username):
        account = db_session.query(KinozalAccount).filter(
            KinozalAccount.login == username).first()
        if account:
            if account.expiry_time < datetime.now():
                db_session.delete(account)
                db_session.commit()
                return None
            return account.cookies
        else:
            return None


@event('plugin.register')
def register_plugin():
    plugin.register(Kinozal, __plugin_name__, api_ver=2)