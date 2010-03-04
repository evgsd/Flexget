import urllib
import urllib2
import logging
from plugin_urlrewriting import UrlRewritingError
from flexget.plugin import *
from flexget.utils.soup import get_soup
import difflib

log = logging.getLogger('piratebay')


class UrlRewritePirateBay:
    """PirateBay urlrewriter."""

    # urlrewriter API
    def url_rewritable(self, feed, entry):
        url = entry['url']
        if url.endswith('.torrent'):
            return False
        if url.startswith('http://thepiratebay.org/'):
            return True
        if url.startswith('http://torrents.thepiratebay.org/'):
            return True
        return False
        
    # urlrewriter API
    def url_rewrite(self, feed, entry):
        if entry['url'].startswith('http://thepiratebay.org/search/'):
            # use search
            try:
                entry['url'] = self.search_title(entry['title'])
            except PluginWarning, e:
                raise UrlRewritingError(e)
        else:
            # parse download page
            entry['url'] = self.parse_download_page(entry['url'])

    @internet(log)
    def parse_download_page(self, url):
        page = urllib2.urlopen(url)
        try:
            soup = get_soup(page)
            tag_div = soup.find('div', attrs={'class': 'download'})
            if not tag_div:
                raise UrlRewritingError('Unable to locate download link from url %s' % url)
            tag_a = tag_div.find('a')
            torrent_url = tag_a.get('href')
            return torrent_url
        except Exception, e:
            raise UrlRewritingError(e)    
            
    # search API
    def search(self, feed, entry):
        url = self.search_title(entry['title'])
        log.debug('search got %s' % url)
        return url

    @internet(log)
    def search_title(self, name, url=None):
        """
            Search for name from piratebay.
            If optional search :url: is passed it will be used instead of internal search.
        """
        
        name = name.replace('.', ' ').lower()
        if not url:
            url = 'http://thepiratebay.org/search/' + urllib.quote(name)
            log.debug('Using %s as piratebay search url' % url)
        page = urllib2.urlopen(url)
        
        soup = get_soup(page)
        torrents = []
        possibilities = {}
        for link in soup.findAll('a', attrs={'class': 'detLink'}):
            # dict of {linktextlowered: linkobj}
            possibilities[link.contents[0].lower()] = link
        # Get the closest 5 (or less) matches to the torrent name, with a confidence of at least 0.9
        matches = difflib.get_close_matches(name.lower(), possibilities.keys(), n=5, cutoff=0.9)
        log.debug('found %i matches. Matches are: %s' % (len(matches), str(matches)))
        for linktext in matches:
            # simpler to just use difflib.get_close_matches like above for what we're doing
            ## assign confidence score of how close this link is to the name you're looking for. .6 and above is "close"
            #confidence = difflib.SequenceMatcher(lambda x: x in ' -._', # junk characters
            #                           link.contents[0].lower(),
            #                           name.lower()).ratio()
            #log.debug('name: %s' % name.lower())
            #log.debug('found name: %s' % link.contents[0].lower())
            #log.debug('confidence: %s' % str(confidence))
            #if confidence < 0.9:
            #    continue
            link = possibilities[linktext]
            torrent = {}
            torrent['name'] = link.contents[0]
            torrent['link'] = 'http://thepiratebay.org' + link.get('href')
            tds = link.parent.parent.parent.findAll('td') 
            torrent['seed'] = int(tds[-2].contents[0])
            torrent['leech'] = int(tds[-1].contents[0])
            torrents.append(torrent)
            
        if not torrents:
            raise PluginWarning('No close matches for %s' % name, log, log_once=True)
            
        def best(a, b):
            score_a = a['seed'] * 2 + a['leech']
            score_b = b['seed'] * 2 + b['leech']
            return cmp(score_a, score_b)

        torrents.sort(best)
        torrents.reverse()

        #for torrent in torrents:
        #    log.debug('%s link: %s' % (torrent, torrent['link']))

        return str(torrents[0]['link'])

register_plugin(UrlRewritePirateBay, 'piratebay', groups=['urlrewriter', 'search'])
