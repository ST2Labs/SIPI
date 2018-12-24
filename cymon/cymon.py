#
# ---
# Cymon.io
# Code from_: https://github.com/eSentire/cymon-python
# Modify by @Julian J Gonzalez / ST2Labs

import json
import requests
from urllib import quote_plus


class Cymon(object):

    def __init__(self, auth_token=None,
                                endpoint='https://cymon.io:443/api/nexus/v1'):
        self.endpoint = endpoint
        self.session = requests.Session()
        self.session.headers = {
            'content-type': 'application/json',
            'accept': 'application/json',
        }
        if auth_token:
            self.session.headers.update(
                         {'Authorization': 'Token {0}'.format(auth_token)})

    def get(self, method, params=None):
        r = self.session.get(self.endpoint + method, params=params)
        r.raise_for_status()
        return r

    def post(self, method, params, headers=None):
        r = self.session.post(self.endpoint + method, data=json.dumps(params),
                                                             headers=headers)
        r.raise_for_status()
        return r

    def ip_lookup(self, ip_addr):
        r = self.get('/ip/' + ip_addr)
        return r.json()

    def ip_events(self, ip_addr):
        r = self.get('/ip/' + ip_addr + '/events')
        return r.json()

    def ip_domains(self, ip_addr):
        r = self.get('/ip/' + ip_addr + '/domains')
        return r.json()

    def ip_urls(self, ip_addr):
        r = self.get('/ip/' + ip_addr + '/urls')
        return r.json()

    def domain_lookup(self, name):
        r = self.get('/domain/' + name)
        return r.json()

    def url_lookup(self, location):
        r = self.get('/url/' + quote_plus(location))
        return r.json()

    def ip_blacklist(self, tag, days=1, limit=10, offset=10):
        # supported tags: malware, botnet, spam, phishing, dnsbl, blacklist
        r = self.get('/blacklist/ip/' + tag + '/?days=%d' % (days) +
                                          '&limit=%d' % (limit) +
                                          '&offset=%d' % (offset))
        return r.json()

    def domain_blacklist(self, tag, days=1, limit=15, offset=10):
        # supported tags: malware, botnet, spam, phishing, dnsbl, blacklist
        r = self.get('/blacklist/domain/' + tag + '/?days=%d' % (days) +
                                          '&limit=%d' % (limit) +
                                          '&offset=%d' % (offset))
        return r.json()
