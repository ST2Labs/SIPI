"""
Copyright 2015 Julian J. Gonzalez | SVTCloudSecurity
www.st2labs.com | @ST2Labs | @rhodius | @seguridadxato2

__Author__: Julian J. GOnzalez
__Version__: 0.1


This is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 2 of the License.

This is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along it; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

SOC Manager
MSOC Security Team at @SVTCloud
www.svtcloud.com
"""
import sys
import os
import argparse
import shodan
sys.path.insert(0, str(os.path.dirname(
                       os.path.abspath(__file__)) +
                       os.path.sep + 'cymon' + os.path.sep))
from cymon import Cymon

__author__ = "\n   Julian J. Gonzalez Caracuel - @rhodius\n"
__version__ = "   Version: 0.1\n"
__team__ = "MSOC / CybeSecurity TEAM: 0.1\n"
__title__ = '\n   [[@SVTCloud] Simple IP Information Tool [[@st2labs]]\n'
__description__ = '''
     sIPi - is a free reconnaissance tool for obtain IP Address Information from
     many Open Sources: cymon.io | shoda.io | ipinfo.io
'''
__banner__ = '''
   _______ _____  _____  _____
   |______   |   |_____]   |
   ______| __|__ |       __|__
   ---------------------------
'''

__credit__ = ((__banner__ + __title__ + __description__ +
               __author__ + __version__))


def usage():
    print ('''

   Use:
       sipi <Host or Host List> <options>
   Info:
       sipi -h
    ''')


def validIPv4(ip):
    import re
    v = False
    if re.match(r'^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$', ip):
        v = True
    return v


def decode_data(data):

    import json

    n_dict = {}
    a_dict = json.loads(data)
    for key, value in list(a_dict.items()):
        nkey = key.encode('utf-8')
        if isinstance(value, int):
            nvalue = value
        else:
            if value is not None:
                nvalue = value.encode('utf-8')
            else:
                nvalue = value
        n_dict[nkey] = nvalue
    return n_dict


def error(index):

    if index == 1:
        msg = '\n'
        msg += '    Error IP format. Must be like 192.168.0.1 \n'
        msg += '    Try again\n'
        print ((__credit__ + msg))
    elif index == 2:
        msg = '\n'
        msg += '    Format Fileconfig it''s not support it.'
        msg += '    Need valid JSON encoded\n'
        msg += '    Try again\n'
        print ((__credit__ + msg))
    elif index == 3:
        msg = '\n'
        msg += '    Error config.json not exits it.\n'
        msg += '    Try again\n'
        print ((__credit__ + msg))


def show_result(data_):
    print ((__credit__))
    sys.stdout.write(' \n')
    sys.stdout.write(' \n')
    for item in data_:
        print (('   -  ' + str(item)))
    sys.stdout.write(' \n')


def show_info(data_):

    try:
        res_ = []
        res_.append('')
        res_.append('++++++++++++++++++++++++++++++++++++++')
        res_.append('+ Info obtain from: http://ipinfo.io +')
        res_.append('++++++++++++++++++++++++++++++++++++++')
        res_.append('')
        if not data_:
            res_.append(' No results')
            res_.append(' Only a private range IP detected ')
            return
        for i in data_:
            # i is dict
            if 'ip' in i:
                res_.append('ip: ' + str(i['ip']))
            if 'hostname' in i:
                res_.append('hostname: ' + str(i['hostname']))
            if 'city' in i:
                res_.append('city: ' + str(i['city']))
            if 'region' in i:
                res_.append('region: ' + str(i['region']))
            if 'country' in i:
                res_.append('country: ' + str(i['country']))
            if 'org' in i:
                res_.append('org: ' + str(i['org']))
            if 'gps' in i:
                res_.append('gps: ' + str(i['loc']))
            res_.append('++++++++++++++++++++++++++++++++++++++ ')
            res_.append('')
        return res_
    except Exception as e:
        print (('  Error Searching IPInfo Data {}'.format(e)))


def ipinfo(iplist):
    import requests

    try:
        hostlist = []
        ipinfolist = []
        if type(iplist) is not list:
            hostlist.append(iplist)
        else:
            hostlist = iplist

        for ip in hostlist:
            req_ = 'http://ipinfo.io/' + ip
            r = requests.get(req_)
            info_ = r.json()
            ipinfolist.append(info_)

        return ipinfolist
    except Exception as e:
        print (('   Error looking for IP Info: {}'.format(e)))


def getModeCode(modo):

    # Default ip_blacklist
    v = 1
    if modo == 'ip_events':
        v = 2
    return v


def search(api, iplist, cat, day, limit, modo='ip_blacklist'):

    try:
        res_ = []
        res_.append('')
        res_.append('++++++++++++++++++++++++++++++++++++++')
        res_.append('+ Info obtain from: http://cymon.io  +')
        res_.append('+     Checking for {}        '.format(modo))
        res_.append('++++++++++++++++++++++++++++++++++++++')
        res_.append('')
        hostlist = []
        catlist = []
        if type(iplist) is not list:
            hostlist.append(iplist)
        else:
            hostlist = iplist
        #
        # Preparada para utilizar la misma funcion search
        # para IP event / IP Blacklist
        # cmodo = 1 ip_blacklist
        # cmodo = 2 ip_events

        cmodo = getModeCode(modo)

        if type(cat) is not list:
            catlist.append(cat)
        else:
            catlist = cat
        f = getattr(api, modo)

        if cmodo == 1:

            for item in catlist:
                res_.append('')
                res_.append('+--------------------------+')
                res_.append('+-Category:{}'.format(item))
                res_.append('+--------------------------+')
                res_.append('')
                iplistnotfound = []
                r = f(item, day, limit)
                for ip in hostlist:
                    ip_found = False
                    for elem in r['results']:
                        if ip in elem['addr']:
                            ip_found = True
                    if ip_found:
                        res_.append(str('  [FOUND] IP {0} found in {1}' +
                                  'BlackList').format(ip, item))
                        r = api.ip_lookup(ip)['sources']
                        res_.append('  From: {} ->'.format(r))
                        res_.append('')
                    else:
                        iplistnotfound.append(ip)
                res_.append(str('  IPs {0} [NOT_FOUND] ' +
                          ' in CATEGORY:{1}').format(iplistnotfound, item))
                res_.append(str('  [!] Try search with -d 4' +
                          ' options'))
                res_.append('')
        elif cmodo == 2:

            for ip in hostlist:
                taglistnotfound = []
                r = f(ip)
                res_.append('')
                res_.append('+---------------------------------+')
                res_.append('+-Events for IP:{}'.format(ip))
                res_.append('+---------------------------------+')
                res_.append('')
                for item in catlist:
                    tag_found = False
                    for elem in r['results']:
                        if item in elem['tag']:
                            tag_found = True
                    if tag_found:
                        res_.append('  +--')
                        res_.append('')
                        res_.append(str('  [!] IP {0} found in {1}' +
                                  ' BlackList').format(ip, item))
                        s = api.ip_lookup(ip)['sources']
                        res_.append('  Detected by: {}'.format(s))
                        res_.append('')
                        res_.append('  --+')
                        res_.append('')
                    else:
                        taglistnotfound.append(item)
                res_.append(str('  [NOT_FOUND] IP {0} ' +
                                  ' in this CATEGORIES:{1}' +
                                  ' ').format(ip, taglistnotfound))
                res_.append('')
        return res_
    except Exception as e:
        import traceback
        print ("    CYMON API Error_: ")
        print (('    msg_ {}'.format(e)))
        print (("    {}".format(traceback.print_tb(sys.exc_info()[2]))))
        print ('')
        sys.exit(2)


def saveOnFile(data_, filepath):

    if os.path.isfile(filepath):
        print ((str('  [!] File {} exists, please choose' +
                'other filename').format(filepath)))
        print ('')
        print ('      >> Results not save on filename!')
        sys.exit(2)

    with open(filepath, 'ab+') as f:
        for element in data_:
            f.write(str(element) + '\r\n')
        f.close()


def loadSetting(filepath):
    import json
    try:
        with open(filepath, 'rb') as f:
            d = json.loads(f.read())
            return d
    except TypeError:
        error(2)
        sys.exit(2)
    except ValueError:
        error(2)
        sys.exit(2)


def search_shodan(api, iplist):
    try:
        hostlist = []
        ipnotdatalist = []
        res_ = []
        res_.append('')
        res_.append('++++++++++++++++++++++++++++++++++++++')
        res_.append('+ Info obtain from: http://shodan.io +')
        res_.append('++++++++++++++++++++++++++++++++++++++')
        res_.append('')

        if type(iplist) is not list:
            hostlist.append(iplist)
        else:
            hostlist = iplist
        for ip in hostlist:
            try:
                host = api.host(ip)
            except shodan.APIError as e:
                ipnotdatalist.append(ip)
                continue

            if host:
                # Print general info
                res_.append('')
                res_.append('+-------------------------------------+')
                res_.append('+- SHODAN Info for IP:{}'.format(ip))
                res_.append('+-------------------------------------+')
                res_.append('')

                for item in sorted(host):
                    if ((item != 'data' and
                         item != 'region_code' and
                         item != 'area_code' and
                         item != 'country_code3' and
                         item != 'dma_code' and
                         item != 'ports' and
                         item != 'postal_code')):

                        res_.append('{}: {}'.format(item, host[item]))

                # Print all banners
                res_.append('')
                res_.append('+- Service Info')
                res_.append('+')
                res_.append('   Ports detected: {}'.format(host['ports']))
                res_.append('')

                for item in host['data']:

                        res_.append('Port: {}'.format(item['port']))
                        res_.append('Protocol: {}/{}'.format(
                                                item['transport'],
                                                item['_shodan']['module']))
                        banner = item['data'].splitlines()
                        msg = ''
                        for line in banner:
                            msg += line + ' '
                        res_.append('Banner: {}'.format(msg))
                res_.append('')
        res_.append(str('  [!] IPs with not Information found ' +
                            ' in SHODAN:{}').format(ipnotdatalist))
        return res_
    except Exception as e:
        print (('Search_shodan_ Error: %s' % e))


def main(argv):

    try:
        info_ = []
        parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description='')

        ogroup = parser.add_argument_group(title='Output')
        maingroup = parser.add_argument_group(title='Main Functions')
        shodangroup = parser.add_argument_group(title='SHODAN Functions')
        cygroup = parser.add_argument_group(title='CYMON.io Funtions')
        maingroup.add_argument('host',
                               help='Input IP or IP list file')
        shodangroup.add_argument('-s',
                               '--shodan',
                               help=''' Search IP in SHODAN engine''',
                               action='store_true'
                               )
        g1 = cygroup.add_mutually_exclusive_group(required=True)

        g1.add_argument('-A',
                        '--all',
                        help=''' Search Blacklist IP in 3 days ago
                         with 100 max result, use -d & -l to increment it
                         in ALL Categories ''',
                        action='store_true'
                        )
        g1.add_argument('-t',
                            '--cat',
                            default=None,
                            help=''' Default: spam | Add one of this Category:
malware botnet spam phishing malicious activity blacklist dnsbl
''',
                            metavar='SPAM'
                            )
        ogroup.add_argument('-o',
                            '--output',
                            default=None,
                            help='''Output filename or Directory''',
                            metavar='FILE'
                            )
        maingroup.add_argument('-i',
                            '--info',
                            default=None,
                            help='''IP Information data from ipinfo.io''',
                            action='store_true'
                            )
        cygroup.add_argument('-d',
                            '--days',
                            type=int,
                            default=3,
                            help='''Looking for days <1-3> ago in Blacklist
                            IP Mode, use 4 to active mode security events
                            list | Default mode is 3 days ago'''
                            )
        cygroup.add_argument('-l',
                            '--limit',
                            type=int,
                            default=100,
                            help='''Result limit <Max> in Security
                            Event list IP | Default limit is 100'''
                            )

        args = parser.parse_args()
        _shodan = args.shodan
        _host = args.host
        _outname = args.output
        _category = args.cat
        _all = args.all
        _info = args.info
        _isfile = False
        _days = args.days
        _limit = args.limit
        _out = False

        cymon_cat = ['malware',
                     'botnet',
                     'spam',
                     'phishing',
                     'malicious activity',
                     'blacklist',
                     'dnsbl']

        if not validIPv4(_host):
            if os.path.isfile(_host):
                _isfile = True
            else:
                error(1)
                sys.exit(2)

        if _outname is not None:
            _out = True
            if os.path.isabs(_outname):
                _fpathOut = _outname
            else:
                _fpathOut = str(os.path.dirname(
                                os.path.abspath(sys.argv[0])) +
                                os.sep +
                                _outname)

        hostlist = []
        if _isfile:
            with open(_host, 'rb') as f:
                iplist = []
                ipnotvalidlist = []
                hostlist = f.read().splitlines()
                for ip in hostlist:
                    if validIPv4(ip):
                        iplist.append(ip)
                    else:
                        ipnotvalidlist.append(ip)
                info_.append((str('[!] This IP {} is not valid' +
                                  ' & have been removed from ' +
                                  'searching').format(ipnotvalidlist)))
                info_.append('')
                hostlist = iplist
        else:
            hostlist = _host

        default_file = 'config.json'
        if os.path.isfile(default_file):
            conf = loadSetting(default_file)
            c_token = conf['cymon']['token']
            s_token = conf['shodan']['token']
        else:
            error(3)
            sys.exit(2)

        api = Cymon(c_token)

        cat = 'spam'
        if _category:
            cat = _category

        mode = 'ip_blacklist'
        if (_days >= 4):
            info_.append('')
            info_.append('[!] If days more than 3, auto change mode is active')
            info_.append('    [ip_blacklist > ip_events] to obtain Ip Info')
            info_.append('')
            mode = 'ip_events'

        if _all:
            cat = cymon_cat

        r = search(api, hostlist, cat, _days, _limit, mode)

        if _shodan:
            sapi = shodan.Shodan(s_token)
            rs = search_shodan(sapi, hostlist)
            if rs is None:
                rs = []
                rs.append(' Main_: Shodan Error')

        if _info:
            ipl = ipinfo(hostlist)
            ri = show_info(ipl)
            if ri is None:
                ri = []
                ri.append(' IPInfo Error')

        all_result = info_

        if _shodan and _info:
            all_result += list(r + rs + ri)
        elif _shodan:
            all_result += list(r + rs)
        elif _info:
            all_result += list(r + ri)
        else:
            all_result += r

        if _out:
            saveOnFile(all_result, _fpathOut)

        show_result(all_result)

    except Exception:
        import traceback
        print (("    Main Error_: "))
        print (("    {}".format(traceback.print_tb(sys.exc_info()[2]))))
        print ('')
        sys.exit(2)


if __name__ == "__main__":

    try:
        if len(sys.argv) > 1:
            main(sys.argv[1:])
        else:
            print ((__credit__))
            usage()
    except KeyboardInterrupt:
            sys.exit(2)
    except Exception as e:
        import traceback
        print ('Somethin was wrong ...')
        print ((("Error> {}").format(e)))
        print (("    {}".format(traceback.print_tb(sys.exc_info()[2]))))