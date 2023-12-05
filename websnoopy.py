#!/usr/bin/python3

import os.path
import re
import queue
import threading
from pprint import pprint
import requests
import random
import time
from bs4 import BeautifulSoup
import urllib3
import argparse
from alive_progress import alive_bar

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser(description='Grab common info about web-servers and apps.')

parser.add_argument('-p', '--project', help="Name of project (prefix for result files)", required=True)
parser.add_argument('-l', '--list', help="List of targets URLs", required=True)
parser.add_argument('-t', '--threads', help="Threads count, default 20", type=int, default=20)
args = parser.parse_args()

# TODO E-tags list separately!
# TODO normal ua, mobile UA
# TODO api 401
# TODO meta generator separate list
# TODO check form in end of redirect
THREADS_LIMIT = args.threads

IGNORE_STATUSES = [502, 503, 504, 497]
# TODO in files all of it
IGNORE_HEADERS = [
    'content-encoding', 'connection', 'date', 'Transfer-Encoding',
    'content-language',
    'Expires', 'X-Frame-Options:', 'Content-Length', 'Cache-Control',
    'Last-Modified', 'Accept-Ranges', 'ETag', 'Vary', 'X-Frame-Options',
    'X-Content-Type-Options', 'Referrer-Policy', 'X-XSS-Protection',
    'Strict-Transport-Security', 'x-accel-buffering', 'Pragma', 'Content-Security-Policy',
    'X-UA-Compatible', 'Age', 'Permissions-Policy', 'Keep-Alive',
]
IGNORE_METAS = ['keywords', 'viewport', 'mobile-web-app-capable', 'viewport',
                'theme-color', 'facebook-domain-verification', 'description', 'robots',
                'google-site-verification', 'format-detection', ]

results = []

all_titles = set()
all_headers_names = set()
all_meta_names = set()
all_cookie_names = set()
all_content_types = set()
all_servers = set()
all_powered_by = set()
all_x_headers = set()
all_codes = set()


def is_header_ignore(header_name, header_value):
    if header_name.lower() == 'content-type' and \
            re.match('^text/html(;( |)charset=([a-z0-9\-]+))*$', header_value, re.I):
        return True

    for ignore_name in IGNORE_HEADERS:
        if ignore_name.lower() == header_name.lower():
            return True

    return False


def is_meta_ignore(meta_name):
    for ignore_name in IGNORE_METAS:
        if ignore_name.lower() == meta_name.lower():
            return True
    return False


class Web(object):
    headers = None
    title = None
    description = None
    metas = None
    url = None
    code = None
    got_form = None

    def __init__(self, url, resp):

        self.headers = {}
        self.title = ""
        self.description = ""
        self.url = url
        self.metas = {}
        self.code = resp.status_code
        self.got_form = False

        self._fill_headers(resp)
        self._fill_title(resp)
        self._fill_metas(resp)
        self._fill_form(resp)

        all_titles.add(self.title)

        all_meta_names.update(self.metas.keys())
        all_codes.add(self.code)
        all_headers_names.update(self.headers.keys())
        if 'server' in self.headers.keys():
            all_servers.add(self.headers.get('server'))
        if 'x-powered-by' in self.headers.keys():
            all_powered_by.add(self.headers.get('x-powered-by'))
        for header_name in self.headers.keys():
            if not header_name.startswith('x-'):
                continue
            all_x_headers.add(header_name)
        if 'content-type' in self.headers.keys():
            all_content_types.add(self.headers.get('content-type'))

        all_cookie_names.update(resp.cookies.keys())

    def _fill_form(self, resp):
        self.got_form = "<form " in resp.text.lower() or \
                        "<form>" in resp.text.lower()

    def _fill_title(self, resp):
        tmp = re.findall("<title>(.+?)</title>", resp.text, re.I)
        if not len(tmp):
            return
        self.title = tmp[0]

    def _fill_headers(self, resp):
        for header_name in resp.headers.keys():
            header_value = resp.headers.get(header_name)
            if is_header_ignore(header_name, header_value):
                continue
            self.headers[header_name.lower()] = header_value.lower()

    def _fill_metas(self, resp):
        soup = BeautifulSoup(resp.text, "lxml")
        metas = soup.find_all("meta")
        for meta in metas:
            if meta.get('charset') is not None:
                continue

            if meta.get('http-equiv') is not None and \
                    meta.get('http-equiv').lower() in ['content-type',
                                                       'x-ua-compatible', 'pragma',
                                                       'content-security-policy', 'refresh',
                                                       'cache-control', 'content-language',
                                                       'content-script-type',
                                                       'MobileOptimized',
                                                       'apple-mobile-web-app-status-bar-style',
                                                       'apple-mobile-web-app-title',
                                                       'color-scheme']:  # TODO чище, мб с хедерами объединить?
                continue

            meta_name = meta.get('name')
            if meta_name is None:
                meta_name = meta.get('property')

            if meta_name is None:
                meta_name = "META_WITHOUT_NAME"

            if is_meta_ignore(meta_name):
                continue

            self.metas[meta_name] = {
                'name': meta_name,
                'value': meta.get('content'),
                'source': str(meta),
            }

    def __str__(self):
        s = ""
        s += "================== {0} ====================\n".format(self.url)
        s += "Code: {0}\n".format(self.code)

        if len(self.title):
            s += "Title: {0}\n".format(self.title)

        if len(self.description):
            s += "Description: {0}\n".format(self.description)

        if self.got_form:
            s += "Form: YES\n"

        if len(self.headers):
            s += "Headers:\n"
            for h in self.headers:
                s += "\t{0}: {1}\n".format(h, self.headers[h])

        s += "\n"

        if len(self.metas):
            s += "Meta:\n"
            for meta_name in self.metas:
                s += "\t{0}: {1} ({2})\n".format(
                    meta_name, self.metas[meta_name]['value'], self.metas[meta_name]['source'])

        return s


def is_it_http_req_to_https(resp):
    if resp.status_code != 400:
        return False

    phrases = ['The plain HTTP request was sent to HTTPS port',
               'speaking plain HTTP to an SSL-enabled']
    for phrase in phrases:
        if phrase not in resp.text:
            continue
        return True

    return False


class Worker(threading.Thread):
    daemon = True

    def run(self) -> None:
        while True:
            try:
                url = q.get(False)
                bar()
                try:
                    resp = requests.get(
                        url,
                        verify=False,
                        timeout=3,
                        headers={'User-Agent': 'Mozilla/5.0'},
                        allow_redirects=False)

                    if resp.status_code in IGNORE_STATUSES or \
                            is_it_http_req_to_https(resp):
                        continue

                    web = Web(url, resp)
                    results.append(web)
                except BaseException as e:
                    # print("Exception: {0} => {1}".format(e, url))
                    pass
            except queue.Empty:
                break
            except BaseException as e:
                # print("Exception: {0} => {1}".format(e, url))
                pass
            # TODO debug param in config.ini for show exceptions


targets = []
for line in open(args.list):
    line = line.strip()
    if not len(line):
        continue
    targets.append(line)

random.shuffle(targets)
q = queue.Queue()
for t in targets:
    q.put(t)

with alive_bar(q.qsize()) as bar:
    pool = []
    for _ in range(THREADS_LIMIT):
        w = Worker()
        w.start()
        pool.append(w)

    stime = int(time.time())
    is_alive = True
    while is_alive:
        is_alive = False

        for w in pool:
            if w.is_alive():
                is_alive = True
                break

        time.sleep(1)

if not os.path.exists(args.project):
    os.mkdir(args.project)

# TODO separate thread here? Data may lost on crash
with open(args.project + "/websnoopy.log", "w") as fh:
    for result in results:
        fh.write(str(result) + "\n")

with open(args.project + "/titles.log", "w") as fh:
    fh.write("\n".join(sorted(all_titles)))
with open(args.project + "/headers-names.log", "w") as fh:
    fh.write("\n".join(sorted(all_headers_names)))
with open(args.project + "/x-headers.log", "w") as fh:
    fh.write("\n".join(sorted(all_x_headers)))
with open(args.project + "/powered-by-headers.log", "w") as fh:
    fh.write("\n".join(sorted(all_powered_by)))
with open(args.project + "/server-headers.log", "w") as fh:
    fh.write("\n".join(sorted(all_servers)))
with open(args.project + "/content-types.log", "w") as fh:
    fh.write("\n".join(sorted(all_content_types)))
with open(args.project + "/metas-names.log", "w") as fh:
    fh.write("\n".join(sorted(all_meta_names)))
with open(args.project + "/cookie-names.log", "w") as fh:
    fh.write("\n".join(sorted(all_cookie_names)))
with open(args.project + "/codes.log", "w") as fh:
    fh.write("\n".join(
        list(map(str, sorted(all_codes))))
    )

# all_codes = set()

print("Done. Look results in ./" + args.project)

# TODO mark upload forms
# TODO игнорим text/html;charset=*, а не как сейчас
# TODO детект формы работает не правильно
# TODO список всех урлов с формами
# TODO список всех предположительных апи
# TODO листинги/трейсы - отдельные списки
# TODO запрос не только с разными юзерагентами, но и разные контент-тайпы - будет ли меняться CT ответа?, XHR-req header
# TODO большой список og: meta - взять из AJ + apple-mobile-web-status + msapplication
# TODO .api. в имени хоста - апи флаг
# TODO threads in params
# TODO urls lists by codes like urls-500.txt
