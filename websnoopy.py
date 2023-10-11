#!/usr/bin/python3

import re
import queue
import threading
import sys
import requests
import random
import time
from bs4 import BeautifulSoup
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#TODO E-tags list separately!
#TODO normal ua, mobile UA
#TODO api 401
#TODO check form in end of redirect
THREADS_LIMIT = 5

IGNORE_STATUSES = [502, 503, 504, 497]
#TODO in files all of it
IGNORE_HEADERS = [
    'content-encoding', 'connection', 'date', 'Transfer-Encoding',
    'Expires', 'X-Frame-Options:', 'Content-Length', 'Cache-Control',
    'Last-Modified', 'Accept-Ranges', 'ETag', 'Vary', 'X-Frame-Options',
    'X-Content-Type-Options', 'Referrer-Policy', 'X-XSS-Protection',
    'Strict-Transport-Security', 'x-accel-buffering', 'Pragma', 'Content-Security-Policy',
    'X-UA-Compatible', 'Age', 'Permissions-Policy', 'Keep-Alive',
]
IGNORE_METAS = ['keywords', 'viewport', 'mobile-web-app-capable', 'viewport', 'theme-color',
                'facebook-domain-verification', 'description', 'robots', 'google-site-verification',
                'format-detection',]

results = []


def is_header_ignore(header_name, header_value):
    if header_name.lower() == 'content-type' and header_value.lower() in \
            ["text/html", "text/html; charset=utf-8", "text/html; charset=utf8"]:
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
            self.headers[header_name] = header_value

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
                                                       'content-script-type']: #TODO чище, мб с хедерами объединить?
                continue

            meta_name = meta.get('name')
            if meta_name is None:
                meta_name = meta.get('property')

            if meta_name is None:
                print("Meta without name! " + str(meta))
                exit(0) #TODO in log, показать в конце работы

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

        if self:
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


class Worker(threading.Thread):
    daemon = True

    def run(self) -> None:
        while True:
            try:
                url = q.get(False)
                try:
                    resp = requests.get(
                        url, verify=False, timeout=3, headers={'User-Agent': 'Mozilla/5.0'},
                    allow_redirects=False)

                    if resp.status_code in IGNORE_STATUSES:
                        continue
                    web = Web(url, resp)
                    results.append(web)
                except BaseException as e:
                    # print("Exception: {0} => {1}".format(e, url))
                    pass
            except queue.Empty:
                break
            except BaseException as e:
                print("Exception: {0} => {1}".format(e, url))
                pass


targets = []
for line in open(sys.argv[1]):
    line = line.strip()
    if not len(line):
        continue
    targets.append(line)

random.shuffle(targets)
q = queue.Queue()
for t in targets:
    q.put(t)

print("Targets: {0}".format(q.qsize()))

start_q_size = q.qsize()
pool = []
for _ in range(THREADS_LIMIT):
    w = Worker()
    w.start()
    pool.append(w)

is_alive = True
while is_alive:
    is_alive = False

    for w in pool:
        if w.is_alive():
            is_alive = True
            break

    time.sleep(10)
    print("Targets left: {0}".format(q.qsize()))

#TODO separate thread here? Data may lost on crash
with open("websnoopy.log", "w") as fh:
    for result in results:
        fh.write(str(result) + "\n")

print("Done")
#TODO mark upload forms