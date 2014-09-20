# encoding: utf-8

from __future__ import unicode_literals

import json
import sys
import urllib

from binascii import hexlify, unhexlify
from email.utils import formatdate
from hashlib import sha256
from tornado import gen
from tornado.httpclient import AsyncHTTPClient, HTTPRequest

log = __import__('logging').getLogger(__name__)


if sys.version_info[0] >= 3:
    unistr = str
else:
    unistr = unicode


def sign_request(req, identity, private, public):
    req.headers['Date'] = formatdate(usegmt=True)
    req.headers['X-Service'] = identity

    canon = "{r.headers[date]}\n{r.url}\n{r.body}".format(r=req).\
            encode('utf-8')
    log.debug("Canonical request:\n\n\"{0}\"".format(canon))
    req.headers['X-Signature'] = hexlify(private.sign(canon))


def verify_response(req, resp, identity, private, public):
    log.info("Validating %s request signature: %s", identity,
             resp.headers['X-Signature'])
    canon = "{ident}\n{r.headers[Date]}\n{url}\n{r.body}".format(
        ident=identity, r=resp, url=req.url)
    log.debug("Canonical data:\n%r", canon)

    # Raises an exception on failure.
    public.verify(
        unhexlify(resp.headers['X-Signature'].encode('utf-8')),
        canon.encode('utf-8'),
        hashfunc=sha256
    )


class API(object):
    __slots__ = ('endpoint', 'identity', 'private', 'public', 'http')

    def __init__(self, endpoint, identity, private, public, http=None):
        self.endpoint = unistr(endpoint)
        self.identity = identity
        self.private = private
        self.public = public

        if not http:
            self.http = AsyncHTTPClient()
        else:
            self.http = http

    def __getattr__(self, name):
        return API(
            '{0}/{1}'.format(self.endpoint, name),
            self.identity,
            self.private,
            self.public,
            self.http
        )

    @gen.coroutine
    def __call__(self, *args, **kwargs):
        req = HTTPRequest(
            url=self.endpoint + (('/' + '/'.join(unistr(arg) for arg in args))
                                 if args else ''),
            method='POST',
            body=urllib.urlencode(kwargs))
        sign_request(req, self.identity, self.private, self.public)

        resp = yield self.http.fetch(req)
        if resp.code != 200:
            raise gen.Return()
        verify_response(req, resp, self.identity, self.private, self.public)

        raise gen.Return(json.load(resp.buffer))
