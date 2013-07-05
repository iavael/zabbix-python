# This is a port of the ruby zabbix api found here:
# http://trac.red-tux.net/browser/ruby/api/zbx_api.rb
#
#LGPL 2.1   http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html
#Zabbix API Python Library.
#Original Ruby Library is Copyright (C) 2009 Andrew Nelson nelsonab(at)red-tux(dot)net
#Python Library is Copyright (C) 2009 Brett Lentz brett.lentz(at)gmail(dot)com
#
#This library is free software; you can redistribute it and/or
#modify it under the terms of the GNU Lesser General Public
#License as published by the Free Software Foundation; either
#version 2.1 of the License, or (at your option) any later version.
#
#This library is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#Lesser General Public License for more details.
#
#You should have received a copy of the GNU Lesser General Public
#License along with this library; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA


# NOTES:
# The API requires zabbix 1.8 or later.
# Currently, not all of the API is implemented, and some functionality is
# broken. This is a work in progress.

import base64
import hashlib
import logging
import string
import sys
try:
    import urllib2
except ImportError:
    import urllib.request as urllib2  # python3
import re
from collections import deque

default_log_handler = logging.StreamHandler(sys.stdout)
__logger = logging.getLogger("zabbix.rpc")
__logger.addHandler(default_log_handler)
__logger.log(10, "Starting logging")

try:
    # Separate module or Python <2.6
    import simplejson as json
    __logger.log(15, "Using simplejson library")
except ImportError:
    # Python >=2.6
    import json
    __logger.log(15, "Using native json library")


def checkauth(fn):
    """ Decorator to check authentication of the decorated method """
    def ret(self, *args):
        self.__checkauth__()
        return fn(self, args)
    return ret


def dojson(name):
    def decorator(fn):
        def wrapper(self, opts):
            self.logger.log(logging.DEBUG, \
                    "Going to do_request for %s with opts %s" \
                    % (repr(fn), repr(opts)))
            return self.do_request(self.json_obj(name, opts))['result']
        return wrapper
    return decorator


def dojson2(fn):
    def wrapper(self, method, opts):
        self.logger.log(logging.DEBUG, \
                "Going to do_request for %s with opts %s" \
                % (repr(fn), repr(opts)))
        return self.do_request(self.json_obj(method, opts))['result']
    return wrapper


class ZabbixRPCException(Exception):
    """ generic zabbix api exception
    code list:
         -32602 - Invalid params (eg already exists)
         -32500 - no permissions
    """
    pass


class Already_Exists(ZabbixRPCException):
    pass


class InvalidProtoError(ZabbixRPCException):
    """ Recived an invalid proto """
    pass


class ZabbixRPC(object):
    __username__ = ''
    __password__ = ''

    auth = ''
    url = '/api_jsonrpc.php'
    params = None
    method = None
    # HTTP or HTTPS
    proto = 'http'
    # HTTP authentication
    httpuser = None
    httppasswd = None
    timeout = 10
    # sub-class instances.
    user = None
    usergroup = None
    host = None
    item = None
    hostgroup = None
    hostinterface = None
    application = None
    trigger = None
    sysmap = None
    template = None
    drule = None
    # Constructor Params:
    # server: Server to connect to
    # path: Path leading to the zabbix install
    # proto: Protocol to use. http or https
    # We're going to use proto://server/path to find the JSON-RPC api.
    #
    # user: HTTP auth username
    # passwd: HTTP auth password
    # log_level: logging level
    # r_query_len: max len query history
    # **kwargs: Data to pass to each api module

    def __init__(self, server='http://localhost/zabbix', user=httpuser, passwd=httppasswd,
                 log_level=logging.WARNING, timeout=10, r_query_len=10, **kwargs):
        """ Create an API object.  """
        self._setuplogging()
        self.set_log_level(log_level)
        self.server = server
        self.url = server + '/api_jsonrpc.php'
        self.proto = self.server.split("://")[0]
        #self.proto=proto
        self.httpuser = user
        self.httppasswd = passwd
        self.timeout = timeout
        self.usergroup = ZabbixRPCSubClass(self, dict({"prefix": "usergroup"}, **kwargs))
        self.user = ZabbixRPCSubClass(self, dict({"prefix": "user"}, **kwargs))
        self.host = ZabbixRPCSubClass(self, dict({"prefix": "host"}, **kwargs))
        self.item = ZabbixRPCSubClass(self, dict({"prefix": "item"}, **kwargs))
        self.hostgroup = ZabbixRPCSubClass(self, dict({"prefix": "hostgroup"}, **kwargs))
        self.hostinterface = ZabbixRPCSubClass(self, dict({"prefix": "hostinterface"}, **kwargs))
        self.application = ZabbixRPCSubClass(self, dict({"prefix": "application"}, **kwargs))
        self.trigger = ZabbixRPCSubClass(self, dict({"prefix": "trigger"}, **kwargs))
        self.template = ZabbixRPCSubClass(self, dict({"prefix": "template"}, **kwargs))
        self.action = ZabbixRPCSubClass(self, dict({"prefix": "action"}, **kwargs))
        self.alert = ZabbixRPCSubClass(self, dict({"prefix": "alert"}, **kwargs))
        self.info = ZabbixRPCSubClass(self, dict({"prefix": "info"}, **kwargs))
        self.event = ZabbixRPCSubClass(self, dict({"prefix": "event"}, **kwargs))
        self.graph = ZabbixRPCSubClass(self, dict({"prefix": "graph"}, **kwargs))
        self.graphitem = ZabbixRPCSubClass(self, dict({"prefix": "graphitem"}, **kwargs))
        self.map = ZabbixRPCSubClass(self, dict({"prefix": "map"}, **kwargs))
        self.screen = ZabbixRPCSubClass(self, dict({"prefix": "screen"}, **kwargs))
        self.script = ZabbixRPCSubClass(self, dict({"prefix": "script"}, **kwargs))
        self.usermacro = ZabbixRPCSubClass(self, dict({"prefix": "usermacro"}, **kwargs))
        self.drule = ZabbixRPCSubClass(self, dict({"prefix": "drule"}, **kwargs))
        self.history = ZabbixRPCSubClass(self, dict({"prefix": "history"}, **kwargs))
        self.maintenance = ZabbixRPCSubClass(self, dict({"prefix": "maintenance"}, **kwargs))
        self.proxy = ZabbixRPCSubClass(self, dict({"prefix": "proxy"}, **kwargs))
        self.apiinfo = ZabbixRPCSubClass(self, dict({"prefix": "apiinfo"}, **kwargs))
        self.configuration = ZabbixRPCSubClass(self, dict({"prefix": "configuration"}, **kwargs))
        self.dcheck = ZabbixRPCSubClass(self, dict({"prefix": "dcheck"}, **kwargs))
        self.dhost = ZabbixRPCSubClass(self, dict({"prefix": "dhost"}, **kwargs))
        self.discoveryrule = ZabbixRPCSubClass(self, dict({"prefix": "discoveryrule"}, **kwargs))
        self.dservice = ZabbixRPCSubClass(self, dict({"prefix": "dservice"}, **kwargs))
        self.iconmap = ZabbixRPCSubClass(self, dict({"prefix": "iconmap"}, **kwargs))
        self.image = ZabbixRPCSubClass(self, dict({"prefix": "image"}, **kwargs))
        self.mediatype = ZabbixRPCSubClass(self, dict({"prefix": "mediatype"}, **kwargs))
        self.service = ZabbixRPCSubClass(self, dict({"prefix": "service"}, **kwargs))
        self.templatescreen = ZabbixRPCSubClass(self, dict({"prefix": "templatescreen"}, **kwargs))
        self.usermedia = ZabbixRPCSubClass(self, dict({"prefix": "usermedia"}, **kwargs))
        self.hostinterface = ZabbixRPCSubClass(self, dict({"prefix": "hostinterface"}, **kwargs))
        self.triggerprototype = ZabbixRPCSubClass(self, dict({"prefix": "triggerprototype"}, **kwargs))
        self.graphprototype = ZabbixRPCSubClass(self, dict({"prefix": "graphprototype"}, **kwargs))
        self.itemprototype = ZabbixRPCSubClass(self, dict({"prefix": "itemprototype"}, **kwargs))
        self.webcheck = ZabbixRPCSubClass(self, dict({"prefix": "webcheck"}, **kwargs))
        self.id = 0
        self.r_query = deque([], maxlen=r_query_len)
        self.debug(logging.INFO, "url: " + self.url)

    def _setuplogging(self):
        self.logger = logging.getLogger("zabbix.rpc.%s" % self.__class__.__name__)

    def set_log_level(self, level):
        self.debug(logging.INFO, "Set logging level to %d" % level)
        self.logger.setLevel(level)

    def recent_query(self):
        """
        return recent query
        """
        return list(self.r_query)

    def debug(self, level, var="", msg=None):
        strval = str(level) + ": "
        if msg:
            strval = strval + str(msg)
        if var != "":
            strval = strval + str(var)

        self.logger.log(level, strval)

    def json_obj(self, method, params={}):
        obj = {'jsonrpc': '2.0',
               'method': method,
               'params': params,
               'auth': self.auth,
               'id': self.id
              }

        self.debug(logging.DEBUG, "json_obj: " + str(obj))

        return json.dumps(obj)

    def login(self, user='', password='', save=True):
        if user != '':
            l_user = user
            l_password = password

            if save:
                self.__username__ = user
                self.__password__ = password
        elif self.__username__ != '':
            l_user = self.__username__
            l_password = self.__password__
        else:
            raise ZabbixRPCException("No authentication information available.")

        # don't print the raw password.
        hashed_pw_string = "md5(" + hashlib.md5(l_password.encode('utf-8')).hexdigest() + ")"
        self.debug(logging.DEBUG, "Trying to login with %s:%s" % \
                (repr(l_user), repr(hashed_pw_string)))
        obj = self.json_obj('user.authenticate', {'user': l_user,
                'password': l_password})
        result = self.do_request(obj)
        self.auth = result['result']

    def test_login(self):
        if self.auth != '':
            obj = self.json_obj('user.checkAuthentication', {'sessionid': self.auth})
            result = self.do_request(obj)

            if not result['result']:
                self.auth = ''
                return False  # auth hash bad
            return True  # auth hash good
        else:
            return False

    def do_request(self, json_obj):
        headers = {'Content-Type': 'application/json-rpc',
                   'User-Agent': 'python/zabbix'}

        if self.httpuser:
            self.debug(logging.INFO, "HTTP Auth enabled")
            auth = 'Basic ' + string.strip(base64.encodestring(self.httpuser + ':' + self.httppasswd))
            headers['Authorization'] = auth
        self.r_query.append(str(json_obj))
        self.debug(logging.INFO, "Sending: " + str(json_obj))
        self.debug(logging.DEBUG, "Sending headers: " + str(headers))

        request = urllib2.Request(url=self.url, data=json_obj.encode('utf-8'), headers=headers)
        if self.proto == "https":
            https_handler = urllib2.HTTPSHandler(debuglevel=0)
            opener = urllib2.build_opener(https_handler)
        elif self.proto == "http":
            http_handler = urllib2.HTTPHandler(debuglevel=0)
            opener = urllib2.build_opener(http_handler)
        else:
            raise ZabbixRPCException("Unknow protocol %s" % self.proto)

        urllib2.install_opener(opener)
        try:
            response = opener.open(request, timeout=self.timeout)
        except Exception as e:
            raise ZabbixRPCException("Site needs HTTP authentication. Error: "+str(e))
        self.debug(logging.INFO, "Response Code: " + str(response.code))

        # NOTE: Getting a 412 response code means the headers are not in the
        # list of allowed headers.
        if response.code != 200:
            raise ZabbixRPCException("HTTP ERROR %s: %s"
                    % (response.status, response.reason))
        reads = response.read()
        if len(reads) == 0:
            raise ZabbixRPCException("Received zero answer")
        try:
            jobj = json.loads(reads.decode('utf-8'))
        except ValueError as msg:
            print ("unable to decode. returned string: %s" % reads)
            sys.exit(-1)
        self.debug(logging.DEBUG, "Response Body: " + str(jobj))

        self.id += 1

        if 'error' in jobj:  # some exception
            msg = "Error %s: %s, %s while sending %s" % (jobj['error']['code'],
                    jobj['error']['message'], jobj['error']['data'], str(json_obj))
            if re.search(".*already\sexists.*", jobj["error"]["data"], re.I):  # already exists
                raise Already_Exists(msg, jobj['error']['code'])
            else:
                raise ZabbixRPCException(msg, jobj['error']['code'])
        return jobj

    def logged_in(self):
        if self.auth != '':
            return True
        return False

    def api_version(self, **options):
        self.__checkauth__()
        obj = self.do_request(self.json_obj('APIInfo.version', options))
        return obj['result']

    def __checkauth__(self):
        if not self.logged_in():
            raise ZabbixRPCException("Not logged in.")


class ZabbixRPCSubClass(ZabbixRPC):
    """ wrapper class to ensure all calls go through the parent object """
    parent = None
    data = None

    def __init__(self, parent, data, **kwargs):
        self._setuplogging()
        self.debug(logging.INFO, "Creating %s" % self.__class__.__name__)
        self.data = data
        self.parent = parent

        # Save any extra info passed in
        for key, val in kwargs.items():
            setattr(self, key, val)
            self.debug(logging.WARNING, "Set %s:%s" % (repr(key), repr(val)))

    def __getattr__(self, name):
        if self.data["prefix"] == "configuration" and name == "import_":  # workaround for "import" method
            name = "import"

        def method(*opts):
            return self.universal("%s.%s" % (self.data["prefix"], name), opts[0])
        return method

    def __checkauth__(self):
        self.parent.__checkauth__()

    def do_request(self, req):
        return self.parent.do_request(req)

    def json_obj(self, method, param):
        return self.parent.json_obj(method, param)

    @dojson2
    @checkauth
    def universal(self, **opts):
        return opts
