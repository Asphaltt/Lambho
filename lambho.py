#!/usr/bin/env python
# encoding: utf-8
import re
import sys
import time
import asyncio
import uvloop
import logging

from cgi import parse_header
from inspect import isawaitable
from httptools import parse_url
from mimetypes import guess_type
from urllib.parse import parse_qs
from multidict import CIMultiDict
from signal import SIGINT, SIGTERM
from http.cookies import SimpleCookie
from aiofiles import open as open_async
from functools import wraps, partial, lru_cache
from collections import namedtuple, defaultdict
from httptools import HttpRequestParser, parse_url
from ujson import dumps as json_dumps, loads as json_loads


class AppStack(list):

    def __call__(self):
        return self.default

    def push(self, app=None):
        if not isinstance(app, Lambho):
            app = Lambho()
        self.append(app)
        return app

    @property
    def default(self):
        try:
            return self[-1]
        except IndexError:
            return self.push()


default_app = AppStack()
logger = logging.getLogger(__name__)


# --- config start ---
class Config(dict):
    LOGO = """
______                   ______ ______
___  / ______ _______ ______  /____  /_______      ▁▁▁▁▁▁▁▁▁▁▁▁▁
__  /  _  __ `/_  __ `__ \\_  __ \\_  __ \\  __ \\    /            /
_  /___/ /_/ /_  / / / / /  /_/ /  / / / /_/ /   /  Run fast! /
/_____/\__,_/ /_/ /_/ /_//_.___//_/ /_/\____/   /▁▁▁▁▁▁▁▁▁▁▁▁/
    """
    ROUTE_CACHE_SIZE = 1024
# --- config end ---


# --- route rules start ---
Route = namedtuple('Route', "handler, pattern, methods, parameters")
Parameter = namedtuple('Parameter', "name, type")

REGEXP_TYPES = {
    "string": (str, r'[^/]+'),
    "int": (int, r'\d+'),
    "number": (float, r'[0-9\\.]+'),
    "alpha": (str, r'[A-Za-z]+'),
    "alphanum": (str, r'[A-Za-z0-9]+')
}


def url_hash(url):
    return url.count('/')


class Router:
    """
    Router collects all route rules, which supports basic routing with
    parameters and methods. Parameters will be passed as keyword arguments
    to request handler function, which can have a type by appending :type
    in <parameter>, like the following usage. IF `type` is not provided,
    it defaults *string*. The `type` must be one of *string*, *int*, *number*,
    *alpha* and *alphanum* if it's provided.
    Usage:
        @lambho.get('/for/example/<parameter>')
        def exam(request, parameter):
            pass
    or
        @lambho.route('/for/example/<parameter:type>', methods=['GET', 'POST', ...])
        def exam(request, parameter):
            pass
    """

    def __init__(self):
        self.all_routes = {}
        self.static_routes = {}
        self.dynamic_routes = defaultdict(list)

    def add(self, uri, methods, handler):
        """
        Add a handler to the route list.
        :param uri: Route path to match
        :param methods: Array methods to be checked
            If none are provided, any method is allowed
        :param handler: Request handler function
        :return:
        """
        if uri in self.all_routes:
            raise LambhoError("Route has been registered: {}".format(uri))

        # frozenset for faster lookup
        if methods:
            methods = frozenset(methods)

        parameters= []

        def add_parameter(match):
            param = match.group(1)
            pattern = "string"
            if ':' in param:
                param, pattern = param.split(':', 1)

            _default = (str, pattern)
            _type, pattern = REGEXP_TYPES.get(pattern, _default)
            parameters.append(Parameter(name=param, type=_type))
            return "({})".format(pattern)

        pattern_re = re.sub(r'<(.+?)>', add_parameter, uri)
        pattern = re.compile(r'^{}$'.format(pattern_re))

        route = Route(handler=handler, pattern=pattern,
                      methods=methods, parameters=parameters)

        self.all_routes[uri] = route
        if parameters:
            self.dynamic_routes[url_hash(uri)].append(route)
        else:
            self.static_routes[uri] = route

    def get(self, request):
        """
        Gets a request handler based on the URL of the request, or raises an
            error
        :param request: Request object
        :return: handler, arguments, keyword arguments
        """
        return self._get(request.url, request.method)

    @lru_cache(Config.ROUTE_CACHE_SIZE)
    def _get(self, url, method):
        """
        Gets a request handler based on the URL of the request, or raises an
            error
        :param request: Request object
        :return: handler, arguments, keyword arguments
        """
        route = self.static_routes.get(url)
        if route:
            match = route.pattern.match(url)
        else:
            for route in self.dynamic_routes[url_hash(url)]:
                match = route.pattern.match(url)
                if match:
                    break
            else:
                raise ServerError('Not found {}.'.format(url), 404)

        if route.methods and method not in route.methods:
            raise ServerError('Method not found.', 405)

        kwargs = {p.name: p.type(value) for value, p
                  in zip(match.groups(1), route.parameters)}
        return route.handler, [], kwargs
# --- route rules end ---


# --- request and response start ---
DEFAULT_HTTP_CONTENT_TYPE = "application/octet-stream"
# HTTP/1.1: https://www.w3.org/Protocols/rfc2616/rfc2616-sec7.html#sec7.2.1
# > If the media type remains unknown, the recipient SHOULD treat it
# > as type "application/octet-stream"


class RequestParameters(dict):

    def __init__(self, *args, **kwargs):
        self.super = super()
        self.super.__init__(*args, **kwargs)

    def get(self, name, default=None):
        values = self.super.get(name)
        return values[0] if values else default

    def getlist(self, name, default=None):
        return self.super.get(name, default)


class BaseRequest:
    """
    BaseRequest get properties of an HTTP request,
    such as url, headers, form data, etc.
    """
    __slots__ = (
        'app', 'url', 'headers', 'version', 'method', '_cookies',
        'query_string', 'body',
        'parsed_json', 'parsed_args', 'parsed_form', 'parsed_files',
    )

    def __init__(self, app, url_bytes, headers, version, method):
        self.app = app
        url_parsed = parse_url(url_bytes)
        self.url = url_parsed.path.decode('utf-8')
        self.headers = headers
        self.version = version
        self.method = method
        self.query_string = None
        if url_parsed.query:
            self.query_string = url_parsed.query.decode('utf-8')

        self.body = None
        self.parsed_json = None
        self.parsed_form = None
        self.parsed_files = None
        self.parsed_args = None
        self._cookies = None

    @property
    def json(self):
        if not self.parsed_json:
            try:
                self.parsed_json = json_loads(self.body)
            except Exception:
                raise InvalidUsage("Failed when parsing body as json")

        return self.parsed_json

    @property
    def form(self):
        if self.parsed_form is None:
            self.parsed_form = RequestParameters()
            self.parsed_files = RequestParameters()
            content_type = self.headers.get(
                'Content-Type', DEFAULT_HTTP_CONTENT_TYPE)
            content_type, parameters = parse_header(content_type)
            try:
                if content_type == 'application/x-www-form-urlencoded':
                    self.parsed_form = RequestParameters(
                        parse_qs(self.body.decode('utf-8')))
                elif content_type == 'multipart/form-data':
                    boundary = parameters['boundary'].encode('utf-8')
                    self.parsed_form, self.parsed_files = (
                        parse_multipart_form(self.body, boundary))
            except Exception:
                logger.exception("Failed when parsing form")

        return self.parsed_form

    @property
    def files(self):
        if self.parsed_files is None:
            self.form

        return self.parsed_files

    @property
    def args(self):
        if self.parsed_args is None:
            if self.query_string:
                self.parsed_args = RequestParameters(
                    parse_qs(self.query_string))
            else:
                self.parsed_args = {}

        return self.parsed_args

    @property
    def cookies(self):
        if self._cookies is None:
            cookie = self.headers.get('Cookie') or self.headers.get('cookie')
            if cookie is not None:
                cookies = SimpleCookie()
                cookies.load(cookie)
                self._cookies = {name: cookie.value
                                 for name, cookie in cookies.items()}
            else:
                self._cookies = {}
        return self._cookies


File = namedtuple('File', "type, body, name")


def parse_multipart_form(body, boundary):
    """
    Parses a request body and returns fields and files
    :param body: Bytes request body
    :param boundary: Bytes multipart boundary
    :return: fields (RequestParameters), files (RequestParameters)
    """
    files = RequestParameters()
    fields = RequestParameters()

    form_parts = body.split(boundary)
    for form_part in form_parts[1:-1]:
        file_name, file_type, field_name = None, None, None
        line_index, line_end_index = 2, 0
        while not line_end_index == -1:
            line_end_index = form_part.find(b'\r\n', line_index)
            form_line = form_part[line_index:line_end_index].decode('utf-8')
            line_index = line_end_index + 2

            if not form_line:
                break

            colon_index = form_line.index(':')
            form_header_field = form_line[0:colon_index]
            form_header_value, form_parameters = parse_header(
                form_line[colon_index + 2:])

            if form_header_field == 'Content-Disposition':
                if 'filename' in form_parameters:
                    file_name = form_parameters['filename']
                field_name = form_parameters.get('name')
            elif form_header_field == 'Content-Type':
                file_type = form_header_value

        post_data = form_part[line_index:-4]
        if file_name or file_type:
            file = File(type=file_type, name=file_name, body=post_data)
            if field_name in files:
                files[field_name].append(file)
            else:
                files[field_name] = [file]
        else:
            value = post_data.decode('utf-8')
            if field_name in fields:
                fields[field_name].append(value)
            else:
                fields[field_name] = [value]

    return fields, files


Request = BaseRequest


class BaseResponse:
    """
    Basic response of an HTTP request.
    """
    __slots__ = ('body', 'status', 'message', 'content_type', 'headers', '_cookies')

    def __init__(self, body=None, status=200, content_type='text/plain',
                 headers=None, message=b'OK', body_bytes=b''):
        self.status = status
        self.message = message
        self.content_type = content_type
        self.headers = headers or {}
        self._cookies = None

        if body is not None:
            try:
                self.body = body.encode('utf-8')
            except AttributeError:
                self.body = str(body).encode('utf-8')
        else:
            self.body = body_bytes

    def output(self, version="1.1", keep_alive=False):
        headers = b''
        if self.headers:
            headers = b''.join(
                b'%b: %b\r\n' % (name.encode(), value.encode('utf-8'))
                for name, value in self.headers.iteritems())
        return (
            b'HTTP/%b %d %b\r\n'
            b'Content-Type: %b\r\n'
            b'Content-Length: %d\r\n'
            b'Connection: %b\r\n'
            b'%b\r\n'
            b'%b') % (
                version.encode(),
                self.status,
                self.message,
                self.content_type.encode(),
                len(self.body),
                b'keep-alive' if keep_alive else b'close',
                headers,
                self.body)


class HTTPError(BaseResponse):

    def __init__(self, status, message):
        super().__init__(status=status, message=message)


Response = BaseResponse


def json(body, status=200, headers=None):
    return Response(json_dumps(body), headers=headers, status=status,
                        content_type="application/json")


def text(body, status=200, headers=None):
    return Response(body, status=status, headers=headers,
                        content_type="text/plain; charset=utf-8")


def html(body, status=200, headers=None):
    return Response(body, status=status, headers=headers,
                        content_type="text/html; charset=utf-8")


async def file(filename, mimetype=True, headers=None,
    download=False, charset='utf-8'):
    """
    Open a file in an async way and return an instance of *Response*.

    :param filename: A file to be opened and returned.
    :param mimetype: If True, guess mimetype and encoding from
        filename or download if download is provided as filename.
    :param headers: A dict to keep the response headers.
    :param download: If True, ask browser open a "Save as ..." dialog
        to save the file instead of opening with associated program.
        It can be a custom string as the filename. Otherwise,
        the original filename is used. (default: False)
    :param charset: The charset is with "text/*" in mimetype.
        (default: utf-8)
    :return: A http error with status code 404 or 403, if "../" in the
        filename or the file does not exist or you have no access
        permission of the file. Or a Response is returned.
    """
    headers = headers or {}

    if '../' in filename:
        return HTTPError(404, "Invalid file to access.")
    else:
        filename = os.path.abspath(filename)

    if not os.path.exists(filename) or not os.path.isfile(filename):
        return HTTPError(404, "File does not exist.")
    if not os.access(filename, os.R_OK):
        return HTTPError(403, "You do not have permission to access this file.")

    if mimetype is True:
        if download and download is not True:
            mimetype, encoding = mimetypes.guess_type(download)
        else:
            mimetype, encoding = mimetypes.guess_type(filename)
        if encoding:
            headers['Content-Encoding'] = encoding

    if mimetype:
        if (mimetype[:5] == 'text/' or mimetype == 'application/javascript') \
            and charset and 'charset' not in mimetype:
            mimetype += '; charset=%s' % charset
        headers['Content-Type'] = mimetype

    if download:
        download = os.path.basename(filename if download is True else download)
        headers['Content-Disposition'] = 'attachment; filename="%s"' % download

    stats = os.stat(filename)
    headers['Content-Length'] = clen = stats.st_size
    lm = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(stats.st_mtime))
    headers['Last-Modified'] = lm
    headers['Date'] = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

    async with open_async(location, mode='rb') as _file:
        body = await _file.read()

    return Response(headers=headers,
                    content_type=mime_type,
                    body_bytes=body)
# --- request and response end ---


# --- exceptions start ---
class LambhoError(Exception):

    def __init__(self, message, status_code=None):
        super().__init__(message)
        if status_code is not None:
            self.status_code = status_code


class InvalidUsage(LambhoError):
    status_code = 400


class ServerError(LambhoError):
    status_code = 500
# --- exceptions end ---


# --- application start ---
class Handler:

    def __init__(self):
        self.handlers = {}

    def add(self, handler, exception=None, status=None):
        if exception is not None:
            self.handlers[exception] = handler
        if status is not None:
            self.handlers[status] = handler

    def response(self, request, exception=None, status=None):
        if status is not None:
            handler = self.handlers.get(status, self.default)
        else:
            handler = self.handlers.get(type(exception), self.default)
        response = handler(request=request, exception=exception)
        return response

    def default(self, request, exception, status=500):
        return Response("An error occurred while requesting.", status=status)


class Lambho(object):

    def __init__(self, name=None, router=None, error_handler=None, config=None,
        logger=None):
        if logger is None:
            logging.basicConfig(
                level=logging.INFO,
                format="%(asctime)s %(levelname)s [%(filename)s:%(lineno)d] %(message)s"
            )

        self.name = name or "Lambho"
        self.router = router or Router()
        self.config = config or Config()
        self.error_handler = error_handler or Handler()

        self.config.setdefault('DEBUG', False)

    def add_route(self, uri, methods, handler):
        self.router.add(uri=uri, methods=methods, handler=handler)

    def route(self, uri, methods=None):
        def decorator(handler):
            self.add_route(uri, methods, handler)
            return handler
        return decorator

    def get(self, uri):
        return self.route(uri, methods=['GET'])

    def post(self, uri):
        return self.route(uri, methods=['POST'])

    def put(self, uri):
        return self.route(uri, methods=['PUT'])

    def delete(self, uri):
        return self.route(uri, methods=['DELETE'])

    def patch(self, uri):
        return self.route(uri, methods=['PATCH'])

    def error(self, status=500):
        def wrapper(handler):
            self.error_handler.add(handler, status=status)
            return handler
        return wrapper

    async def request_handler(self, request, response_callback):
        handler, args, kwargs = self.router.get(request)

        if handler is None:
            raise ServerError(("'None' was returned while requesting "
                "a handler from the router"))

        response = handler(request, *args, **kwargs)
        if isawaitable(response):
            response = await response
        response = Response(response)

        response_callback(response)


def wrapper_default_app_method(name):
    @wraps(getattr(Lambho, name))
    def wrapper(*a, **kw):
        return getattr(default_app(), name)(*a, **kw)
    return wrapper


route = wrapper_default_app_method('route')
get = wrapper_default_app_method('get')
post = wrapper_default_app_method('post')
put = wrapper_default_app_method('put')
delete = wrapper_default_app_method('delete')
patch = wrapper_default_app_method('patch')
error = wrapper_default_app_method('error')
# --- application end ---


# --- server start ---
class Signal:
    stopped = False


current_timestamp = None


def update_current_timestamp(loop):
    global current_timestamp
    current_timestamp = time.time()
    loop.call_later(1, partial(update_current_timestamp, loop))


class Server(asyncio.Protocol):

    def __init__(self, *, app, loop, request_handler, error_handler,
                 signal=Signal(), connections={},
                 request_timeout=60, request_max_size=None):
        self.app = app
        self.loop = loop
        self.transport = None
        self.request = None
        self.url = None
        self.headers = None
        self.request_handler = request_handler
        self.error_handler = error_handler
        self.signal = signal
        self.connections = connections
        self.request_timeout = request_timeout
        self.request_max_size = request_max_size
        self._request_handler_task = None
        self.parser = None

    def connection_made(self, transport):
        self.connections.add(self)
        self.transport = transport

    def connection_lost(self, exception):
        self.connections.discard(self)

    def connection_timeout(self):
        pass

    def data_received(self, data):
        if self.parser is None:
            self.headers = []
            self.parser = HttpRequestParser(self)
        self.parser.feed_data(data)

    def on_url(self, url):
        self.url = url

    def on_header(self, name, value):
        self.headers.append((name.decode(), value.decode('utf-8')))

    def on_headers_complete(self):
        remote_addr = self.transport.get_extra_info('peername')
        if remote_addr:
            self.headers.append(('Remote-Addr', '%s:%s' % remote_addr))

        self.request = Request(
            app=self.app,
            url_bytes=self.url,
            headers=CIMultiDict(self.headers),
            version=self.parser.get_http_version(),
            method=self.parser.get_method().decode()
        )

    def on_body(self, body):
        if self.request.body:
            self.request.body += body
        else:
            self.request.body = body

    def on_message_complete(self):
        self._request_handler_task = self.loop.create_task(
            self.request_handler(self.request, self.write_response))

    def write_response(self, response):
        try:
            keep_alive = self.parser.should_keep_alive() \
                and not self.signal.stopped
            self.transport.write(response.output(self.request.version))
            self.transport.close()
        except Exception as e:
            logger.exception("Excepting while writing response.")

    def write_error(self, exception):
        try:
            response = self.error_handler.response(self.request, exception)
            version = self.request.version if self.request else '1.1'
            self.transport.write(response.output(version))
            self.transport.close()
        except Exception as e:
            logger.exception("Excepting while writing error.")

    def close_if_idle(self):
        if not self.parser:
            self.transport.close()
            return True
        return False
# --- server end ---


def run(app=None, host='127.0.0.1', port=5000, request_timeout=60,
        request_max_size=None, reuse_port=False, server=None, loop=None,
        debug=False):
    app = app or default_app()
    server = server or Server
    loop = loop or uvloop.new_event_loop()
    asyncio.set_event_loop(loop)

    if debug:
        app.config['DEBUG'] = True
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    connections = set()
    signal = Signal()
    server_factory = partial(
        server,
        app=app,
        loop=loop,
        connections=connections,
        signal=signal,
        request_handler=app.request_handler,
        error_handler=app.error_handler,
        request_timeout=request_timeout,
        request_max_size=request_max_size,
    )

    coro = loop.create_server(
        server_factory, host, port, reuse_port=reuse_port,
        sock=None
    )

    loop.call_soon(partial(update_current_timestamp, loop))

    try:
        http_server = loop.run_until_complete(coro)
    except Exception:
        logger.error("Unable to start server")
        return

    for _signal in (SIGINT, SIGTERM):
        loop.add_signal_handler(_signal, loop.stop)

    try:
        logger.debug(Config.LOGO)
        logger.info('Running ...\nAccess by http://{}:{}/  (Press Ctrl+C to quit)'
            .format(host, port))
        loop.run_forever()

    except KeyboardInterrupt:
        pass
    except (SystemExit, MemoryError):
        raise
    except:
        sys.exit(3)
    finally:
        http_server.close()
        loop.run_until_complete(http_server.wait_closed())

        signal.stopped = True
        for connection in connections:
            connection.close_if_idle()

        while connections:
            loop.run_until_complete(asyncio.sleep(0.1))

        loop.close()
