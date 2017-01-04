#!/usr/bin/env python
# encoding: utf-8
import sys
import asyncio
import uvloop

from time import time
from inspect import isawaitable
from signal import SIGINT, SIGTERM
from functools import wraps, partial
from collections import namedtuple, defaultdict
from httptools import HttpRequestParser, parse_url


def _makelist(item):
    if isinstance(item, (tuple, list, set, dict)):
        return list(item)
    elif item:
        return [item]
    else:
        return []


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


app = default_app = AppStack()


Route = namedtuple('Route', "handler, pattern, methods")


class Router:

    def __init__(self):
        self.all_routes = {}
        self.static_routes = {}
        self.dynamic_routes = defaultdict(list)

    def add(self, handler, methods, pattern):
        route = Route(handler=handler, pattern=pattern, methods=methods)
        for meth in methods:
            self.static_routes[meth + pattern] = route

    def get(self, request):
        return self._get(request.url, request.method)

    def _get(self, url, method):
        route = self.static_routes.get(method + url)
        if route is None:
            return None, [], {}
        return route.handler, [], {}


class BaseRequest:

    def __init__(self, url_bytes, headers, version, method):
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


Request = BaseRequest


class BaseResponse:
    __slots__ = ('body', 'status', 'content_type', 'headers', '_cookies')

    def __init__(self, body=None, status=200, content_type='text/plain',
                 headers=None, body_bytes=b''):
        self.status = status
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
        return (b'HTTP/%b %d %b\r\n'
                b'Content-Type: %b\r\n'
                b'Content-Length: %d\r\n'
                b'Connection: %b\r\n'
                b'%b\r\n'
                b'%b') % (
            version.encode(),
            self.status,
            b'ok',
            self.content_type.encode(),
            len(self.body),
            b'keep-alive' if keep_alive else b'close',
            headers,
            self.body
        )


Response = BaseResponse


class LambhoError(Exception):

    status_code = None

    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


class Handler:

    def __init__(self):
        self.handlers = {}

    def response(self, request, exception):
        handler = self.handlers.get(type(exception), self.default)
        response = handler(request=request, exception=exception)
        return response

    def default(self, request, exception):
        return Response("An error occurred while requesting.", status=500)


class ServerError(LambhoError):
    status_code = 500


class Lambho(object):

    def __init__(self, name=None, router=None, error_handler=None):
        self.name = name or "Lambho"
        self.router = router or Router()
        self.error_handler = error_handler or Handler()

    def add_route(self, path, methods, handler):
        self.router.add(handler=handler, methods=methods, pattern=path)

    def route(self, path, method='GET'):
        def decorator(handler):
            methods = _makelist(method)
            self.add_route(path, methods, handler)
            return handler
        return decorator

    def get(self, path, *a, **kw):
        return self.route(path, *a, **kw)

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
        return getattr(app(), name)(*a, **kw)
    return wrapper


route = wrapper_default_app_method('route')
get = wrapper_default_app_method('get')


class Signal:
    stopped = False


current_timestamp = None


def update_current_timestamp(loop):
    global current_timestamp
    current_timestamp = time()
    loop.call_later(1, partial(update_current_timestamp, loop))


class Server(asyncio.Protocol):

    def __init__(self, *, loop, request_handler, error_handler,
                 signal=Signal(), connections={},
                 request_timeout=60, request_max_size=None):
        self.loop = loop
        self.transport = None
        self.request = None
        self.url = None
        self.headers = []
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
            self.parser = HttpRequestParser(self)
        self.parser.feed_data(data)

    def on_url(self, url):
        self.url = url

    def on_headers(self, name, value):
        self.headers.append((name.decode(), value.decode('utf-8')))

    def on_headers_complete(self):
        remote_addr = self.transport.get_extra_info('peername')
        if remote_addr:
            self.headers.append(('Remote-Addr', '%s:%s' % remote_addr))

        self.request = Request(
            url_bytes=self.url,
            headers=self.headers,
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
            print("Excepting while writing response.")
            import traceback
            traceback.print_exc()

    def write_error(self, exception):
        try:
            response = self.error_handler.response(self.request, exception)
            version = self.request.version if self.request else '1.1'
            self.transport.write(response.output(version))
            self.transport.close()
        except Exception as e:
            print("Excepting while writing error.")

    def close_if_idle(self):
        if not self.parser:
            self.transport.close()
            return True
        return False


def run(app=None, host='127.0.0.1', port=5000, request_timeout=60,
        request_max_size=None, reuse_port=False, server=None, loop=None):
    app = app or default_app()
    server = server or Server
    loop = loop or uvloop.new_event_loop()
    asyncio.set_event_loop(loop)

    connections = set()
    signal = Signal()
    server_factory = partial(
        server,
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
        print("Unable to start server")
        return

    for _signal in (SIGINT, SIGTERM):
        loop.add_signal_handler(_signal, loop.stop)

    try:
        print('Running ...\nAccess by http://{}:{}'.format(host, port))
        loop.run_forever()

    except KeyboardInterrupt:
        pass
    except (SystemExit, MemoryError):
        raise
    except:
        sys.exit(3)
    finally:
        print("Stopping ...")
        http_server.close()
        loop.run_until_complete(http_server.wait_closed())

        signal.stopped = True
        for connection in connections:
            connection.close_if_idle()

        while connections:
            loop.run_until_complete(asyncio.sleep(0.1))

        loop.close()
