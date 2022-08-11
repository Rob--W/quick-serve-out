#!/usr/bin/env python
from __future__ import print_function

"""
Provides a server with a simple interface to request and receive text
or a file from another endpoint in your network. The result is send to
the standard output.
"""

DOC_EXAMPLES = """
By default, the server form must be accessed over HTTPS.
To generate a self-signed certificate (for --certfile), run:
    openssl req -x509 -newkey rsa:2048 -days 3660 -keyout localhost.pem -out localhost.pem -nodes -sha256 -subj '/CN=localhost'

Examples:

Simple text sharing:
1. %(prog)s PORT
2. Visit https://youriphere:PORT/
3. Input text and submit.
4. Look at stdout.

File sharing:
1. %(prog)s PORT > filename
2. Visit https://youriphere:PORT/
3. Select a file and submit.
4. Look at stderr for the actual name of the uploaded file.
5. Look at stdout (=piped to filename) for the file content.

Via curl instead of a web browser:
1. %(prog)s PORT
2. echo or cat anything | curl https://youriphere:PORT --data-binary @-
3. Look at stdout.
"""  # NOQA

try:  # Py3
    from http.server import HTTPServer, BaseHTTPRequestHandler
except ImportError:  # Py2
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import cgi
import os
import re
import socket
import ssl
import sys
import threading

"""
Relevant related sources:
https://hg.python.org/cpython/file/2.7/Lib/BaseHTTPServer.py
https://hg.python.org/cpython/file/2.7/Lib/SocketServer.py
https://hg.python.org/cpython/file/2.7/Lib/ssl.py
https://github.com/python/cpython/blob/3.6/Lib/http/server.py

https://docs.python.org/2/library/socket.html

Multipart form parsing:
https://tools.ietf.org/html/rfc2046#page-43
https://tools.ietf.org/html/rfc7578
"""


DEFAULT_INDEX_HTML = b"""
<!DOCTYPE html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<style>
* {
    box-sizing: border-box;
}
html, body {
    margin: 0;
    padding: 0;
}
html, body, form {
    width: 100%;
    height: 100%;
}
form {
    padding: 1em;
    display: flex;
    flex-direction: column;
}
.top-controls {
    flex-shrink: 0;
    flex-grow: 0;
}
textarea {
    width: 100%;
    flex-shrink: 0;
    flex-grow: 1;
}
.error {
    color: red;
}
</style>
<form method="POST" enctype="multipart/form-data">
<div class="top-controls">
<input type="file" name="file">
<input type="submit" value="Submit">
<span class="error">ERROR_HERE</span>
</div>
<textarea name="text" placeholder="text for stdout (or stderr if a file is selected)"></textarea>
</form>
""".replace(b"%", b"%%").replace(b"ERROR_HERE", b"%s")  # NOQA

if hasattr(sys.stdout, "buffer"):  # Py3
    def write_bytes(f, b): f.buffer.write(b)
else:  # Py2
    def write_bytes(f, b): f.write(b)


class HTTPSHTTPServer(HTTPServer):
    """
    TCP server that accepts both HTTPS and HTTP requests.
    """
    def __init__(self,
                 server_address,
                 HTTPRequestHandlerClass,
                 HTTPSRequestHandlerClass,
                 bind_and_activate=True,
                 keyfile=None,
                 certfile=None):
        HTTPServer.__init__(self,
                            server_address,
                            HTTPRequestHandlerClass,
                            bind_and_activate)
        self.HTTPSRequestHandlerClass = HTTPSRequestHandlerClass
        self.keyfile = keyfile
        self.certfile = certfile

        if not certfile:
            raise ValueError("certfile must be specified")

    def get_request(self):
        newsock, addr = self.socket.accept()
        firstbyte = newsock.recv(1, socket.MSG_PEEK)
        if firstbyte == b"\x16":
            # This is a TLS handshake
            # https://tools.ietf.org/html/rfc5246#appendix-A.1
            newsock = ssl.wrap_socket(newsock,
                                      keyfile=self.keyfile,
                                      certfile=self.certfile,
                                      server_side=True)
        return (newsock, addr)

    def finish_request(self, request, client_address):
        """
        Select the right request handler.
        """
        if isinstance(request, ssl.SSLSocket):
            return self.HTTPSRequestHandlerClass(request, client_address, self)

        # Equivalent to HTTPRequestHandlerClass(request, client_address, self)
        return HTTPServer.finish_request(self, request, client_address)

    def shutdown_async(self):
        """
        Shut the server down - can be used while a request was being processed.
        """
        task = threading.Thread(target=self.shutdown)
        task.daemon = True  # Don't wait for this thread before exiting.
        task.start()

    def handle_error(self, request, client_address):
        """
        From https://github.com/python/cpython/blob/3.6/Lib/socketserver.py
        This is because in Py2, the default implementation prints to stdout.
        https://hg.python.org/cpython/file/2.7/Lib/SocketServer.py#l341
        Ugh.
        """
        print('-'*40, file=sys.stderr)
        print('Exception happened during processing of request from',
              client_address, file=sys.stderr)
        import traceback
        traceback.print_exc()
        print('-'*40, file=sys.stderr)


class SilentHTTPRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Do not put useless messages in stderr.
        pass


class RedirectToHttpsHandler(SilentHTTPRequestHandler):
    def reply_redirect(self):
        host = self.headers.get("Host")
        if not host:
            self.send_error(400, "Host header is required")
            return
        self.send_response(307)

        path = self.path
        if not path.startswith("/"):
            # E.g. for proxies the "path" can be an absolute URL.
            # Let's treat it as if there was a "/" in front of it.
            path = '/%s' % path

        self.send_header("Location", "https://%s%s" % (host, path))
        self.end_headers()

    def do_GET(self):
        return self.reply_redirect()

    def do_HEAD(self):
        return self.reply_redirect()

    def do_POST(self):
        return self.reply_redirect()


class RequestHandler(SilentHTTPRequestHandler):
    """
    For now, simply print to stdout.
    If desired, I could implement file listing etc. based on SimpleHTTPServer.
    """
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(
            DEFAULT_INDEX_HTML % b"Server will close after submission")

    def do_POST(self):
        try:  # Py3
            content_type = self.headers.get_content_type()
        except AttributeError:  # Py2
            content_type = self.headers.gettype()
        if content_type == "multipart/form-data":
            self._handle_multipart_formdata()
        elif content_type == "application/x-www-form-urlencoded":
            # For now, do not attempt to parse the body.
            self._handle_raw_post()
        else:
            self._handle_raw_post()

    def _handle_multipart_formdata(self):
        try:  # Py3
            boundary = self.headers.get_param("boundary")
        except AttributeError:  # Py2
            boundary = self.headers.getparam("boundary")
        if not boundary:
            self.send_error(400, "boundary not found in Content-Type header")
            return

        dash_boundary = b"--" + boundary.encode("ascii")
        delimiter = b"\r\n" + dash_boundary
        close_delimiter = delimiter + b"--"

        # Pattern to retrieve form name.
        r_cd_form_part_name = re.compile(
            b"^\r\nContent-Disposition: form-data(?=;).*[; ]name=\"([^\"]+)\"",
            flags=re.IGNORECASE)

        STATE_BEFORE_BODY = 0
        STATE_MULTIPART_HEAD = 1
        STATE_MULTIPART_HEAD_END = 2
        STATE_MULTIPART_BODY = 3
        state = STATE_BEFORE_BODY
        part_name = ""
        did_print_file_info = False
        did_print_text_info = False

        # Look for first delimiter.
        for chunk in self._iter_body():
            if state == STATE_BEFORE_BODY:
                if chunk == b"\r\n":
                    continue
                if chunk == dash_boundary or chunk == delimiter:
                    state = STATE_MULTIPART_HEAD
                    continue
                # Note: RFC 2046 allows "preamble = discard-text"
                # = any CHAR (RFC 822) excluding CRLF before the body.
                # Let's not allow that to ease debugging of malformed requests.
                self.send_error(400, "Boundary delimiter not found")
                return

            if chunk == delimiter:
                part_name = ""
                state = STATE_MULTIPART_HEAD
                continue
            if chunk == close_delimiter:
                break  # This was the last part.

            if state == STATE_MULTIPART_HEAD:
                if chunk == b"\r\n":
                    # Empty line = end of headers.
                    state = STATE_MULTIPART_HEAD_END
                    continue
                match = r_cd_form_part_name.match(chunk)
                if match:
                    part_name = match.group(1).decode("ascii")
                    _, parts = cgi.parse_header(chunk.decode("ascii"))
                    filename = parts.get("filename", "")
                continue

            if state == STATE_MULTIPART_HEAD_END:
                assert chunk.startswith(b"\r\n")
                chunk = chunk[2:]
                state = STATE_MULTIPART_BODY

            if part_name == "file":
                if not did_print_file_info and (chunk or filename):
                    did_print_file_info = True
                    sys.stderr.write("Received file: \"%s\"" % filename)
                write_bytes(sys.stdout, chunk)
            elif part_name == "text":
                if not did_print_text_info and chunk:
                    did_print_text_info = True
                    if did_print_file_info:
                        sys.stderr.write("Received file and text.\n")
                    else:
                        sys.stderr.write("Received text.\n")

                if did_print_file_info:
                    # If a file was already given, put the text in stderr
                    # so that the file can be obtained through piping.
                    write_bytes(sys.stderr, chunk)
                else:
                    write_bytes(sys.stdout, chunk)
            else:
                self.send_error(400, "Unknown field \"%s\"" % part_name)
                return

        sys.stderr.flush()
        sys.stdout.flush()
        # Print a final new line to make sure that the last line in the
        # terminal appears terminated.
        sys.stderr.write("\n")
        sys.stderr.flush()

        self.send_response(200)
        self.end_headers()
        if did_print_text_info or did_print_file_info:
            self.wfile.write(
                DEFAULT_INDEX_HTML % b"See stdout/stderr (server closed).")
            self.server.shutdown_async()
        else:
            self.wfile.write(
                DEFAULT_INDEX_HTML % b"Did not receive anything, try again.")

    def _handle_raw_post(self):
        BUF_LEN = 0xFFFF

        bodylen = int(self.headers.get("Content-Length", "0"))

        sys.stderr.write("Received data (%d bytes).\n" % bodylen)
        sys.stderr.flush()
        while bodylen > 0:
            data = self.rfile.read(min(BUF_LEN, bodylen))
            bodylen -= len(data)
            write_bytes(sys.stdout, data)

        sys.stdout.flush()

        # Print a final new line to make sure that the last line in the
        # terminal appears terminated.
        sys.stderr.write("\n")
        sys.stderr.flush()

        self.send_response(200)
        self.end_headers()
        self.server.shutdown_async()

    def _iter_body(self):
        """
        Iterator over response body stream. Each chunk contains no CRLF,
        except possibly at the start of each yielded chunk.

        Yields chunks of type type(b"")
        """
        # The maximum size of the buffer. This value is chosen such that a full
        # header line fits (at the very least the boundary separator!), and
        # that the throughput of a large response body is still reasonable.
        BUF_LEN = 0xFFFF
        EMPTY_BUFFER = b""
        CR = b"\r"
        LF = b"\n"

        bodylen = int(self.headers.get("Content-Length", "-1"))
        buffer = EMPTY_BUFFER
        while True:
            data = self.rfile.read(
                    min(bodylen, BUF_LEN) if bodylen > 0 else BUF_LEN)
            bodylen -= len(data)
            buffer += data
            i = 0
            previ = 0
            finali = len(buffer) - 1
            while True:
                # i + 1 at the first iteration, to ignore the leading CRLF.
                # i + 1 at later iterations to find the next CR.
                i = buffer.find(CR, i + 1)
                if i == -1:
                    break
                if i == finali or buffer[i + 1:i + 2] == LF:
                    yield buffer[previ:i]
                    previ = i
                # Otherwise it is certainly a CR without LF. Skip to next CR.

            if previ != 0:
                buffer = buffer[previ:]
            if len(buffer) >= BUF_LEN:
                yield buffer
                buffer = EMPTY_BUFFER
            if not data:
                break
        if buffer:
            yield buffer


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=DOC_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "port", metavar="PORT", type=int,
        help="The port on which the server listens")
    parser.add_argument(
        "--allow-http", action="store_const", const=True,
        help="Allow the form to be used over HTTP (instead of HTTPS only)")
    parser.add_argument(
        "--certfile", metavar="FILE",
        default=os.path.join(sys.path[0], "localhost.pem"),
        help="""
        Path to the SSL certificate for HTTPS.
        Defaults to %(default)s.
        """)
    parser.add_argument(
        "--keyfile", metavar="FILE", default=None,
        help="""
        Path to private key of the SSL certificate.
        Defaults to the path provided by --certfile.
        """)
    args = parser.parse_args()
    if args.allow_http:
        HTTPRequestHandlerClass = RequestHandler
    else:
        HTTPRequestHandlerClass = RedirectToHttpsHandler
    server = HTTPSHTTPServer(
            ("", args.port),
            HTTPRequestHandlerClass=HTTPRequestHandlerClass,
            HTTPSRequestHandlerClass=RequestHandler,
            certfile=args.certfile,
            keyfile=args.keyfile)
    server.serve_forever()
