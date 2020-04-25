#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import socket
import logging
from io import StringIO
from xml.etree import ElementTree
from http.server import HTTPServer
from socketserver import ThreadingMixIn
from http.server import SimpleHTTPRequestHandler


class NonBlockingHTTPServer(ThreadingMixIn, HTTPServer):
    pass


class WebLogicHandler(SimpleHTTPRequestHandler):
    logger = None

    protocol_version = "HTTP/1.1"

    EXPLOIT_STRING = "</void>"
    PATCHED_RESPONSE = """<?xml version='1.0' encoding='UTF-8'?><S:Envelope xmlns:S="http://schemas.xmlsoap.org/soa""" \
                       """p/envelope/"><S:Body><S:Fault xmlns:ns4="http://www.w3.org/2003/05/soap-envelope"><faultc""" \
                       """ode>S:Server</faultcode><faultstring>Invalid attribute for element void:class</faultstrin""" \
                       """g></S:Fault></S:Body></S:Envelope>"""
    GENERIC_RESPONSE = """<?xml version='1.0' encoding='UTF-8'?><S:Envelope xmlns:S="http://schemas.xmlsoap.org/soa""" \
                       """p/envelope/"><S:Body><S:Fault xmlns:ns4="http://www.w3.org/2003/05/soap-envelope"><faultc""" \
                       """ode>S:Server</faultcode><faultstring>The current event is not START_ELEMENT but 2</faults""" \
                       """tring></S:Fault></S:Body></S:Envelope>"""

    basepath = os.path.dirname(os.path.abspath(__file__))

    alert_function = None

    def setup(self):
        SimpleHTTPRequestHandler.setup(self)
        self.request.settimeout(1)

    def version_string(self):
        return 'WebLogic Server 10.3.6.0.171017 PSU Patch for BUG26519424 TUE SEP 12 18:34:42 IST 2017 WebLogic ' \
               'Server 10.3.6.0 Tue Nov 15 08:52:36 PST 2011 1441050 Oracle WebLogic Server Module Dependencies ' \
               '10.3 Thu Sep 29 17:47:37 EDT 2011 Oracle WebLogic Server on JRockit Virtual Edition Module ' \
               'Dependencies 10.3 Wed Jun 15 17:54:24 EDT 2011'

    def send_head(self):
        # send_head will return a file object that do_HEAD/GET will use
        # do_GET/HEAD are already implemented by SimpleHTTPRequestHandler
        filename = os.path.basename(self.path.rstrip('/'))

        if self.path == '/':
            return self.send_file('404.html', 404)
        elif filename == 'wls-wsat':  # don't allow dir listing
            return self.send_file('403.html', 403)
        else:
            return self.send_file(filename)

    def do_POST(self):
        data_len = int(self.headers.get('Content-length', 0))
        data = self.rfile.read(data_len) if data_len else ''
        if self.EXPLOIT_STRING in data:
            xml = ElementTree.fromstring(data)
            payload = []
            for void in xml.iter('void'):
                for s in void.iter('string'):
                    payload.append(s.text)

            self.alert_function(self, payload)
            body = self.PATCHED_RESPONSE
        else:
            body = self.GENERIC_RESPONSE

        self.send_response(500)
        self.send_header('Content-Length', int(len(body)))
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, filename, status_code=200):
        try:
            with open(os.path.join(self.basepath, 'wls-wsat', filename), 'rb') as fh:
                body = fh.read()
                body = body.replace('%%HOST%%', self.headers.get('Host'))
                self.send_response(status_code)
                self.send_header('Content-Length', int(len(body)))
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                return StringIO(body)
        except IOError:
            return self.send_file('404.html', 404)

    def log_message(self, format, *args):
        self.logger.debug("%s - - [%s] %s" %
                          (self.client_address[0],
                           self.log_date_time_string(),
                           format % args))

    def handle_one_request(self):
        """Handle a single HTTP request.
        Overriden to not send 501 errors
        """
        self.close_connection = True
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.close_connection = 1
                return
            if not self.raw_requestline:
                self.close_connection = 1
                return
            if not self.parse_request():
                # An error code has been sent, just exit
                return
            mname = 'do_' + self.command
            if not hasattr(self, mname):
                self.log_request()
                self.close_connection = True
                return
            method = getattr(self, mname)
            method()
            self.wfile.flush()  # actually send the response if not already done.
        except socket.timeout as e:
            # a read or a write timed out.  Discard this connection
            self.log_error("Request timed out: %r", e)
            self.close_connection = 1
            return

if __name__ == '__main__':
    import click

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger()

    @click.command()
    @click.option('-h', '--host', default='0.0.0.0', help='Host to listen')
    @click.option('-p', '--port', default=8000, help='Port to listen', type=click.INT)
    @click.option('-v', '--verbose', default=False, help='Verbose logging', is_flag=True)
    def start(host, port, verbose):
        """
           A low interaction honeypot for the Oracle Weblogic wls-wsat component capable of detecting CVE-2017-10271,
           a remote code execution vulnerability
        """
        def alert(cls, request, payload):
            logger.critical({
                'src': request.client_address[0],
                'spt': request.client_address[1],
                'destinationServiceName': ' '.join(payload),
            })

        if verbose:
            logger.setLevel(logging.DEBUG)

        requestHandler = WebLogicHandler
        requestHandler.alert_function = alert
        requestHandler.logger = logger

        httpd = HTTPServer((host, port), requestHandler)
        logger.info('Starting server on port {:d}, use <Ctrl-C> to stop'.format(port))
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        logger.info('Stopping server.')
        httpd.server_close()

    start()

