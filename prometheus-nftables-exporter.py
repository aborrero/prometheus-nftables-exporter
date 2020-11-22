#!/usr/bin/env python3

# (C) 2020 by Arturo Borrero Gonzalez <arturo@netfilter.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#

import argparse
import logging
import nftables
import urllib
import json
import traceback
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
from socketserver import ForkingMixIn
from nftables.nftables import Nftables
from prometheus_client import (
    CollectorRegistry,
    generate_latest,
    Gauge,
    CONTENT_TYPE_LATEST,
)


class Context:
    def __init__(self):
        self.args = None
        self.nft = None
        self.ruleset = None
        self.metrics = None


def load_nft_ruleset():
    logging.debug("loading nft ruleset")
    rc, output, error = ctx.nft.cmd("list ruleset")
    if rc != 0:
        logging.error(error)

    logging.debug(output)
    ctx.ruleset = json.loads(output)["nftables"]


def _find_objs(type):
    return [o for o in ctx.ruleset if type in o]


def generate_table_metrics():
    for i in _find_objs("table"):
        ctx.metrics.append(
            'nft_table{{family="{}", name="{}"}} 1'.format(
                i["table"]["family"], i["table"]["name"]
            )
        )


def generate_chain_metrics():
    for i in _find_objs("chain"):
        ctx.metrics.append(
            'nft_chain{{family="{}", table="{}", name="{}"}} 1'.format(
                i["chain"]["family"], i["chain"]["table"], i["chain"]["name"]
            )
        )


def generate_counter_metrics():
    for i in _find_objs("counter"):
        ctx.metrics.append(
            'nft_counter_packets{{family="{}", table="{}", name="{}"}} {}'.format(
                i["counter"]["family"],
                i["counter"]["table"],
                i["counter"]["name"],
                i["counter"]["packets"],
            )
        )
        ctx.metrics.append(
            'nft_counter_bytes{{family="{}", table="{}", name="{}"}} {}'.format(
                i["counter"]["family"],
                i["counter"]["table"],
                i["counter"]["name"],
                i["counter"]["bytes"],
            )
        )


def generate_metrics():
    ctx.metrics = []
    load_nft_ruleset()
    generate_table_metrics()
    generate_chain_metrics()
    generate_counter_metrics()


class ForkingHTTPServer(ForkingMixIn, HTTPServer):
    pass


class PrometheusNftablesExporterHttpHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        if url.path == "/metrics":
            try:
                generate_metrics()
                self.send_response(200)
                self.send_header("Content-Type", CONTENT_TYPE_LATEST)
                self.end_headers()
                self.wfile.write("\n".join(ctx.metrics).encode("utf-8"))
            except Exception:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(traceback.format_exc())
        elif url.path == "/":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(
                """<html>
            <head><title>prometheus nftables exporter</title></head>
            <body>
            <h1>prometheus nftables exporter</h1>
            <p>Visit <code>/metrics</code> to use.</p>
            </body>
            </html>""".encode(
                    "utf-8"
                )
            )
        else:
            self.send_response(404)
            self.end_headers()


def http_handler(*args, **kwargs):
    PrometheusNftablesExporterHttpHandler(*args, **kwargs)


def parse_args():
    description = "prometheus nftables exporter"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "--run-once",
        action="store_true",
        help="just print the metrics, don't run the HTTP server",
    )
    parser.add_argument(
        "-p",
        "--listen-port",
        default="12345",
        type=int,
        help="TCP port to use to serve prometheus metrics endpoint. "
        "Defaults to '%(default)s'",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="activate debug mode",
    )

    return parser.parse_args()


def configure_logging():
    if ctx.args.debug:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.INFO

    bold_start = "\033[1m"
    bold_end = "\033[0m"
    logging_format = "{}[%(filename)s]{} %(levelname)s: %(message)s".format(
        bold_start, bold_end
    )
    logging.basicConfig(format=logging_format, level=logging_level)


def configure_nftables():
    ctx.nft = Nftables()
    ctx.nft.set_json_output(True)
    ctx.nft.set_stateless_output(False)
    ctx.nft.set_service_output(False)
    ctx.nft.set_reversedns_output(False)
    ctx.nft.set_numeric_proto_output(True)


def configure_http_server():
    server_address = ("", ctx.args.listen_port)
    http_server = ForkingHTTPServer(server_address, http_handler)
    http_server.serve_forever()


# global data
ctx = Context()


def main():
    global ctx
    ctx.args = parse_args()

    configure_logging()
    configure_nftables()

    if ctx.args.run_once:
        generate_metrics()
        print("\n".join(ctx.metrics))
        exit(0)

    configure_http_server()


if __name__ == "__main__":
    main()
