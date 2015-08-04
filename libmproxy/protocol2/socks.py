from __future__ import (absolute_import, print_function, division, unicode_literals)

from ..proxy import ProxyError, Socks5ProxyMode, ProxyError2
from .layer import Layer, ServerConnectionMixin
from .auto import AutoLayer


class Socks5IncomingLayer(Layer, ServerConnectionMixin):
    def __call__(self):
        try:
            s5mode = Socks5ProxyMode(self.config.ssl_ports)
            address = s5mode.get_upstream_server(self.client_conn)[2:]
        except ProxyError as e:
            # TODO: Unmonkeypatch
            raise ProxyError2(str(e), e)

        self.server_address = address

        layer = AutoLayer(self)
        layer()
