import asyncio
import unittest
from socket import AF_INET, IPPROTO_UDP, SOCK_DGRAM, socket

from aio_dtls.dtls.socket import DtlsSocket
from tests.dtls_test_obj import DemoProtocolClass


class DemoDtlsEndpoint2:
    def __init__(self, *, address=None):
        self._address = address
        _sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        self._sock = DtlsSocket(_sock, endpoint=self)
        self._sock.bind(address)

    @property
    def address(self):
        return self._address[0], self._address[1]

    async def listen(self, app_protocol_factory):
        await self._sock.listen(None, app_protocol_factory)

    def sendto(self, data, address):
        self._sock.sendto(data, address)
        # server_protocol.datagram_received(data, self._address)

    def raw_sendto(self, data, address):
        self._sock.raw_sendto(data, address)


class TestServer(unittest.IsolatedAsyncioTestCase):
    async def test_server(self):
        self.server_address = ('192.168.1.13', 20103)

        self.server_endpoint = DemoDtlsEndpoint2(address=self.server_address)
        await self.server_endpoint.listen(DemoProtocolClass)
        await asyncio.sleep(999)
