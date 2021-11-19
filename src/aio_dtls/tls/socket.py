import asyncio
import logging
from typing import Optional

from ..connection_manager.connection_manager import ConnectionManager
from ..tls.handshake import Handshake
from ..tls.protocol import TLSProtocol

logger = logging.getLogger(__name__)


class TlsSocket:
    def __init__(self, *,
                 # server=None,
                 endpoint=None,
                 # protocol=None,
                 connection_manager=None,
                 certfile=None,
                 do_handshake_on_connect=False,
                 ciphers: Optional[list] = None,
                 elliptic_curves=None
                 ):
        self.endpoint = endpoint
        self._server = None
        self._reader = None
        self._writer = None
        self._sock = None
        self._address = None
        self.connection_manager = ConnectionManager(
            ciphers=ciphers,
            elliptic_curves=elliptic_curves,
            is_dtls=False
        ) if connection_manager is None else connection_manager

        pass

    async def connect(self, address):
        self._reader, self._writer = await asyncio.open_connection(address[0], address[1])
        self._address = address
        pass

    async def send(self, data: bytes):
        if not self._address or not self._writer:
            raise Exception('dest not found')
        connection = self.connection_manager.get_connection(self._address)
        if not connection:
            await self.do_handshake(connection)
            pass
        pass

    async def do_handshake(self, connection):
        self.connection_manager.new_client_connection(connection)

        client_hello = Handshake.build_client_hello(self.connection_manager, connection)

        self._writer.write(client_hello)
        protocol = TLSProtocol(
            None,
            self.connection_manager,
            self.endpoint,
            None,
            address=self._address
        )
        protocol.transport = self._writer
        while True:
            data = await self._reader.read(4096)
            send_data = protocol.data_received(data)
            # self._writer.write(send_data)
            pass

    def raw_send(self, data: bytes):
        self._writer.write(data)

    @property
    def address(self):
        return self._address

    async def listen(self, server, protocol_factory, host, port, *, loop=None):
        if loop is None:
            loop = asyncio.get_event_loop()

        self._server = await loop.create_server(
            lambda: TLSProtocol(
                server,
                self.connection_manager,
                self.endpoint,
                protocol_factory
            ), host, port)

        self._sock = self._server.sockets[0]
