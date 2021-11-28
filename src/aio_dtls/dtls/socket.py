import asyncio
import logging

from ..connection_manager.connection_manager import ConnectionManager
from ..connection_manager.connection import Connection
from ..const import tls as const_tls
from ..constructs import dtls as dtls
from .helper import Helper
from ..dtls.handshake import Handshake
from ..dtls.protocol import DTLSProtocol

logger = logging.getLogger(__name__)


class DtlsSocket:
    def __init__(self, sock, *,
                 # server=None,
                 endpoint=None,
                 # protocol=None,
                 connection_manager=None,
                 certfile=None,
                 do_handshake_on_connect=False,
                 ciphers="NULL"
                 ):
        # self.server = server
        self.endpoint = endpoint
        self._sock = sock
        self._transport = None
        self._protocol = None
        self._address = None
        self.connection_manager = ConnectionManager() if connection_manager is None else connection_manager
        # self.dtls_protocol = DTLSProtocol(
        #     connection_manager=connection_manager,
        # )

        pass

    def sendto(self, data: bytes, address: tuple):
        connection = self.connection_manager.get_connection(address)

        if connection:
            records = Helper.build_application_record(connection, [data])
            Helper.send_records(connection, records, self._sock.sendto)
        else:
            connection.flight_buffer.append(data)
            self.do_handshake(connection)

    def do_handshake(self, connection: Connection):
        self.connection_manager.new_client_connection(connection)
        client_hello = Handshake.build_client_hello(self.connection_manager, connection)
        self._sock.sendto(client_hello, connection.address)
        pass

    def raw_sendto(self, data: bytes, address: tuple):
        self._sock.sendto(data, address)

    @property
    def address(self):
        return self._address

    def bind(self, address):
        self._sock.bind(address)
        self._address = address
        pass

    async def listen(self, server, protocol_factory, *, loop=None):
        if loop is None:
            loop = asyncio.get_event_loop()
        self._transport, self._protocol = await loop.create_datagram_endpoint(
            lambda: DTLSProtocol(
                server,
                self.connection_manager,
                self.endpoint,
                protocol_factory
            ), sock=self._sock)
        _address = self._transport.get_extra_info('socket').getsockname()
        source_port = self._address[1]
        if source_port:
            if source_port != _address[1]:
                raise Exception(f'source port {source_port} not installed')
        else:
            self._address = (self._address[0], _address[1])
