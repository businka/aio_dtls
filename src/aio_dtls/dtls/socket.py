import asyncio
import logging
from typing import Optional

from .helper import Helper
from ..connection_manager.connection import Connection
from ..connection_manager.connection_manager import ConnectionManager
from ..const import tls as const_tls
from ..dtls.handshake import Handshake
from ..dtls.protocol import DTLSProtocol

logger = logging.getLogger(__name__)


class DtlsSocket:
    def __init__(self, sock, *,
                 # server=None,
                 endpoint=None,
                 # protocol=None,
                 connection_manager=None,
                 connection_props=None,
                 do_handshake_on_connect=False,
                 ciphers: Optional[list] = None,
                 elliptic_curves: Optional[list] = None,
                 identity_hint: Optional[dict] = None,
                 psk: Optional[str] = None
                 ):
        # self.server = server
        self.endpoint = endpoint
        self.connection_props = connection_props
        self._sock = sock
        self._transport = None
        self._protocol = None
        self._address = None

        self.connection_manager = ConnectionManager(
            identity_hint=identity_hint,
            elliptic_curves=elliptic_curves,
            psk=psk,
            ciphers=ciphers,
        ) if connection_manager is None else connection_manager
        # self.dtls_protocol = DTLSProtocol(
        #     connection_manager=connection_manager,
        # )

        pass

    def sendto(self, data: bytes, address: tuple, **kwargs):
        connection = self.connection_manager.get_connection(address, **kwargs)
        if connection:
            if kwargs:
                new_connection = kwargs.get('new_connection')
                if new_connection:
                    record = Helper.build_alert(
                        connection, const_tls.AlertLevel.WARNING, const_tls.AlertDescription.CLOSE_NOTIFY)
                    connection.new_connection = {
                        'send_alert': 2,
                        'address': address,
                        'params': new_connection,
                        'data': data
                    }
                    Helper.send_records(connection, [record, record], self._sock.sendto)
                    return
        if connection:
            records = Helper.build_application_record(connection, [data])
            Helper.send_records(connection, records, self._sock.sendto)
        else:
            connection.flight_buffer.append(data)
            self.do_handshake(connection)

    # def send_alert(self, level: const_tls.AlertLevel, description: const_tls.AlertDescription, address: tuple,
    #                **kwargs):
    #     connection = self.connection_manager.get_connection(address, **kwargs)
    #     if connection:
    #         records = [Helper.build_alert(connection, level, description)]
    #         Helper.send_records(connection, records, self._sock.sendto)
    #     else:
    #         raise NotImplemented()

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

    def close(self, address=None):
        if address is not None:
            connection = self.connection_manager.get_connection(address)
            if connection:
                record = Helper.build_alert(
                    connection, const_tls.AlertLevel.WARNING, const_tls.AlertDescription.CLOSE_NOTIFY)
                Helper.send_records(connection, [record], self._sock.sendto)
        else:
            self._sock.close()
