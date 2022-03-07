import logging
from asyncio import Protocol
from typing import Optional

from .handshake import Handshake
from .helper import Helper
from ..connection_manager.connection_manager import ConnectionManager
from ..const import handshake as const_handshake
from ..constructs import tls
from ..protocol import Protocol2

logger = logging.getLogger(__name__)


class TLSProtocol(Protocol, Protocol2):
    protocol_construct = tls
    protocol_helper = Helper
    handshake_handler = Handshake

    def __init__(self,
                 server,
                 connection_manager: ConnectionManager,
                 endpoint,
                 protocol_factory, *,
                 address=None
                 ):
        Protocol2.__init__(self, server, connection_manager, endpoint, protocol_factory)
        self.sender_address: Optional[tuple] = address
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        self.sender_address = self.transport.get_extra_info('peername')

    def data_received(self, data):
        self._data_received(data, self.transport.write)

    def check_message_number(self, record):
        pass

    def app_process_received_data(self, data):
        self.app_protocol.data_received(data)

    def received_change_cipher_spec(self, record: tls.RawPlaintext):
        if self.connection.state.value != const_handshake.ConnectionState.HANDSHAKE_OVER:
            self.connection.state.value = const_handshake.ConnectionState.HANDSHAKE_OVER
            return
        raise NotImplemented()
