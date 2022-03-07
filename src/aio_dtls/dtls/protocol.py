import logging
from asyncio import DatagramProtocol

from .handshake import Handshake
from .helper import Helper
from ..connection_manager.connection_manager import ConnectionManager
from ..const import handshake as const_handshake
from ..constructs import dtls
from ..protocol import Protocol2

logger = logging.getLogger(__name__)


class DTLSProtocol(DatagramProtocol, Protocol2):
    protocol_construct = dtls
    protocol_helper = Helper
    handshake_handler = Handshake

    def __init__(self,
                 server,
                 connection_manager: ConnectionManager,
                 endpoint,
                 protocol_factory
                 ):
        Protocol2.__init__(self, server, connection_manager, endpoint, protocol_factory)
        self.sender_address = None

    def datagram_received(self, data, sender_address):
        self.sender_address = sender_address
        self._data_received(data, self.endpoint.raw_sendto)

    def check_message_number(self, record):
        if record.sequence_number == 0 and record.epoch == 0 and self.connection.next_receive_epoch:  # новая сессия
            self.connection_manager.close_connection(self.connection)
            self.connection = self.connection_manager.get_connection(self.sender_address)
            return False
        if (record.sequence_number < self.connection.next_receive_seq
            and record.epoch == self.connection.next_receive_epoch) \
                or record.epoch < self.connection.next_receive_epoch:
            logger.debug(f'skip record')
            return True
        return False

    def app_process_received_data(self, data):
        self.app_protocol.datagram_received(data, self.sender_address)

    def app_process_error(self, exception):
        self.app_protocol.error_received(exception, self.sender_address)

    def received_change_cipher_spec(self, record: dtls.RawPlaintext):
        if record.epoch < self.connection.next_receive_epoch:
            return
        self.connection.next_receive_epoch += 1
        self.connection.next_receive_seq = 0
        if self.connection.state.value != const_handshake.ConnectionState.HANDSHAKE_OVER:
            self.connection.state.value = const_handshake.ConnectionState.HANDSHAKE_OVER
            return
        raise NotImplemented()
