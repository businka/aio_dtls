import logging
from asyncio import DatagramProtocol
from typing import Optional

from .handshake import Handshake
from .helper import Helper
from ..connection_manager.connection import Connection
from ..connection_manager.connection_manager import ConnectionManager
from ..const import handshake as const_handshake
from ..const import tls as const_tls
from ..constructs import tls, dtls
from ..tls import helper as tls_helper

logger = logging.getLogger(__name__)


class DTLSProtocol(DatagramProtocol):
    def __init__(self,
                 server,
                 connection_manager: ConnectionManager,
                 endpoint,
                 protocol_factory
                 ):
        self.server = server
        self.connection_manager = connection_manager
        self.endpoint = endpoint
        self.app_protocol = protocol_factory(server, endpoint)
        self.connection: Optional[Connection] = None
        # self.record: Datagram = None
        self.sender_address = None

    def datagram_received(self, data, sender_address):
        logger.debug(f'datagram received from {sender_address} {data}')
        self.connection = self.connection_manager.get_connection(sender_address)
        self.sender_address = sender_address

        records = dtls.RawDatagram.parse(data)
        answers = []
        for record in records:
            logger.debug(f'received seq_num {record.sequence_number} epoch {record.epoch})')
            logger.debug(f'current next seq_num {self.connection.next_receive_seq}'
                         f' epoch {self.connection.next_receive_epoch}')
            if (record.sequence_number < self.connection.next_receive_seq
                and record.epoch == self.connection.next_receive_epoch) \
                    or record.epoch < self.connection.next_receive_epoch:
                logger.debug(f'skip record')
                continue

            self.connection.next_receive_seq += 1
            handler = f'received_{str(record.type).lower()}'
            logger.debug(f'processed {handler}')

            answer = getattr(self, handler)(record)
            if answer:
                answers.extend(answer)
            # todo как минимум надо проверять размер ответа
        if answers:
            Helper.send_records(self.connection, answers, self.endpoint.raw_sendto)

    def received_handshake(self, record):
        if self.connection.state.value == const_handshake.ConnectionState.HANDSHAKE_OVER:
            if self.connection.security_params.entity == const_tls.ConnectionEnd.server:
                return Handshake.received_client_finished(self.connection_manager, self.connection, record)
            else:
                return Handshake.received_server_finished(self.connection_manager, self.connection, record)
            pass
        else:
            _handler = f'received_{const_tls.HandshakeType(record.fragment[0]).name.lower()}'
            logger.debug(_handler)
            if hasattr(Handshake, _handler):
                return getattr(Handshake, _handler)(self.connection_manager, self.connection, record)
            else:
                raise Exception(f'Not implemented {_handler}')
            pass

    def received_change_cipher_spec(self, record: dtls.RawPlaintext):
        if record.epoch < self.connection.next_receive_epoch:
            return
        self.connection.next_receive_epoch += 1
        self.connection.next_receive_seq = 0
        if self.connection.state.value != const_handshake.ConnectionState.HANDSHAKE_OVER:
            self.connection.state.value = const_handshake.ConnectionState.HANDSHAKE_OVER
            return
        raise NotImplemented()

    def received_alert(self, record: tls.RawPlaintext):
        alert = tls.Alert.parse(record.fragment)
        raise Exception(f'TLS {alert.level} {alert.description}')
        pass

    def received_application_data(self, record: tls.RawPlaintext):
        try:
            data = Helper.decrypt_ciphertext_fragment(self.connection, record)
        except tls_helper.BadMAC:
            answer = [Helper.build_alert(const_tls.AlertLevel.FATAL, const_tls.AlertDescription.BAD_RECORD_MAC)]
            self.connection_manager.terminate_connection(self.connection)
            return answer
        if self.app_protocol:
            self.app_protocol.datagram_received(data.block_ciphered.content, self.sender_address)
