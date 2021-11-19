import logging
from asyncio import Protocol
from typing import Optional, List

from . import helper as tls_helper
from .handshake import Handshake
from ..connection_manager.connection import Connection
from ..connection_manager.connection_manager import ConnectionManager
from ..const import handshake as const_handshake
from ..const.tls import HandshakeType, ConnectionEnd
from ..constructs import tls

logger = logging.getLogger(__name__)


class TLSProtocol(Protocol):
    def __init__(self,
                 server,
                 connection_manager: ConnectionManager,
                 endpoint,
                 protocol_factory, *,
                 address=None
                 ):
        self.server = server
        self.connection_manager = connection_manager
        self.endpoint = endpoint
        self.app_protocol = protocol_factory(server, endpoint) if protocol_factory else None
        self.connection: Optional[Connection] = None
        self.sender_address: Optional[tuple] = address
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        self.sender_address = self.transport.get_extra_info('peername')

    def data_received(self, data):
        logger.debug(f'received from {self.sender_address} {data}')
        self.connection = self.connection_manager.get_connection(self.sender_address)

        records = tls.RawDatagram.parse(data)
        answers = []
        for record in records:
            handler = f'received_{str(record.type).lower()}'
            answer = getattr(self, handler)(record)
            if answer:
                answers.extend(answer)

        # todo как минимум надо проверять размер ответа
        if answers:
            plaintext = self.build_plaintext(self.connection, answers)
            self.transport.write(plaintext)
        return answers

    def received_handshake(self, record: tls.RawPlaintext):
        if self.connection.state.value == const_handshake.ConnectionState.HANDSHAKE_OVER:
            if self.connection.security_params.entity == ConnectionEnd.server:
                return Handshake.received_client_finished(self.connection_manager, self.connection, record)
            else:
                return Handshake.received_server_finished(self.connection_manager, self.connection, record)
            pass
        else:
            _handler = f'received_{HandshakeType(record.fragment[0]).name.lower()}'
            print(_handler)
            if hasattr(Handshake, _handler):
                return getattr(Handshake, _handler)(self.connection_manager, self.connection, record)
            else:
                raise Exception(f'Not implemented {_handler}')
            pass

    def received_application_data(self, record: tls.RawPlaintext):
        data = tls_helper.decrypt_ciphertext_fragment(self.connection, record, tls_helper)
        if self.app_protocol:
            self.app_protocol.data_received(data.content)

    def received_change_cipher_spec(self, record: tls.RawPlaintext):
        if self.connection.state.value != const_handshake.ConnectionState.HANDSHAKE_OVER:
            self.connection.state.value = const_handshake.ConnectionState.HANDSHAKE_OVER
            return
        raise NotImplemented()

    def received_alert(self, record: tls.RawPlaintext):
        alert = tls.Alert.parse(record.fragment)
        raise Exception(f'TLS {alert.level} {alert.description}')
        pass

    @classmethod
    def build_plaintext(cls, connection: Connection, records_data: List[tls.AnswerRecord]):
        records = []
        for record in records_data:
            records.append({
                "type": record.content_type,
                "version": connection.ssl_version.value,
                "fragment": record.fragment
            })
        plaintext = tls.RawDatagram.build(records)
        return plaintext
