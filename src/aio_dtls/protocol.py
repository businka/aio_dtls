import logging
from typing import Optional

from .connection_manager.connection import Connection
from .connection_manager.connection_manager import ConnectionManager
from .const import handshake as const_handshake
from .const import tls as const_tls
from .exceptions import TLSCloseNotify, BadMAC, TLSException
from .constructs import tls
from .tls import helper as tls_helper

logger = logging.getLogger(__name__)


class Protocol2:
    protocol_construct = None
    protocol_helper = None
    handshake_handler = None

    def __init__(self,
                 server,
                 connection_manager: ConnectionManager,
                 endpoint,
                 protocol_factory
                 ):
        self.server = server
        self.connection_manager = connection_manager
        self.endpoint = endpoint
        self.app_protocol = protocol_factory(server, endpoint) if protocol_factory else None
        self.connection: Optional[Connection] = None
        self.sender_address: Optional[tuple] = None
        self.writer = None

    def _data_received(self, data, writer):
        logger.debug(f'received from {self.sender_address} {data}')
        self.writer = writer
        self.connection = self.connection_manager.get_connection(self.sender_address)

        records = self.protocol_construct.RawDatagram.parse(data)
        answers = []
        for record in records:
            if self.check_message_number(record):
                continue
            handler = f'received_{str(record.type).lower()}'
            logger.debug(f'processed {handler}')

            answer = getattr(self, handler)(record)
            if answer:
                answers.extend(answer)

        # todo как минимум надо проверять размер ответа
        if answers:
            self.protocol_helper.send_records(self.connection, answers, writer)
        return answers

    def check_message_number(self, record):
        pass

    def received_handshake(self, record):
        self.connection.next_receive_seq += 1
        if self.connection.state.value == const_handshake.ConnectionState.HANDSHAKE_OVER:
            if self.connection.security_params.entity == const_tls.ConnectionEnd.server:
                return self.handshake_handler.received_client_finished(self.connection_manager, self.connection, record)
            else:
                return self.handshake_handler.received_server_finished(self.connection_manager, self.connection, record)
            pass
        else:
            _handler = f'received_{const_tls.HandshakeType(record.fragment[0], None).name.lower()}'
            logger.debug(_handler)
            if hasattr(self.handshake_handler, _handler):
                return getattr(self.handshake_handler, _handler)(self.connection_manager, self.connection, record)
            else:
                raise Exception(f'Not implemented {_handler}')
            pass

    def received_application_data(self, record):
        self.connection.next_receive_seq += 1
        try:
            data = self.protocol_helper.decrypt_ciphertext_fragment(self.connection, record)
        except BadMAC:
            answer = [
                self.protocol_helper.build_alert(self.connection, const_tls.AlertLevel.FATAL,
                                                 const_tls.AlertDescription.BAD_RECORD_MAC)]
            self.connection_manager.close_connection(self.connection)
            logger.info('terminate connection')
            return answer

        logger.info(f'dtls receive seq={record.sequence_number} data {data.block_ciphered.content.hex()}')
        if self.app_protocol:
            self.app_process_received_data(data.block_ciphered.content)

    def app_process_received_data(self, data: bytes):
        raise NotImplemented()

    def app_process_error(self, message):
        raise NotImplemented()

    def received_alert(self, record):
        if self.connection.state.value == const_handshake.ConnectionState.HANDSHAKE_OVER:
            self.connection.next_receive_seq += 1
            data = self.protocol_helper.decrypt_ciphertext_fragment(self.connection, record)
            alert = tls.Alert.parse(data.block_ciphered.content)
            if int(alert.description) == const_tls.AlertDescription.CLOSE_NOTIFY.value:
                record = self.protocol_helper.build_alert(
                    self.connection, const_tls.AlertLevel.WARNING, const_tls.AlertDescription.CLOSE_NOTIFY)
                self.protocol_helper.send_records(self.connection, [record], self.writer)
            else:
                raise NotImplemented()
        else:
            if len(record.fragment) > 2:  # encrypted alert
                # получено после закрытия соединения
                logger.info(f'Receive TLS encrypted alert')
                return
                # self.app_process_error(TLSException('TLS encrypted alert'))
                # self.connection_manager.close_connection(self.connection)
                # return answer
            else:
                self.connection.next_receive_seq += 1
                alert = tls.Alert.parse(record.fragment)
        logger.info(f'Receive TLS Alert {alert.level} {alert.description}')
        self.app_process_error(TLSException(alert.description))
        # self.connection_manager.close_connection(self.connection)

    def received_change_cipher_spec(self, record: tls.RawPlaintext):
        if self.connection.state.value != const_handshake.ConnectionState.HANDSHAKE_OVER:
            self.connection.state.value = const_handshake.ConnectionState.HANDSHAKE_OVER
            return
        raise NotImplemented()
