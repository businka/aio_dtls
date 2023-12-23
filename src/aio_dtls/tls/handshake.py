import logging

from .handshake_ecdh_anon import EcdhAnon
from .handshake_ecdhe_ecdsa import EcdheEcdsa
from .helper import Helper
from ..connection_manager import CipherSuites as CipherSuitesHandler
from ..connection_manager.connection import Connection
from ..connection_manager.connection_manager import ConnectionManager
from ..const import tls as const_tls
from ..const.cipher_suites import CipherSuite, CipherSuites
from ..constructs import tls
from ..exceptions import BadMAC

logger = logging.getLogger(__name__)


class Handshake:
    tls = tls
    helper = Helper
    handlers = {
        'ECDH_ANON': EcdhAnon,
        'ECDHE_ECDSA': EcdheEcdsa,
    }

    @classmethod
    def get_handshake_handler(cls, cipher: CipherSuite):
        try:
            _name = f'{cipher.key_exchange}'.upper()
            return cls.handlers[_name]
        except KeyError:
            raise Exception(f'{cipher.name} not supported')

    @classmethod
    def build_client_hello_fragment_data(cls, connection_manager: ConnectionManager, connection: Connection):
        connection.security_params.client_random = connection_manager.generate_tls_random()
        ciphers = connection_manager.ciphers.available_values
        if connection.user_props:
            if 'ciphers' in connection.user_props:
                ciphers = CipherSuitesHandler(connection.user_props['ciphers']).available_values

        return {
            "cipher_suites": ciphers,
            "client_version": connection.ssl_version.value,
            "compression_methods": [const_tls.CompressionMethod.NULL.value],
            "random": connection.security_params.client_random,
            "session_id": b'',
            "extension": [
                {
                    "type": const_tls.ExtensionType.SIGNATURE_ALGORITHMS.value,
                    "data": connection_manager.signature_scheme.max
                },
                {
                    "type": const_tls.ExtensionType.ELLIPTIC_CURVES.value,
                    "data": {"elliptic_curve_list": [const_tls.NamedCurve['secp256r1'].value]}
                },
                # https://datatracker.ietf.org/doc/html/rfc5746
                # {
                #     "type": const_tls.ExtensionType.RENEGOTIATION_INFO.value,
                #     "data": b'\x00'
                # },
                {
                    "type": const_tls.ExtensionType.EXTENDED_MASTER_SECRET.value,
                    "data": b''
                },
                {
                    "type": const_tls.ExtensionType.EC_POINT_FORMATS.value,
                    "data": {"ec_point_format_list": [
                        const_tls.ECPointFormat.uncompressed.value
                    ]}
                }]

        }

    @classmethod
    def build_client_hello(cls, connection_manager: ConnectionManager, connection: Connection):
        fragment = cls.build_client_hello_record(connection_manager, connection)
        client_hello = tls.RawPlaintext.build({
            "type": const_tls.ContentType.HANDSHAKE.value,
            "version": const_tls.ProtocolVersion.TLS_1.value,
            "fragment": fragment
        })
        return client_hello

    @classmethod
    def build_client_hello_record(cls, connection_manager: ConnectionManager, connection: Connection):
        fragment = tls.Handshake.build({
            "handshake_type": const_tls.HandshakeType.CLIENT_HELLO.value,
            "fragment": cls.build_client_hello_fragment_data(connection_manager, connection)
        })
        connection.update_handshake_hash(fragment, clear=True)
        return fragment

    @classmethod
    def received_client_hello(cls, connection_manager: ConnectionManager, connection: Connection, record):
        cls.received_client_hello_prepare(connection_manager, connection, record)
        return cls.received_client_hello_init_session(connection_manager, connection, record)

    @classmethod
    def received_client_hello_prepare(cls, connection_manager: ConnectionManager, connection: Connection, record):
        connection.update_handshake_hash(record.fragment, clear=True, name='client hello')
        record.fragment = cls.tls.Handshake.parse(record.fragment)

    pass

    @classmethod
    def received_client_hello_init_session(cls, connection_manager: ConnectionManager, connection: Connection, record):
        client_hello_data = record.fragment.fragment
        if connection.id not in connection_manager.connections:
            connection_manager.connections[connection.id] = connection

        connection_manager.new_server_connection(connection, record)

        # todo сделать выбор протокола, отказ от обсуживания
        connection.ssl_version = connection_manager.ssl_versions.get_best([record.fragment.fragment.client_version])

        connection.security_params.client_random = client_hello_data.random

        best_cipher = connection_manager.ciphers.get_best(client_hello_data.cipher_suites)
        connection.cipher = best_cipher
        # todo добавить проверку если нет подходящего

        extensions = cls.helper.extensions_to_dict(client_hello_data.extension)

        # todo добавить проверку если сервер не хочет
        connection.handshake_params.extended_master_secret = const_tls.ExtensionType.EXTENDED_MASTER_SECRET.name in extensions

        handler = cls.get_handshake_handler(connection.cipher)
        answers = handler.received_client_hello(connection_manager, connection, record, extensions)
        return answers

    @classmethod
    def received_server_hello(cls, connection_manager: ConnectionManager, connection: Connection, record):
        connection.update_handshake_hash(record.fragment, name='server hello')
        record.fragment = cls.tls.Handshake.parse(record.fragment)

        server_hello_data = record.fragment.fragment
        connection.security_params.server_random = server_hello_data.random
        connection.cipher = CipherSuites[server_hello_data.cipher_suite]

        extensions = cls.helper.extensions_to_dict(server_hello_data.extension)

        ext_master_secret = const_tls.ExtensionType.EXTENDED_MASTER_SECRET.name
        connection.handshake_params.extended_master_secret = ext_master_secret in extensions

        handler = cls.get_handshake_handler(connection.cipher)
        return handler.received_server_hello(connection_manager, connection, record, extensions)

    @classmethod
    def received_server_key_exchange(cls, connection_manager: ConnectionManager, connection: Connection, record):
        connection.update_handshake_hash(record.fragment, name='server key exchange')
        logger.info(f'connection cipher {connection.cipher}')
        handler = cls.get_handshake_handler(connection.cipher)
        handler.received_server_key_exchange(connection_manager, connection, record)

    @classmethod
    def received_server_hello_done(cls, connection_manager: ConnectionManager, connection: Connection, record):
        connection.update_handshake_hash(record.fragment, name='server hello done')
        handler = cls.get_handshake_handler(connection.cipher)
        answer = handler.received_server_hello_done(connection_manager, connection, record)

        connection.security_params.master_secret = cls.helper.generate_master_secret(connection)

        cls.helper.calc_pending_states(connection)
        fragment_client_finished = cls.build_handshake_fragment_finished(connection)
        connection.update_handshake_hash(fragment_client_finished, name='client finished')
        fragment_client_finished = cls.helper.encrypt_ciphertext_fragment(
            connection, const_tls.ContentType.HANDSHAKE, fragment_client_finished)

        logger.debug(f'fragment_client_finished {fragment_client_finished.hex(" ")}')

        logger.debug('build client finished')
        answer.append(cls.helper.build_handshake_answer(connection, fragment_client_finished))
        return answer
        pass

    @classmethod
    def received_client_key_exchange(cls, connection_manager: ConnectionManager, connection: Connection, record):
        connection.update_handshake_hash(record.fragment, name='client key exchange')
        record.fragment = cls.tls.Handshake.parse(record.fragment)
        handler = cls.get_handshake_handler(connection.cipher)
        return handler.received_client_key_exchange(connection_manager, connection, record)

    @classmethod
    def received_client_finished(cls, connection_manager: ConnectionManager, connection: Connection, record):
        cls.helper.calc_pending_states(connection)
        logger.debug(f'receive encrypted client finished {record.fragment.hex(" ")}')
        try:
            block_cipher = cls.helper.decrypt_ciphertext_fragment(connection, record)
        except BadMAC:
            answer = [cls.helper.build_alert(connection, const_tls.AlertLevel.FATAL,
                                             const_tls.AlertDescription.BAD_RECORD_MAC)]
            connection_manager.close_connection(connection)
            return answer
        logger.debug(f'receive client finished {block_cipher.block_ciphered.content.hex(" ")}')
        handshake_data = cls.tls.Handshake.parse(block_cipher.block_ciphered.content)
        incoming_verify_data = handshake_data.fragment.verify_data

        verify_data = cls.helper.generate_finished_verify_data(connection, b'client finished')

        if incoming_verify_data != verify_data:
            logger.debug(f'verify data {verify_data.hex(" ")}')
            logger.debug(f'incoming verify data {incoming_verify_data.hex(" ")}')
            answer = [
                cls.helper.build_alert(connection, const_tls.AlertLevel.ALERT_MESSAGE,
                                       const_tls.AlertDescription.ENCRYPTED_ALERT)]
            connection_manager.close_connection(connection)
            return answer

        answer = [cls.helper.build_change_cipher(connection)]

        connection.update_handshake_hash(block_cipher.block_ciphered.content, name='client finished')

        fragment_server_finished = cls.build_handshake_fragment_finished(connection)
        # connection.update_handshake_hash(fragment_server_finished, name='server finished')
        fragment_server_finished = cls.helper.encrypt_ciphertext_fragment(
            connection, const_tls.ContentType.HANDSHAKE, fragment_server_finished)

        answer.append(cls.helper.build_handshake_answer(connection, fragment_server_finished))

        return answer

    @classmethod
    def build_handshake_fragment_finished(cls, connection: Connection):

        is_client = connection.security_params.entity == const_tls.ConnectionEnd.client
        label = b'client finished' if is_client else b'server finished'

        verify_data = cls.helper.generate_finished_verify_data(connection, label)

        logger.debug(f'verify data: {verify_data.hex(" ")}')

        fragment = cls.helper.build_handshake_fragment(connection, const_tls.HandshakeType.FINISHED,
                                                       tls.Finished.build({'verify_data': verify_data}))

        logger.debug(f'finished: {fragment.hex(" ")}')
        return fragment

    @classmethod
    def received_server_finished(cls, connection_manager: ConnectionManager, connection: Connection, record):
        block_cipher = cls.helper.decrypt_ciphertext_fragment(connection, record)
        handshake_data = cls.tls.Handshake.parse(block_cipher.block_ciphered.content)
        incoming_verify_data = handshake_data.fragment.verify_data
        logger.debug(f'handshake msg server finished {connection.handshake_params.full_handshake_messages.hex(" ")}')
        verify_data = cls.helper.generate_finished_verify_data(connection, b'server finished')

        if incoming_verify_data != verify_data:
            raise Exception('wrong verify data')  # todo return Alert

        mac = cls.helper.build_mac(connection, record, connection.server_mac_func,
                                   const_tls.ContentType.HANDSHAKE.value, block_cipher.block_ciphered.content)

        if block_cipher.block_ciphered.MAC != mac:
            answer = [cls.helper.build_alert(connection, const_tls.AlertLevel.FATAL,
                                             const_tls.AlertDescription.BAD_RECORD_MAC)]
            connection_manager.close_connection(connection)
            return answer

        return cls.helper.build_application_record(connection, connection.flight_buffer)
