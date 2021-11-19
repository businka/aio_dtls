from . import helper as dtls_helper
from .handshake_ecdh_anon import EcdhAnon
from ..connection_manager.connection import Connection
from ..connection_manager.connection_manager import ConnectionManager
from ..const import tls as const_tls
from ..constructs import dtls
from ..tls.handshake import Handshake as TlsHandshake


class Handshake(TlsHandshake):
    tls = dtls
    tls_helper = dtls_helper
    handlers = {
        'ECDH_ANON': EcdhAnon
    }

    @classmethod
    def build_client_hello(cls, connection_manager: ConnectionManager, connection: Connection):
        answer = cls.build_client_hello_record(connection_manager, connection)
        client_hello = dtls.RawPlaintext.build({
            "type": const_tls.ContentType.HANDSHAKE.value,
            "version": connection_manager.ssl_versions.default.value,
            "epoch": connection.epoch,
            "sequence_number": connection.get_sequence_number(),
            "fragment": answer.fragment
        })
        return client_hello

    @classmethod
    def build_client_hello_record(cls, connection_manager: ConnectionManager, connection: Connection):
        data = Handshake.build_client_hello_fragment_data(connection_manager, connection)
        data['cookie'] = connection.cookie
        fragment = dtls.ClientHello.build(data)
        return dtls_helper.build_handshake_record(connection, const_tls.HandshakeType.CLIENT_HELLO, fragment, True)

    @classmethod
    def build_hello_verify_request(cls, connection_manager: ConnectionManager, connection: Connection, record,
                                   trust_cookie):
        _hello_verify_request = dtls.HelloVerifyRequest.build(dict(
            server_version=connection.ssl_version.value,
            cookie=trust_cookie
        ))
        return [
            dtls_helper.build_handshake_record(connection, const_tls.HandshakeType.HELLO_VERIFY_REQUEST,
                                               _hello_verify_request
                                               )]

    @classmethod
    def received_client_hello(cls, connection_manager: ConnectionManager, connection: Connection, record):
        cls.received_client_hello_prepare(connection_manager, connection, record)
        cookie = record.fragment.fragment.cookie
        trust_cookie = connection_manager.get_cookie(connection)

        client_hello_data = record.fragment.fragment

        if cookie == trust_cookie:
            pass
        else:
            # если пришел запрос без или неправильным cookie возвращаем hello_verify_request
            connection.sequence_number = record.sequence_number
            connection.message_seq = 0
            connection.ssl_version = connection_manager.ssl_versions.get_best([client_hello_data.client_version])
            return cls.build_hello_verify_request(connection_manager, connection, record, trust_cookie)

        connection.security_params.client_random = client_hello_data.random
        connection.message_seq = 1
        return cls.received_client_hello_init_session(connection_manager, connection, record)

    @classmethod
    def received_hello_verify_request(cls, connection_manager: ConnectionManager, connection: Connection, record):
        record.fragment = dtls.Handshake.parse(record.fragment)
        hello_verify_request_data = record.fragment.fragment
        cookie = hello_verify_request_data.cookie
        connection.cookie = cookie
        connection.next_receive_seq = 0
        answer = Handshake.build_client_hello_record(connection_manager, connection)
        return [answer]
