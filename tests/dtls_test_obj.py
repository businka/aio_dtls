from datetime import datetime

from aio_dtls import ConnectionManager, DtlsSocket
from aio_dtls.constructs.tls import Random
from aio_dtls.dtls.protocol import DTLSProtocol


class DemoProtocolClass:
    def __init__(self, server=None, endpoint=None):
        self.last_data = None
        self.last_client_address = None

    def datagram_received(self, data, client_address):
        self.last_data = data
        self.last_client_address = client_address


class DemoSocket:
    def __init__(self):
        self.sending_data = []

    def sendto(self, data, address):
        self.sending_data.append((data, address))


class DemoDtlsEndpoint:
    def __init__(self, *, address=None, **kwargs):
        self._address = address
        self._sock = DemoDtlsSocket(DemoSocket(), endpoint=self, **kwargs)
        self._sock.bind(address)

    @property
    def address(self):
        return self._address[0], self._address[1]

    def listen(self, app_protocol_factory):
        self._sock.listen_demo(app_protocol_factory)

    def sendto(self, data, address):
        self._sock.sendto(data, address)
        # server_protocol.datagram_received(data, self._address)

    def raw_sendto(self, data, address):
        self._sock.raw_sendto(data, address)


class DemoDtlsSocket(DtlsSocket):
    def __init__(self, sock, **kwargs):
        super(DemoDtlsSocket, self).__init__(sock, **kwargs)
        self.connection_manager = DemoConnectionManager(secret='test', **kwargs)

        self.protocol = None
        self.demo_app_protocol = None

    def listen_demo(self, app_protocol_fabric):
        self.demo_app_protocol = app_protocol_fabric
        self.protocol = DTLSProtocol(None, self.connection_manager, self.endpoint, app_protocol_fabric)

    def bind(self, address):
        pass


class DemoConnectionManager(ConnectionManager):
    random = Random.build(dict(
        gmt_unix_time=1632034046,
        random_bytes=b'*\x87G\xb7 \xc5\xae\r\xf0\x91\x9b\xd5n\x0e<k%\xa8\x1a\x83\xe19\xdf\x98\xd7\xbd\xc3\xaa'
    ))

    @classmethod
    def generate_tls_random(cls):
        return cls.random

    def get_ec_private_key(self, elliptic_curve):
        # from aio_dtls.protocol.handshake_ecdh_anon import generate_elliptic_curve_private_key
        # private_key_raw = generate_elliptic_curve_private_key(elliptic_curve)

        from cryptography.hazmat.primitives import serialization
        private_key_raw = b'-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJ0SgzfKARhFl6qjW\nPzUc2cBvuokYTRExh7hP+QUJsvChRANCAATALtMnRKCU4lhd4Vsz7RlR4fyonFdu\n3n2sy6AXFRCS1N0hSLx1sqoxADAn9nFLR4/oMwnTokBiBijtlJdNaRZi\n-----END PRIVATE KEY-----\n'
        return serialization.load_pem_private_key(private_key_raw, password=None)

    def new_server_connection(self, connection, record):
        super(DemoConnectionManager, self).new_server_connection(connection, record)
        connection.uid = b'*\x87G\xb7 \xc5\xae\r\xf0\x91\x9b\xd5n\x0e<k%\xa8\x1a\x83\xe19\xdf\x98\xd7\xbd\xc3\xaa'
        connection.begin = datetime(2021, 1, 1, 1, 1, 1)
