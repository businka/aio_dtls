from typing import Optional
from aio_dtls import ConnectionManager, TlsSocket
from datetime import datetime
from aio_dtls.tls.protocol import TLSProtocol
from aio_dtls.constructs.tls import Random


class DemoTransport:
    def __init__(self, address):
        self.address = address
        self.send_data = []

    def write(self, data):
        self.send_data.append(data)

    def get_extra_info(self, key):
        return self.address


class DemoTlsSocket(TlsSocket):
    def __init__(self, *,
                 # server=None,
                 endpoint=None,
                 # protocol=None,
                 connection_manager=None,
                 certfile=None,
                 do_handshake_on_connect=False,
                 ciphers: Optional[list] = None,
                 elliptic_curves=None,
                 protocol: TLSProtocol = None
                 ):
        super(DemoTlsSocket, self).__init__(
            endpoint=endpoint,
            # protocol=None,
            connection_manager=connection_manager,
            certfile=None,
            do_handshake_on_connect=do_handshake_on_connect,
            ciphers=ciphers,
            elliptic_curves=None
        )
        self.protocol = protocol

    async def connect(self, address):
        self._writer = DemoTransport(address)
        self._address = address
        self.protocol.connection_made(self._writer)
        pass

    def raw_send(self, data: bytes):
        self._writer.write(data)

    def listen(self, server, protocol_factory, host, port, *, loop=None):
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
