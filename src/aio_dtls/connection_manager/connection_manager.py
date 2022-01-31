import hashlib
import hmac
import secrets
import time
from datetime import datetime
from uuid import uuid4

from . import ECPointFormats, SSlVersions, EllipticCurves, CompressionMethods, CipherSuites, SignatureScheme
from .connection import Connection
from ..const import handshake as const_handshake
from ..const import tls as const_tls
from ..constructs.tls import Random
from typing import Optional


class ConnectionManager:
    def __init__(self, *, secret=None, connections=None, ssl_versions=None, ec_point_formats=None,
                 compression_methods=None, signature_scheme=None, unittest_mode=False, is_dtls=True,
                 ciphers: Optional[list] = None,
                 elliptic_curves: Optional[list] = None,
                 identity_hint: Optional[str] = None,
                 psk: Optional[str] = None,
                 **kwargs):

        self.unittest_mode = unittest_mode
        self.secret = secret if secret else [str(uuid4())]
        self.connections = connections if connections else {}
        self.ssl_versions = SSlVersions(ssl_versions, is_dtls)
        self.elliptic_curves = EllipticCurves(elliptic_curves)
        self.ec_point_formats = ECPointFormats(ec_point_formats)
        self.ciphers = CipherSuites(ciphers)
        self.compression_methods = CompressionMethods(compression_methods)
        self.signature_scheme = SignatureScheme(signature_scheme)
        self.private_key = None
        self.identity_hint = identity_hint
        self.psk = psk

    def get_connection(self, address, **kwargs):
        try:
            connection = self.connections[Connection.get_id(address)]
            if kwargs:
                connection.user_props = kwargs
            return connection
        except KeyError:
            return Connection(address, **kwargs)

    def new_client_connection(self, connection: Connection):
        connection.ssl_version = self.ssl_versions.default
        connection.state.value = const_handshake.ConnectionState.HELLO_REQUEST
        connection.security_params.entity = const_tls.ConnectionEnd.client
        self.connections[connection.id] = connection

    def new_server_connection(self, connection: Connection, record):
        connection.security_params.entity = const_tls.ConnectionEnd.server
        connection.state.value = const_handshake.ConnectionState.HELLO_REQUEST
        connection.uid = secrets.token_bytes(32)
        connection.begin = datetime.now()
        connection.ssl_version = self.ssl_versions.default

    def get_cookie(self, connection: Connection):
        if self.unittest_mode:
            url = f'{connection.address[0]}'.encode()
        else:
            url = f'{connection.address[0]}:{connection.address[1]}'.encode()
        signing = hmac.new(self.secret[-1].encode(), url, hashlib.sha256)
        return signing.digest()

    @classmethod
    def generate_tls_random(cls):
        return Random.build({
            "gmt_unix_time": int(time.time()),
            "random_bytes": secrets.token_bytes(28)
        })

    @classmethod
    def generate_tls_session_id(cls):
        return secrets.token_bytes(32)

    def get_ec_private_key(self, elliptic_curve):
        from cryptography.hazmat.primitives.asymmetric import ec

        return ec.generate_private_key(elliptic_curve)

    def close_connection(self, connection):
        try:
            del self.connections[connection.id]
        except KeyError:
            pass
