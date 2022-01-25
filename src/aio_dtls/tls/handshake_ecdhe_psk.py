import logging

from .helper import Helper
from ..connection_manager.connection import Connection
from ..connection_manager.connection_manager import ConnectionManager
from ..constructs import tls
from ..tls.handshake_ecdh_anon import EcdhAnon as TlsEcdhAnon

# rfc5489

logger = logging.getLogger(__name__)


class EcdhePsk(TlsEcdhAnon):
    key_exchange_algorithm = 'ec_diffie_hellman_psk'
    tls_construct = tls
    helper = Helper

    @classmethod
    def received_server_key_exchange(cls, connection_manager: ConnectionManager, connection: Connection, record):
        connection_manager = connection_manager

        raw_handshake_message = record.fragment
        record.fragment = cls.tls_construct.Handshake.parse(raw_handshake_message)

        _premaster_secret = cls.generate_client_shared_key(connection_manager, connection, record)
        pass
