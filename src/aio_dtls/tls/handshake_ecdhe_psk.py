import logging

from .helper import Helper
from ..connection_manager.connection import Connection
from ..connection_manager.connection_manager import ConnectionManager
from ..const.tls import ECCurveType
from ..constructs import tls
from ..constructs import tls_ecc
from ..tls.handshake_ecdh_anon import EcdhAnon as TlsEcdhAnon

# rfc5489

logger = logging.getLogger(__name__)


class EcdhePsk(TlsEcdhAnon):
    key_exchange_algorithm = 'ec_diffie_hellman_psk'
    tls_construct = tls
    helper = Helper

    @classmethod
    def received_server_key_exchange(cls, connection_manager: ConnectionManager, connection: Connection, record):
        super().received_server_key_exchange(connection_manager, connection, record)
        print('hint', record.fragment.fragment.psk_identity_hint.hex(" "))
        if record.fragment.fragment.psk_identity_hint != connection.user_props['identity_hint']:
            print('!!! bad psk identity hint !!!')
            pass  # todo кидать алерт если не равны
        pass

    @classmethod
    def build_handshake_fragment_server_key_exchange(cls, connection_manager: ConnectionManager,
                                                     connection: Connection,
                                                     record):
        server_public_key_raw = cls.generate_server_private_key(connection_manager, connection)
        handshake_fragment_server_key_exchange = tls_ecc.ServerKeyExchangeECDHPSK.build({
            "param": {
                "curve_type": ECCurveType.named_curve.value,
                "curve_params": {
                    "curve_type": ECCurveType.named_curve.value,
                    "namedcurve": connection.ec.value  # NamedCurve.secp256r1.value
                },
                "public": {"point": server_public_key_raw}
            },
            "psk_identity_hint": connection_manager.identity_hint
        })
        print("identity_hint", connection_manager.identity_hint.hex(" "))
        return handshake_fragment_server_key_exchange

    @classmethod
    def build_handshake_fragment_client_key_exchange(cls, connection_manager: ConnectionManager,
                                                     connection: Connection,
                                                     record):
        client_public_key_raw = cls.get_raw_client_public_key(connection)
        return tls_ecc.ClientKeyExchange.build({
            "psk_identity": {
                "dh_public_Yc": client_public_key_raw,
                "psk": connection.user_props['psk']
            }
        }, key_exchange_algorithm=cls.key_exchange_algorithm)
