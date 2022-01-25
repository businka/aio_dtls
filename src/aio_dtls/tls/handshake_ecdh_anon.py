import logging

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from .helper import Helper
from ..connection_manager.connection import Connection
from ..connection_manager.connection_manager import ConnectionManager
from ..const.tls import NamedCurve, ExtensionType, HandshakeType, CompressionMethod, ECCurveType
from ..constructs import tls
from ..constructs import tls_ecc

logger = logging.getLogger(__name__)


class EcdhAnon:
    key_exchange_algorithm = 'ec_diffie_hellman'
    tls_construct = tls
    helper = Helper

    @classmethod
    def build_handshake_fragment_server_hello(cls, connection_manager: ConnectionManager, connection: Connection):
        connection.security_params.server_random = connection_manager.generate_tls_random()
        data = {
            "server_version": connection.ssl_version.value,
            "random": connection.security_params.server_random,
            "cookie": connection.cookie,  # for dtls only
            "session_id": connection.uid,
            "cipher_suite": hash(connection.cipher),
            "compression_method": CompressionMethod.NULL.value,
            "extension": [
                # {
                #     "type": ExtensionType.RENEGOTIATION_INFO.value,
                #     "data": b'\x00'
                # },
                {
                    "type": ExtensionType.EC_POINT_FORMATS.value,
                    "data": connection_manager.ec_point_formats.max
                }

            ],
        }

        if connection.handshake_params.extended_master_secret:
            data['extension'].append({
                "type": ExtensionType.EXTENDED_MASTER_SECRET.value,
                "data": b''
            })

        handshake_fragment_server_hello = tls.ServerHello.build(data)
        return handshake_fragment_server_hello

    @classmethod
    def build_handshake_fragment_server_key_exchange(cls, connection_manager: ConnectionManager,
                                                     connection: Connection,
                                                     record):
        connection_ec = getattr(ec, connection.ec.name.upper())()

        connection.server_private_key = connection_manager.get_ec_private_key(connection_ec)

        server_public_key = connection.server_private_key.public_key()

        server_public_key_raw = server_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        logger.debug(f'server public key {server_public_key_raw.hex(" ")}')

        handshake_fragment_server_key_exchange = tls_ecc.ServerKeyExchangeECDH.build({
            "param": {
                "curve_type": ECCurveType.named_curve.value,
                "curve_params": {
                    "curve_type": ECCurveType.named_curve.value,
                    "namedcurve": connection.ec.value  # NamedCurve.secp256r1.value
                },
                "public": {"point": server_public_key_raw}
            },
        })
        return handshake_fragment_server_key_exchange

    @classmethod
    def build_handshake_fragment_client_key_exchange(cls, connection_manager: ConnectionManager,
                                                     connection: Connection,
                                                     record):
        client_public_key = connection.client_private_key.public_key()

        client_public_key_raw = client_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        logger.debug(f'client public key {client_public_key_raw.hex(" ")}')

        return tls_ecc.ClientKeyExchange.build({
            "exchange_keys": {
                "dh_public": {
                    "dh_Yc": client_public_key_raw
                }
            }
        })

    @classmethod
    def generate_client_shared_key(cls, connection_manager: ConnectionManager, connection: Connection, record):
        data = tls_ecc.ServerKeyExchange.parse(
            record.fragment.fragment, key_exchange_algorithm=cls.key_exchange_algorithm)

        if data.param.curve_type != ECCurveType.named_curve and not data.param.curve_params.namedcurve:
            raise NotImplemented()
            pass
        connection.ec = NamedCurve(int(data.param.curve_params.namedcurve))

        server_public_key_raw = data.param.public.point  # bytes(bytearray(data.param.public.point))
        connection_ec = getattr(ec, connection.ec.name.upper())()
        connection.server_public_key = EllipticCurvePublicKey.from_encoded_point(connection_ec, server_public_key_raw)

        connection.client_private_key = connection_manager.get_ec_private_key(connection_ec)
        key = connection.client_private_key.exchange(ec.ECDH(),
                                                     connection.server_public_key)
        logger.debug(f'ec {connection.ec.name}')
        logger.debug(f'server public key {server_public_key_raw.hex(" ")}')
        logger.debug(f'shared key {key.hex(" ")}')
        return key

    @classmethod
    def generate_server_shared_key(cls, connection: Connection, record):
        data = tls_ecc.ClientKeyExchange.parse(record.fragment.fragment)
        client_public_key_raw = data.exchange_keys.dh_public.dh_Yc
        connection_ec = getattr(ec, connection.ec.name.upper())()
        connection.client_public_key = EllipticCurvePublicKey.from_encoded_point(connection_ec, client_public_key_raw)

        key = connection.server_private_key.exchange(ec.ECDH(),
                                                     connection.client_public_key)
        logger.debug(f'ec {connection.ec.name}')
        logger.debug(f'client public key {client_public_key_raw.hex(" ")}')
        logger.debug(f'shared key {key.hex(" ")}')
        return key

    # @classmethod
    # def build_change_cipher(cls, connection_manager: ConnectionManager, session: Connection):
    #     derived_key = HKDF(
    #         algorithm=hashes.SHA256(),
    #         length=32,
    #         salt=None,
    #         info=b'1',
    #     ).derive(session.shared_key)
    #
    #     return derived_key

    @classmethod
    def generate_elliptic_curve_private_key(cls, elliptic_curve: ec.EllipticCurve):
        private_key = ec.generate_private_key(elliptic_curve)
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    @classmethod
    def received_client_hello(cls, connection_manager: ConnectionManager, connection: Connection, record, extensions):
        # client_hello_data = record.fragment.fragment
        if ExtensionType.EC_POINT_FORMATS.name in extensions \
                or ExtensionType.ELLIPTIC_CURVES.name in extensions:  # rfc-4492
            ext_ec_data = extensions[ExtensionType.ELLIPTIC_CURVES.name][0].data
            # todo выбирать ec среди поддерживаемых
            connection.ec = NamedCurve(int(ext_ec_data.elliptic_curve_list[0]))
            answer = []
            fragment = cls.build_handshake_fragment_server_hello(connection_manager, connection)
            answer.append(cls.helper.build_handshake_record(connection, HandshakeType.SERVER_HELLO, fragment))

            fragment = cls.build_handshake_fragment_server_key_exchange(connection_manager, connection,
                                                                        record)
            answer.append(cls.helper.build_handshake_record(connection, HandshakeType.SERVER_KEY_EXCHANGE,
                                                        fragment))
            answer.append(cls.helper.build_handshake_record(connection, HandshakeType.SERVER_HELLO_DONE, b''))

            return answer

    @classmethod
    def received_server_hello(cls, connection_manager: ConnectionManager, connection: Connection, record, extensions):
        server_hello_data = record.fragment.fragment
        # if not connection.ec:
        #     raise NotImplemented()
        if ExtensionType.EC_POINT_FORMATS.name in extensions:  # rfc-4492
            ext_data = extensions[ExtensionType.EC_POINT_FORMATS.name][0].data
            connection.ec_point_format = ext_data.ec_point_format_list[0]
        pass

    @classmethod
    def received_server_key_exchange(cls, connection_manager: ConnectionManager, connection: Connection, record):
        connection_manager = connection_manager

        raw_handshake_message = record.fragment
        record.fragment = cls.tls_construct.Handshake.parse(raw_handshake_message)

        connection.premaster_secret = cls.generate_client_shared_key(connection_manager, connection, record)

    @classmethod
    def received_server_hello_done(cls, connection_manager: ConnectionManager, connection: Connection, record):
        fragment_client_key_exchange = cls.build_handshake_fragment_client_key_exchange(
            connection_manager, connection,
            record)

        answer = [
            cls.helper.build_handshake_record(connection, HandshakeType.CLIENT_KEY_EXCHANGE, fragment_client_key_exchange),
            cls.helper.build_change_cipher(connection)
        ]

        return answer

    @classmethod
    def received_client_key_exchange(cls, connection_manager: ConnectionManager, connection: Connection, record):
        connection.premaster_secret = cls.generate_server_shared_key(connection, record)
        connection.security_params.master_secret = cls.helper.generate_master_secret(connection)
