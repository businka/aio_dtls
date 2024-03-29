from typing import List

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .handshake_ecdh_anon import EcdhAnon as BaseEcdhAnon
from ..connection_manager.connection import Connection
from ..connection_manager.connection_manager import ConnectionManager
from ..const.tls import CompressionMethod, ProtocolVersion, ECCurveType
from ..const.tls import NamedCurve, ExtensionType, HandshakeType, ContentType
from ..constructs.dtls import ClientHello
from ..constructs.dtls import RawDatagram, AnswerRecord
from ..constructs.tls import ServerHello
from ..constructs.tls_ecc import ServerKeyExchangeECDH, ClientKeyExchange


class EcdhEcdsa(BaseEcdhAnon):

    @classmethod
    def build_handshake_fragment_client_hello(cls, connection_manager: ConnectionManager, connection: Connection):
        extensions = [{
            "type": ExtensionType.SIGNATURE_ALGORITHMS.value,
            "data": connection_manager.signature_scheme.max
        },
            {
                "type": ExtensionType.ELLIPTIC_CURVES.value,
                "data": {"elliptic_curve_list": connection_manager.elliptic_curves.max}
            },
            {
                "type": ExtensionType.RENEGOTIATION_INFO.value,
                "data": b'\x00'
            },
            {
                "type": ExtensionType.EXTENDED_MASTER_SECRET.value,
                "data": b''
            },
            {
                "type": ExtensionType.EC_POINT_FORMATS.value,
                "data": connection_manager.ec_point_formats.max
            }]
        connection.security_params.client_random = connection_manager.generate_tls_random()
        handshake_fragment_client_hello = ClientHello.build(dict(
            client_version=connection_manager.ssl_versions.max,
            session_id=connection.uid,
            random=connection.client_random,
            cookie=connection.cookie,
            cipher_suites=connection_manager.ciphers.max,
            compression_methods=connection_manager.compression_methods.max,
            extension=extensions
        ))
        return handshake_fragment_client_hello

    @classmethod
    def build_handshake_fragment_server_hello(cls, connection_manager: ConnectionManager, connection: Connection):
        connection.security_params.server_random = connection_manager.generate_tls_random()
        handshake_fragment_server_hello = ServerHello.build({
            "server_version": ProtocolVersion.DTLS_1_2.value,
            "random": connection.security_params.server_random,
            "session_id": connection.uid,
            "cipher_suite": connection.cipher.value,
            "compression_method": CompressionMethod.NULL.value,
            "extension": [
                {
                    "type": ExtensionType.RENEGOTIATION_INFO.value,
                    "data": b'\x00'
                },
                {
                    "type": ExtensionType.EXTENDED_MASTER_SECRET.value,
                    "data": b''
                },
                {
                    "type": ExtensionType.EC_POINT_FORMATS.value,
                    "data": connection_manager.ec_point_formats.max
                }

            ],
        })
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

        handshake_fragment_server_key_exchange = ServerKeyExchangeECDH.build({
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
        return ClientKeyExchange.build({
            "exchange_keys": {
                "dh_public": {
                    "dh_Yc": client_public_key_raw
                }
            }
        })

    @classmethod
    def generate_client_shared_key(cls, connection_manager: ConnectionManager, connection: Connection, record):
        data = ServerKeyExchangeECDH.parse(record.fragment.fragment)
        if data.param.curve_type != ECCurveType.named_curve and not data.param.curve_params.namedcurve:
            raise NotImplemented()
            pass
        connection.ec = NamedCurve(int(data.param.curve_params.namedcurve))

        server_public_key_raw = data.param.public.point  # bytes(bytearray(data.param.public.point))
        connection_ec = getattr(ec, connection.ec.name.upper())()
        connection.server_public_key = EllipticCurvePublicKey.from_encoded_point(connection_ec, server_public_key_raw)

        connection.client_private_key = connection_manager.get_ec_private_key(connection_ec)
        return connection.client_private_key.exchange(ec.ECDH(),
                                                      connection.server_public_key)

    @classmethod
    def generate_server_shared_key(cls, connection: Connection, record):
        data = ClientKeyExchange.parse(record.fragment.fragment)
        client_public_key_raw = data.exchange_keys.dh_public.dh_Yc
        connection_ec = getattr(ec, connection.ec.name.upper())()
        connection.client_public_key = EllipticCurvePublicKey.from_encoded_point(connection_ec, client_public_key_raw)

        return connection.server_private_key.exchange(ec.ECDH(),
                                                      connection.client_public_key)

    @classmethod
    def build_change_cipher(cls, connection_manager: ConnectionManager, session: Connection):
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'1',
        ).derive(session.shared_key)

        return derived_key

    @classmethod
    def generate_elliptic_curve_private_key(cls, elliptic_curve: ec.EllipticCurve):
        private_key = ec.generate_private_key(elliptic_curve)
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    @classmethod
    def received_trusted_client_hello(cls, connection_manager: ConnectionManager, connection: Connection, record):
        client_hello_data = record.fragment.fragment
        extensions = tls_helper.extensions_to_dict(client_hello_data.extension)
        if ExtensionType.EC_POINT_FORMATS.name in extensions \
                or ExtensionType.ELLIPTIC_CURVES.name in extensions:  # rfc-4492
            ext_ec_data = extensions[ExtensionType.ELLIPTIC_CURVES.name][0].data
            # todo выбирать ec среди поддерживаемых
            connection.ec = NamedCurve(int(ext_ec_data.elliptic_curve_list[0]))
            answer = []
            fragment = cls.build_handshake_fragment_server_hello(connection_manager, connection)
            answer.append(build_handshake_record(
                connection, HandshakeType.SERVER_HELLO.value, fragment))

            fragment = cls.build_handshake_fragment_server_key_exchange(connection_manager, connection,
                                                                        record)
            answer.append(build_handshake_record(
                connection, HandshakeType.SERVER_KEY_EXCHANGE.value, fragment))
            answer.append(build_handshake_record(
                connection, HandshakeType.SERVER_HELLO_DONE.value, b''))

            return answer

    @classmethod
    def received_server_hello(cls, connection_manager: ConnectionManager, connection: Connection, record):
        server_hello_data = record.fragment.fragment
        # if not connection.ec:
        #     raise NotImplemented()
        extensions = tls_helper.extensions_to_dict(server_hello_data.extension)
        if ExtensionType.EC_POINT_FORMATS.name in extensions:  # rfc-4492
            ext_data = extensions[ExtensionType.EC_POINT_FORMATS.name][0].data
            connection.ec_point_format = ext_data.ec_point_format_list[0]
        pass

    @classmethod
    def received_server_hello_done(cls, connection_manager: ConnectionManager, connection: Connection, record):
        pass

    @classmethod
    def received_server_key_exchange(cls, connection_manager: ConnectionManager, connection: Connection, record):
        connection_manager = connection_manager

        connection.premaster_secret = cls.generate_client_shared_key(connection_manager, connection, record)
        connection.security_params.master_secret = cls.generate_master_secret(connection)

        fragment_client_key_exchange = cls.build_handshake_fragment_client_key_exchange(
            connection_manager, connection,
            record)
        answer = [build_handshake_record(
            connection_manager, connection, HandshakeType.CLIENT_KEY_EXCHANGE.value, fragment_client_key_exchange
        ), AnswerRecord(
            content_type=ContentType.CHANGE_CIPHER_SPEC.value,
            # protocol_version=connection.ssl_version,
            epoch=connection.epoch,
            # sequence_number=connection.sequence_number,
            fragment=b'\x01'
        )]

        return answer

    @classmethod
    def received_client_key_exchange(cls, connection_manager: ConnectionManager, connection: Connection, record):
        connection.premaster_secret = cls.generate_server_shared_key(connection, record)
        connection.security_params.master_secret = cls.generate_master_secret(connection)
        _d = cls.generate_finished(connection, b"server finished")

        pass

    @classmethod
    def build_handshake_plaintext(cls, connection: Connection, records_data: List[AnswerRecord]):
        records = []
        for record in records_data:
            records.append({
                "type": record.content_type,
                "protocol_version": connection.ssl_version.value,
                "epoch": record.epoch,
                "sequence_number": connection.sequence_number,
                "fragment": record.fragment
            })
            connection.sequence_number += 1

        plaintext = RawDatagram.build(records)
        return plaintext
