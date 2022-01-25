import logging
from typing import List

from .. import math
from ..connection_manager.connection import Connection
from ..const import tls as const_tls, handshake as const_handshake
from ..constructs import dtls, tls
from ..tls.helper import Helper as TlsHelper

logger = logging.getLogger(__name__)


class Helper(TlsHelper):

    @classmethod
    def build_plaintext(cls, connection: Connection, records_data: List[dtls.AnswerRecord]):
        records = []
        for record in records_data:
            records.append({
                "type": record.content_type,
                "version": connection.ssl_version.value,
                "epoch": record.epoch,
                "sequence_number": connection.get_sequence_number(record.epoch),
                "fragment": record.fragment
            })

        plaintext = dtls.RawDatagram.build(records)
        return plaintext

    @classmethod
    def build_application_record(cls, connection: Connection, fragments):
        records = []
        logger.debug(f'prepare {len(fragments)} application data for send')
        for fragment in fragments:
            encrypted_data = cls.encrypt_ciphertext_fragment(
                connection, const_tls.ContentType.APPLICATION_DATA, fragment)
            records.append(dtls.AnswerRecord(
                content_type=const_tls.ContentType.APPLICATION_DATA.value,
                epoch=connection.epoch,
                fragment=encrypted_data
            ))
        return records

    @classmethod
    def build_mac(cls, connection: Connection, record: dtls.RawPlaintext, mac_func, content_type: int, fragment: bytes):
        if record is None:
            version = connection.ssl_version.value
            seq_num = connection.epoch.to_bytes(2, 'big') + connection.sequence_number.to_bytes(6, 'big')
        else:
            version = int(record.version)
            seq_num = record.epoch.to_bytes(2, 'big') + record.sequence_number.to_bytes(6, 'big')
        return math.build_mac(mac_func, seq_num, content_type, version, fragment)

    @classmethod
    def build_handshake_fragment(cls, connection: Connection, handshake_type: const_tls.HandshakeType,
                                 handshake_fragment: bytes):
        fragment = dtls.RawHandshake.build({
            "handshake_type": handshake_type.value,
            "length": len(handshake_fragment),
            "message_seq": connection.message_seq,
            "fragment_offset": 0,
            "fragment_length": len(handshake_fragment),
            "fragment": handshake_fragment
        })
        return fragment

    @classmethod
    def build_handshake_record(cls, connection: Connection, handshake_type: const_tls.HandshakeType,
                               handshake_fragment: bytes, clear_handshake_hash=False):
        fragment = cls.build_handshake_fragment(connection, handshake_type, handshake_fragment)

        connection.update_handshake_hash(fragment, clear=clear_handshake_hash, name=handshake_type.name)
        connection.message_seq += 1
        return dtls.AnswerRecord(
            content_type=const_tls.ContentType.HANDSHAKE.value,
            epoch=connection.epoch,
            fragment=fragment
        )

    @classmethod
    def build_change_cipher(cls, connection: Connection):
        epoch = connection.epoch
        connection.epoch += 1
        return dtls.AnswerRecord(
            content_type=const_tls.ContentType.CHANGE_CIPHER_SPEC.value,
            epoch=epoch,
            fragment=b'\x01'
        )

    @classmethod
    def build_alert(cls, connection: Connection, level: const_tls.AlertLevel, description: const_tls.AlertDescription):
        fragment = tls.Alert.build({
            "level": level.value,
            "description": description.value

        })
        if connection.state.value == const_handshake.ConnectionState.HANDSHAKE_OVER:
            fragment = Helper.encrypt_ciphertext_fragment(
                connection, const_tls.ContentType.ALERT, fragment)

        return dtls.AnswerRecord(
            content_type=const_tls.ContentType.ALERT.value,
            epoch=connection.epoch,
            fragment=fragment)

    @classmethod
    def build_handshake_answer(cls, connection: Connection, fragment: bytes):
        return dtls.AnswerRecord(
            content_type=const_tls.ContentType.HANDSHAKE.value,
            epoch=connection.epoch,
            fragment=fragment
        )

    @classmethod
    def send_records(cls, connection: Connection, answers, writer):
        logger.debug(f'dtls send answers ({len(answers)})')
        plaintext = cls.build_plaintext(connection, answers)
        writer(plaintext, connection.address)
