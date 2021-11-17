import logging

from .. import math
from ..connection_manager.connection import Connection
from ..const import tls as const_tls
from ..constructs.dtls import RawHandshake, AnswerRecord, RawPlaintext
from ..const.handshake import ConnectionState

logger = logging.getLogger(__file__)


def build_mac(connection: Connection, record: RawPlaintext, mac_func, content_type: int, fragment: bytes):
    if record is None:
        version = connection.ssl_version.value
        seq_num = connection.epoch.to_bytes(2, 'big') + connection.sequence_number.to_bytes(6, 'big')
    else:
        version = int(record.version)
        seq_num = record.epoch.to_bytes(2, 'big') + record.sequence_number.to_bytes(6, 'big')
    return math.build_mac(mac_func, seq_num, content_type, version, fragment)


def build_handshake_fragment(connection: Connection, handshake_type: const_tls.HandshakeType,
                             handshake_fragment: bytes):
    fragment = RawHandshake.build({
        "handshake_type": handshake_type.value,
        "length": len(handshake_fragment),
        "message_seq": connection.message_seq,
        "fragment_offset": 0,
        "fragment_length": len(handshake_fragment),
        "fragment": handshake_fragment
    })
    return fragment


def build_handshake_record(connection: Connection, handshake_type: const_tls.HandshakeType,
                           handshake_fragment: bytes, clear_handshake_hash=False):
    fragment = build_handshake_fragment(connection, handshake_type, handshake_fragment)

    connection.update_handshake_hash(fragment, clear=clear_handshake_hash, name=handshake_type.name)
    connection.message_seq += 1
    return AnswerRecord(
        content_type=const_tls.ContentType.HANDSHAKE.value,
        epoch=connection.epoch,
        fragment=fragment
    )


def build_change_cipher(connection: Connection):
    epoch = connection.epoch
    connection.epoch += 1
    return AnswerRecord(
        content_type=const_tls.ContentType.CHANGE_CIPHER_SPEC.value,
        epoch=epoch,
        fragment=b'\x01'
    )


def build_handshake_answer(connection: Connection, fragment: bytes):
    return AnswerRecord(
        content_type=const_tls.ContentType.HANDSHAKE.value,
        epoch=connection.epoch,
        fragment=fragment
    )
