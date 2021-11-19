import secrets
import time
from collections import namedtuple

from construct import Prefixed, Int32ub, GreedyBytes, GreedyRange, Default, RepeatUntil
from construct import Struct, Int8ub, Int16ub, Int24ub, Bytes, Enum, Byte, Switch, If, this

from .helper import Extensions
from ..const import cipher_suites
from ..const import tls as const_tls

CipherSuite = Enum(Int16ub, cipher_suites.CipherSuites)
CipherSuites = Prefixed(Int16ub, GreedyRange(CipherSuite))
CompressionMethod = Enum(Int8ub, const_tls.CompressionMethod)
CompressionMethods = Prefixed(Int8ub, GreedyRange(Int8ub))

Random = Struct(
    gmt_unix_time=Default(Int32ub, int(time.time())),
    random_bytes=Default(Bytes(28), secrets.token_bytes(28))
)

SessionID = Prefixed(Int8ub, Default(GreedyBytes, b''))

ContentType = Enum(Byte, const_tls.ContentType)

# ProtocolVersion = Struct(
#     major=Int8ub,
#     minor=Int8ub
# )

ProtocolVersion = Enum(Int16ub, const_tls.ProtocolVersion)

ServerHello = Struct(
    server_version=ProtocolVersion,
    random=Bytes(32),  # Random,
    session_id=SessionID,
    cipher_suite=CipherSuite,
    compression_method=CompressionMethod,
    extension=Extensions
)

Alert = Struct(
    level=Enum(Int8ub, const_tls.AlertLevel),
    description=Enum(Int8ub, const_tls.AlertDescription)
)

TLSCompressed = Struct(
    type=ContentType,
    version=ProtocolVersion,
    fragment=Prefixed(
        Int16ub,
        GreedyBytes
    )
)

GenericBlockCipher = Struct(
    IV=Bytes(lambda ctx: ctx._params.record_iv_length),
    block_ciphered=Struct(
        content=Bytes(lambda ctx: ctx._params.tls_compressed_length),
        MAC=Bytes(lambda ctx: ctx._params.mac_length),
        padding_length=Int8ub,
        padding=If(this.padding_length > 0, RepeatUntil(lambda obj, lst, ctx: len(lst) == ctx.padding_length, Byte))
    )
)

CiphertextFragment = Switch(lambda ctx: ctx._params.cipher_type, {
    # 'stream': GenericStreamCipher,
    'block': GenericBlockCipher,
    # const_tls.CipherType.aead: GenericAEADCipher
}, default=GreedyBytes)

ClientHello = Struct(
    client_version=ProtocolVersion,
    random=Bytes(32),  # Random,
    session_id=SessionID,
    cipher_suites=CipherSuites,
    compression_methods=CompressionMethods,
    extension=Extensions,
)

Certificate = Struct(
    certificate_list=Prefixed(Int24ub, GreedyRange(Prefixed(Int24ub, GreedyBytes)))
)

Finished = Struct(
    verify_data=GreedyBytes
)

ServerHelloDone = GreedyBytes

Handshake = Struct(
    handshake_type=Enum(Int8ub, const_tls.HandshakeType),
    fragment=Prefixed(Int24ub, Switch(lambda ctx: int(ctx.handshake_type), {
        const_tls.HandshakeType.CLIENT_HELLO.value: ClientHello,
        const_tls.HandshakeType.SERVER_HELLO.value: ServerHello,
        const_tls.HandshakeType.CERTIFICATE.value: Certificate,
        const_tls.HandshakeType.SERVER_HELLO_DONE.value: ServerHelloDone,
        const_tls.HandshakeType.FINISHED.value: Finished
    }, default=GreedyBytes)))

RawHandshake = Struct(
    handshake_type=Enum(Int8ub, const_tls.HandshakeType),
    fragment=Prefixed(Int24ub, GreedyBytes)
)

Plaintext = Struct(
    type=ContentType,
    version=ProtocolVersion,
    fragment=Prefixed(
        Int16ub,
        Switch(lambda ctx: int(ctx.type), {
            const_tls.ContentType.CHANGE_CIPHER_SPEC.value: GreedyBytes,
            const_tls.ContentType.ALERT.value: Alert,
            const_tls.ContentType.HANDSHAKE.value: Handshake,
            const_tls.ContentType.APPLICATION_DATA.value: GreedyBytes
        }, default=GreedyBytes)))

RawPlaintext = Struct(
    type=ContentType,
    version=ProtocolVersion,
    fragment=Prefixed(
        Int16ub,
        GreedyBytes
    )
)

RawDatagram = GreedyRange(RawPlaintext)
Datagram = GreedyRange(Plaintext)

AnswerRecord = namedtuple('AnswerRecord', ('content_type', 'fragment', 'epoch',), defaults=(None, None, None))
