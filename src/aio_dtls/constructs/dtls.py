from collections import namedtuple

from construct import Struct, Int8ub, Int16ub, Int24ub, BytesInteger, Bytes, Enum, Byte, Switch, Prefixed, \
    GreedyBytes, IfThenElse, GreedyRange, Default

from . import tls
from .helper import Extensions
from ..const import tls as const_tls, dtls as const_dtls

# from dtls.constructs.old_adapter import Pre

Cookie = Prefixed(Int8ub, Default(GreedyBytes, b''))

ProtocolVersion = Enum(Int16ub, const_dtls.ProtocolVersion)

ClientHello = Struct(
    client_version=ProtocolVersion,
    random=Bytes(32),  # Random,
    session_id=tls.SessionID,
    cookie=Cookie,
    cipher_suites=tls.CipherSuites,
    compression_methods=tls.CompressionMethods,
    extension=Extensions,
)

HelloVerifyRequest = Struct(
    server_version=ProtocolVersion,
    cookie=Cookie,
)

Handshake = Struct(
    handshake_type=Enum(Byte, const_tls.HandshakeType),
    length=Int24ub,
    message_sequence=Int16ub,
    fragment_offset=Default(Int24ub, 0),
    fragment_length=Default(Int24ub, lambda ctx: ctx.length),
    fragment=IfThenElse(
        lambda ctx: ctx.length == ctx.fragment_length,
        Switch(lambda ctx: int(ctx.handshake_type), {
            const_tls.HandshakeType.CLIENT_HELLO.value: ClientHello,
            const_tls.HandshakeType.HELLO_VERIFY_REQUEST.value: HelloVerifyRequest,
            const_tls.HandshakeType.SERVER_HELLO.value: tls.ServerHello,
            const_tls.HandshakeType.CERTIFICATE.value: tls.Certificate,
            const_tls.HandshakeType.SERVER_HELLO_DONE.value: tls.ServerHelloDone,
            const_tls.HandshakeType.FINISHED.value: tls.Finished
        }, default=Bytes(lambda ctx: ctx.fragment_length)),
        Bytes(lambda ctx: ctx.fragment_length)
    )
)

RawHandshake = Struct(
    handshake_type=Enum(Byte, const_tls.HandshakeType),
    length=Int24ub,
    message_seq=Int16ub,
    fragment_offset=Int24ub,
    fragment_length=Int24ub,
    fragment=Bytes(lambda ctx: ctx.fragment_length)
)

Plaintext = Struct(
    type=tls.ContentType,
    version=ProtocolVersion,
    epoch=Int16ub,
    sequence_number=BytesInteger(6),
    fragment=Prefixed(
        Int16ub,
        Switch(lambda ctx: ctx.type.intvalue, {
            const_tls.ContentType.CHANGE_CIPHER_SPEC.value: GreedyBytes,
            const_tls.ContentType.ALERT.value: tls.Alert,
            const_tls.ContentType.HANDSHAKE.value: Handshake,
            const_tls.ContentType.APPLICATION_DATA.value: GreedyBytes
        }, default=GreedyBytes))
)

RawPlaintext = Struct(
    type=tls.ContentType,
    version=ProtocolVersion,
    epoch=Int16ub,
    sequence_number=BytesInteger(6),
    fragment=Prefixed(
        Int16ub,
        GreedyBytes
    )
)

RawDatagram = GreedyRange(RawPlaintext)
Datagram = GreedyRange(Plaintext)

AnswerRecord = namedtuple('AnswerRecord', ('content_type', 'epoch', 'fragment'))

TLSCompressed = Struct(
    type=tls.ContentType,
    version=ProtocolVersion,
    epoch=Int16ub,
    sequence_number=BytesInteger(6),
    fragment=Prefixed(
        Int16ub,
        GreedyBytes
    )
)

TLSCiphertext = Struct(
    type=tls.ContentType,
    version=ProtocolVersion,
    epoch=Int16ub,
    sequence_number=BytesInteger(6),
    fragment=Prefixed(
        Int16ub,
        Switch(lambda ctx: ctx._params.security_parameters.cipher_type, {
            'block': tls.GenericBlockCipher,
            # const_tls.CipherType.aead: GenericAEADCipher
        }, default=GreedyBytes))
)
