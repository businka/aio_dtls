from __future__ import absolute_import, division, print_function

from enum import Enum


class ClientCertificateType(Enum):
    RSA_SIGN = 1
    DSS_SIGN = 2
    RSA_FIXED_DH = 3
    DSS_FIXED_DH = 4
    RSA_EPHEMERAL_DH_RESERVED = 5
    DSS_EPHEMERAL_DH_RESERVED = 6
    FORTEZZA_DMS_RESERVED = 20


class HashAlgorithm(Enum):
    NONE = 0
    MD5 = 1
    SHA1 = 2
    SHA224 = 3
    SHA256 = 4
    SHA384 = 5
    SHA512 = 6


class SignatureAlgorithm(Enum):
    ANONYMOUS = 0
    RSA = 1
    DSA = 2
    ECDSA = 3


class HandshakeType(Enum):
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    HELLO_VERIFY_REQUEST = 3  # DTLS 1.2
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20
    CERTIFICATE_URL = 21
    CERTIFICATE_STATUS = 22


class ContentType(Enum):
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23


class AlertLevel(Enum):
    WARNING = 1
    FATAL = 2
    ALERT_MESSAGE = 170  # ??? from wireshark


class AlertDescription(Enum):
    CLOSE_NOTIFY = 0
    UNEXPECTED_MESSAGE = 10
    BAD_RECORD_MAC = 20
    DECRYPTION_FAILED_RESERVED = 21
    RECORD_OVERFLOW = 22
    DECOMPRESSION_FAILURE = 30
    HANDSHAKE_FAILURE = 40
    NO_CERTIFICATE_RESERVED = 41
    BAD_CERTIFICATE = 42
    UNSUPPORTED_CERTIFICATE = 43
    CERTIFICATE_REVOKED = 44
    CERTIFICATE_EXPIRED = 45
    CERTIFICATE_UNKNOWN = 46
    ILLEGAL_PARAMETER = 47
    UNKNOWN_CA = 48
    ACCESS_DENIED = 49
    DECODE_ERROR = 50
    DECRYPT_ERROR = 51
    EXPORT_RESTRICTION_RESERVED = 60
    PROTOCOL_VERSION = 70
    INSUFFICIENT_SECURITY = 71
    INTERNAL_ERROR = 80
    USER_CANCELED = 90
    ENCRYPTED_ALERT = 96  # ??? from wireshark
    NO_RENEGOTIATION = 100
    UNSUPPORTED_EXTENSION = 110
    CERTIFICATE_UNOBTAINABLE = 111
    UNRECOGNIZED_NAME = 112
    BAD_CERTIFICATE_STATUS_RESPONSE = 113
    BAD_CERTIFICATE_HASH_VALUE = 114


class ExtensionType(Enum):
    """
    TLS extensions as assigned in
    http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml.
    """
    SERVER_NAME = 0
    MAX_FRAGMENT_LENGTH = 1
    CLIENT_CERTIFICATE_URL = 2
    TRUSTED_CA_KEYS = 3
    TRUNCATED_HMAC = 4
    STATUS_REQUEST = 5
    USER_MAPPING = 6
    CLIENT_AUTHZ = 7
    SERVER_AUTHZ = 8
    CERT_TYPE = 9
    ELLIPTIC_CURVES = 10
    EC_POINT_FORMATS = 11
    SRP = 12
    SIGNATURE_ALGORITHMS = 13
    USE_SRTP = 14
    HEARTBEAT = 15
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16
    STATUS_REQUEST_V2 = 17
    SIGNED_CERTIFICATE_TIMESTAMP = 18
    CLIENT_CERTIFICATE_TYPE = 19
    SERVER_CERTIFICATE_TYPE = 20
    PADDING = 21
    ENCRYPT_THEN_MAC = 22
    EXTENDED_MASTER_SECRET = 23
    # TOKEN_BINDING = 24  (TEMPORARY - registered 2016-02-04, expires
    #                      2017-02-04) [draft-ietf-tokbind-negotiation]
    CACHED_INFO = 25
    RENEGOTIATION_INFO = 65281


class CompressionMethod(Enum):
    NULL = 0


BulkCipherAlgorithm = Enum('BulkCipherAlgorithm', ['null', 'rc4', '3des', 'aes'], start=0)

ConnectionEnd = Enum('ConnectionEnd', ['server', 'client'])

PRFAlgorithm = Enum('PRFAlgorithm', ['tls_prf_sha256'])


class NameType(Enum):
    HOST_NAME = 0


class CertChainType(Enum):
    INDIVIDUAL_CERTS = 0
    PKIPATH = 1


class MaxFragmentLength(Enum):
    TWO_TO_THE_9TH = 1
    TWO_TO_THE_10TH = 2
    TWO_TO_THE_11TH = 3
    TWO_TO_THE_12TH = 4


class CertificateStatusType(Enum):
    OCSP = 1


class TrustedAuthorityIdentifierType(Enum):
    PRE_AGREED = 0
    KEY_SHA1_HASH = 1
    X509_NAME = 2
    CERT_SHA1_HASH = 3


class ProtocolVersion(Enum):
    TLS_1 = 0x0301
    TLS_1_2 = 0x0303


class NamedCurve(Enum):
    sect163k1 = 0x0001
    sect163r1 = 0x0002
    sect163r2 = 0x0003
    sect193r1 = 0x0004
    sect193r2 = 0x0005
    sect233k1 = 0x0006
    sect233r1 = 0x0007
    sect239k1 = 0x0008
    sect283k1 = 0x0009
    sect283r1 = 0x000A
    sect409k1 = 0x000B
    sect409r1 = 0x000C
    sect571k1 = 0x000D
    sect571r1 = 0x000E
    secp160k1 = 0x000F
    secp160r1 = 0x0010
    secp160r2 = 0x0011
    secp192k1 = 0x0012
    secp192r1 = 0x0013
    secp224k1 = 0x0014
    secp224r1 = 0x0015
    secp256k1 = 0x0016
    secp256r1 = 0x0017
    secp384r1 = 0x0018
    secp521r1 = 0x0019
    # reserved=0xFE00.0xFEFF),
    arbitrary_explicit_prime_curves = 0xFF01
    arbitrary_explicit_char2_curves = 0xFF02
    # (0xFFFF)


class ECPointFormat(Enum):
    uncompressed = 0
    ansiX962_compressed_prime = 1
    ansiX962_compressed_char2 = 2
    # reserved(248..255)


class ECCurveType(Enum):
    explicit_prime = 1
    explicit_char2 = 2
    named_curve = 3
