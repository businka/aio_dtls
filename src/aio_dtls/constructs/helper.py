from construct import Prefixed, GreedyBytes, GreedyRange
from construct import Struct, Int8ub, Int16ub, Bytes, Enum, Switch

# from dtls.constructs_core import PrefixedBytes
from aio_dtls.const import tls

# import enums

ServerName = Enum(Int8ub, tls.NameType)
ServerNameList = GreedyRange(ServerName)

SignatureAndHashAlgorithm = Struct(
    "hash" / Enum(Int8ub, tls.HashAlgorithm),
    "signature" / Enum(Int8ub, tls.SignatureAlgorithm),
)
# SignatureAndHashAlgorithm = GreedyBytes

SupportedSignatureAlgorithms = Prefixed(Int16ub, GreedyRange(SignatureAndHashAlgorithm))

MaxFragmentLength = Enum(Int8ub, tls.MaxFragmentLength)
ClientCertificateURL = Struct(
    # The "extension_data" field of this extension SHALL be empty.
)
TruncatedHMAC = Struct(
    # The "extension_data" field of this extension SHALL be empty.
)
SHA1Hash = Bytes(20)

NamedCurve = Enum(Int16ub, tls.NamedCurve)

EllipticCurveList = Struct(
    "elliptic_curve_list" / Prefixed(Int16ub, GreedyRange(NamedCurve))
)

ECPointFormat = Enum(Int8ub, tls.ECPointFormat)

ECPointFormatList = Struct(
    "ec_point_format_list" / Prefixed(Int8ub, GreedyRange(ECPointFormat))
)

# DistinguishedName = PrefixedBytes(
#     SizeWithin(UBInt16("DistinguishedName_length"),
#                min_size=1, max_size=2 ** 16 - 1),
# )
#
# TrustedAuthority = Struct(
#     *EnumSwitch(
#         type_field=UBInt8("identifier_type"),
#         type_enum=enums.TrustedAuthorityIdentifierType,
#         value_field="identifier",
#         value_choices={
#             enums.TrustedAuthorityIdentifierType.PRE_AGREED: Struct(None),
#             enums.TrustedAuthorityIdentifierType.KEY_SHA1_HASH: SHA1Hash,
#             enums.TrustedAuthorityIdentifierType.X509_NAME: DistinguishedName,
#             enums.TrustedAuthorityIdentifierType.CERT_SHA1_HASH: SHA1Hash,
#         }
#     )
# )
#
# TrustedAuthorities = TLSPrefixedArray("trusted_authorities_list",
#                                       TrustedAuthority)

Extension = Struct(
    "type" / Enum(Int16ub, tls.ExtensionType),
    "data" / Prefixed(
        Int16ub,
        Switch(lambda ctx: int(ctx.type), {
            tls.ExtensionType.SERVER_NAME.value: ServerNameList,
            tls.ExtensionType.SIGNATURE_ALGORITHMS.value: SupportedSignatureAlgorithms,
            tls.ExtensionType.CLIENT_CERTIFICATE_URL.value: ClientCertificateURL,
            tls.ExtensionType.MAX_FRAGMENT_LENGTH.value: MaxFragmentLength,
            tls.ExtensionType.TRUNCATED_HMAC.value: TruncatedHMAC,
            tls.ExtensionType.ELLIPTIC_CURVES.value: EllipticCurveList,
            tls.ExtensionType.EC_POINT_FORMATS.value: ECPointFormatList
            # enums.ExtensionType.TRUSTED_CA_KEYS.value: TrustedAuthorities,
            # enums.ExtensionType.STATUS_REQUEST.value: CertificateStatusRequest,
        }, default=GreedyBytes))
)

Extensions = Prefixed(Int16ub, GreedyRange(Extension))
