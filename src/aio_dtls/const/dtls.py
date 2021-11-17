from __future__ import absolute_import, division, print_function

from enum import Enum

MACAlgorithm = Enum('MACAlgorithm', ['null', 'hmac_md5', 'hmac_sha1', 'hmac_sha256', 'hmac_sha384', 'hmac_sha512'],
                    start=0)

CipherType = Enum('CipherType', ['stream', 'block', 'aead'])


class ProtocolVersion(Enum):
    DTLS_1_2 = 0xfefd
    DTLS_1 = 0xfeff
