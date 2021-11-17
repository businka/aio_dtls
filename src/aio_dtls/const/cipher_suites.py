# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from enum import Enum

from cryptography.hazmat.primitives import hashes

from aio_dtls.exceptions import UnsupportedCipherException
from ..cipher import cipher


# from .cryptographic_primitive import cryptography_primitives


class _MACAlgorithm:
    def __init__(self, hash_func):
        self.hash_func = hash_func
        self.name = self.hash_func.name if self.hash_func is not None else 'null'

    def __hash__(self):
        return self.name

    def __eq__(self, other):
        if other is None and self.hash_func is None:
            return True
        return other == self.name

    def __bool__(self):
        return self.hash_func is not None


class MACAlgorithm(Enum):
    null = _MACAlgorithm(None)
    hmac_null = _MACAlgorithm(None)
    hmac_md5 = _MACAlgorithm(hashes.MD5)
    hmac_sha1 = _MACAlgorithm(hashes.SHA1)
    hmac_sha = _MACAlgorithm(hashes.SHA1)
    hmac_sha256 = _MACAlgorithm(hashes.SHA256)
    hmac_sha384 = _MACAlgorithm(hashes.SHA3_384)
    hmac_sha512 = _MACAlgorithm(hashes.SHA512)

    @property
    def mac_length(self):
        try:
            return self.value.hash_func.digest_size
        except Exception as err:
            return 0

    @property
    def hash_func(self):
        return self.value.hash_func

    @property
    def digestmod(self):
        return self.value.hash_func.name

    def __hash__(self) -> int:
        return hash(self.value)

    def __eq__(self, other):
        return int(other) == hash(self.value)

    # def __bool__(self):
    #     return self.value.hash_func is not None

    def __str__(self):
        return hash(self.value)


class CipherSuite:
    def __init__(self, value):
        self.value = value
        self.name = None
        self.protocol = None
        self.authentication_mechanism = None

        self.encryption_type = None
        self.hash_function = None
        self.digest_size = None
        self.key_length = None
        self.iv_length = None

        self.key_exchange = None
        self.cipher = None
        self.mac = None

    def init_from_name(self, name):
        try:
            self.name = name
            _tmp = name.split('_WITH_')
            _tmp1 = _tmp[0].split('_')
            if _tmp1[0] != 'TLS':
                raise Exception('Not TLS cipher')
            self.protocol = _tmp1[0]

            if len(_tmp) == 2:
                self.key_exchange = '_'.join(_tmp1[1:])
                _tmp1 = _tmp[1].split('_')
            elif len(_tmp) == 1:  # 1.3
                _tmp1 = _tmp1[1:]
            else:
                return None

            mac_name = _tmp1[-1]  # идет последним
            try:
                self.mac = MACAlgorithm[f'hmac_{mac_name.lower()}']
            except KeyError:
                pass

            cipher_name = '_'.join(_tmp1[:-1] if self.mac else _tmp1)  # идет перед mac
            if cipher_name not in cipher:
                return None
            self.cipher = cipher[cipher_name]

            return self
        except Exception as err:
            raise Exception(f'{err} from {name}')

    # def __str__(self):
    #     return self.name

    def __hash__(self):
        return self.value

    def __eq__(self, other):
        return other == self.value


class CipherSuites(Enum):
    TLS_NULL_WITH_NULL_NULL = CipherSuite(0x0000)
    TLS_RSA_WITH_NULL_MD5 = CipherSuite(0x0001)
    TLS_RSA_WITH_NULL_SHA = CipherSuite(0x0002)
    TLS_RSA_EXPORT_WITH_RC4_40_MD5 = CipherSuite(0x0003)
    TLS_RSA_WITH_RC4_128_MD5 = CipherSuite(0x0004)
    TLS_RSA_WITH_RC4_128_SHA = CipherSuite(0x0005)
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = CipherSuite(0x0006)
    TLS_RSA_WITH_IDEA_CBC_SHA = CipherSuite(0x0007)
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = CipherSuite(0x0008)
    TLS_RSA_WITH_DES_CBC_SHA = CipherSuite(0x0009)
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuite(0x000A)
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = CipherSuite(0x000B)
    TLS_DH_DSS_WITH_DES_CBC_SHA = CipherSuite(0x000C)
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = CipherSuite(0x000D)
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = CipherSuite(0x000E)
    TLS_DH_RSA_WITH_DES_CBC_SHA = CipherSuite(0x000F)
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuite(0x0010)
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = CipherSuite(0x0011)
    TLS_DHE_DSS_WITH_DES_CBC_SHA = CipherSuite(0x0012)
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = CipherSuite(0x0013)
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = CipherSuite(0x0014)
    TLS_DHE_RSA_WITH_DES_CBC_SHA = CipherSuite(0x0015)
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuite(0x0016)
    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 = CipherSuite(0x0017)
    TLS_DH_anon_WITH_RC4_128_MD5 = CipherSuite(0x0018)
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = CipherSuite(0x0019)
    TLS_DH_anon_WITH_DES_CBC_SHA = CipherSuite(0x001A)
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = CipherSuite(0x001B)
    TLS_KRB5_WITH_DES_CBC_SHA = CipherSuite(0x001E)
    TLS_KRB5_WITH_3DES_EDE_CBC_SHA = CipherSuite(0x001F)
    TLS_KRB5_WITH_RC4_128_SHA = CipherSuite(0x0020)
    TLS_KRB5_WITH_IDEA_CBC_SHA = CipherSuite(0x0021)
    TLS_KRB5_WITH_DES_CBC_MD5 = CipherSuite(0x0022)
    TLS_KRB5_WITH_3DES_EDE_CBC_MD5 = CipherSuite(0x0023)
    TLS_KRB5_WITH_RC4_128_MD5 = CipherSuite(0x0024)
    TLS_KRB5_WITH_IDEA_CBC_MD5 = CipherSuite(0x0025)
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = CipherSuite(0x0026)
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = CipherSuite(0x0027)
    TLS_KRB5_EXPORT_WITH_RC4_40_SHA = CipherSuite(0x0028)
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = CipherSuite(0x0029)
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = CipherSuite(0x002A)
    TLS_KRB5_EXPORT_WITH_RC4_40_MD5 = CipherSuite(0x002B)
    TLS_PSK_WITH_NULL_SHA = CipherSuite(0x002C)
    TLS_DHE_PSK_WITH_NULL_SHA = CipherSuite(0x002D)
    TLS_RSA_PSK_WITH_NULL_SHA = CipherSuite(0x002E)
    TLS_RSA_WITH_AES_128_CBC_SHA = CipherSuite(0x002F)
    TLS_DH_DSS_WITH_AES_128_CBC_SHA = CipherSuite(0x0030)
    TLS_DH_RSA_WITH_AES_128_CBC_SHA = CipherSuite(0x0031)
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA = CipherSuite(0x0032)
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = CipherSuite(0x0033)
    TLS_DH_anon_WITH_AES_128_CBC_SHA = CipherSuite(0x0034)
    TLS_RSA_WITH_AES_256_CBC_SHA = CipherSuite(0x0035)
    TLS_DH_DSS_WITH_AES_256_CBC_SHA = CipherSuite(0x0036)
    TLS_DH_RSA_WITH_AES_256_CBC_SHA = CipherSuite(0x0037)
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA = CipherSuite(0x0038)
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = CipherSuite(0x0039)
    TLS_DH_anon_WITH_AES_256_CBC_SHA = CipherSuite(0x003A)
    TLS_RSA_WITH_NULL_SHA256 = CipherSuite(0x003B)
    TLS_RSA_WITH_AES_128_CBC_SHA256 = CipherSuite(0x003C)
    TLS_RSA_WITH_AES_256_CBC_SHA256 = CipherSuite(0x003D)
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = CipherSuite(0x003E)
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = CipherSuite(0x003F)
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = CipherSuite(0x0040)
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = CipherSuite(0x0041)
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = CipherSuite(0x0042)
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = CipherSuite(0x0043)
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = CipherSuite(0x0044)
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = CipherSuite(0x0045)
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA = CipherSuite(0x0046)
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = CipherSuite(0x0067)
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = CipherSuite(0x0068)
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = CipherSuite(0x0069)
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = CipherSuite(0x006A)
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = CipherSuite(0x006B)
    TLS_DH_anon_WITH_AES_128_CBC_SHA256 = CipherSuite(0x006C)
    TLS_DH_anon_WITH_AES_256_CBC_SHA256 = CipherSuite(0x006D)
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = CipherSuite(0x0084)
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = CipherSuite(0x0085)
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = CipherSuite(0x0086)
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = CipherSuite(0x0087)
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = CipherSuite(0x0088)
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA = CipherSuite(0x0089)
    TLS_PSK_WITH_RC4_128_SHA = CipherSuite(0x008A)
    TLS_PSK_WITH_3DES_EDE_CBC_SHA = CipherSuite(0x008B)
    TLS_PSK_WITH_AES_128_CBC_SHA = CipherSuite(0x008C)
    TLS_PSK_WITH_AES_256_CBC_SHA = CipherSuite(0x008D)
    TLS_DHE_PSK_WITH_RC4_128_SHA = CipherSuite(0x008E)
    TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA = CipherSuite(0x008F)
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA = CipherSuite(0x0090)
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA = CipherSuite(0x0091)
    TLS_RSA_PSK_WITH_RC4_128_SHA = CipherSuite(0x0092)
    TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA = CipherSuite(0x0093)
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA = CipherSuite(0x0094)
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA = CipherSuite(0x0095)
    TLS_RSA_WITH_SEED_CBC_SHA = CipherSuite(0x0096)
    TLS_DH_DSS_WITH_SEED_CBC_SHA = CipherSuite(0x0097)
    TLS_DH_RSA_WITH_SEED_CBC_SHA = CipherSuite(0x0098)
    TLS_DHE_DSS_WITH_SEED_CBC_SHA = CipherSuite(0x0099)
    TLS_DHE_RSA_WITH_SEED_CBC_SHA = CipherSuite(0x009A)
    TLS_DH_anon_WITH_SEED_CBC_SHA = CipherSuite(0x009B)
    TLS_RSA_WITH_AES_128_GCM_SHA256 = CipherSuite(0x009C)
    TLS_RSA_WITH_AES_256_GCM_SHA384 = CipherSuite(0x009D)
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = CipherSuite(0x009E)
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = CipherSuite(0x009F)
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = CipherSuite(0x00A0)
    TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = CipherSuite(0x00A1)
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = CipherSuite(0x00A2)
    TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = CipherSuite(0x00A3)
    TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = CipherSuite(0x00A4)
    TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = CipherSuite(0x00A5)
    TLS_DH_anon_WITH_AES_128_GCM_SHA256 = CipherSuite(0x00A6)
    TLS_DH_anon_WITH_AES_256_GCM_SHA384 = CipherSuite(0x00A7)
    TLS_PSK_WITH_AES_128_GCM_SHA256 = CipherSuite(0x00A8)
    TLS_PSK_WITH_AES_256_GCM_SHA384 = CipherSuite(0x00A9)
    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = CipherSuite(0x00AA)
    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = CipherSuite(0x00AB)
    TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = CipherSuite(0x00AC)
    TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = CipherSuite(0x00AD)
    TLS_PSK_WITH_AES_128_CBC_SHA256 = CipherSuite(0x00AE)
    TLS_PSK_WITH_AES_256_CBC_SHA384 = CipherSuite(0x00AF)
    TLS_PSK_WITH_NULL_SHA256 = CipherSuite(0x00B0)
    TLS_PSK_WITH_NULL_SHA384 = CipherSuite(0x00B1)
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = CipherSuite(0x00B2)
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = CipherSuite(0x00B3)
    TLS_DHE_PSK_WITH_NULL_SHA256 = CipherSuite(0x00B4)
    TLS_DHE_PSK_WITH_NULL_SHA384 = CipherSuite(0x00B5)
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = CipherSuite(0x00B6)
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = CipherSuite(0x00B7)
    TLS_RSA_PSK_WITH_NULL_SHA256 = CipherSuite(0x00B8)
    TLS_RSA_PSK_WITH_NULL_SHA384 = CipherSuite(0x00B9)
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuite(0x00BA)
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuite(0x00BB)
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuite(0x00BC)
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuite(0x00BD)
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuite(0x00BE)
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuite(0x00BF)
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = CipherSuite(0x00C0)
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 = CipherSuite(0x00C1)
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = CipherSuite(0x00C2)
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 = CipherSuite(0x00C3)
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = CipherSuite(0x00C4)
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 = CipherSuite(0x00C5)
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = CipherSuite(0x00FF)
    TLS_ECDH_ECDSA_WITH_NULL_SHA = CipherSuite(0xC001)
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA = CipherSuite(0xC002)
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = CipherSuite(0xC003)
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = CipherSuite(0xC004)
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = CipherSuite(0xC005)
    TLS_ECDHE_ECDSA_WITH_NULL_SHA = CipherSuite(0xC006)
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = CipherSuite(0xC007)
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = CipherSuite(0xC008)
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = CipherSuite(0xC009)
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = CipherSuite(0xC00A)
    TLS_ECDH_RSA_WITH_NULL_SHA = CipherSuite(0xC00B)
    TLS_ECDH_RSA_WITH_RC4_128_SHA = CipherSuite(0xC00C)
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuite(0xC00D)
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = CipherSuite(0xC00E)
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = CipherSuite(0xC00F)
    TLS_ECDHE_RSA_WITH_NULL_SHA = CipherSuite(0xC010)
    TLS_ECDHE_RSA_WITH_RC4_128_SHA = CipherSuite(0xC011)
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuite(0xC012)
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = CipherSuite(0xC013)
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = CipherSuite(0xC014)
    TLS_ECDH_anon_WITH_NULL_SHA = CipherSuite(0xC015)
    TLS_ECDH_anon_WITH_RC4_128_SHA = CipherSuite(0xC016)
    TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA = CipherSuite(0xC017)
    TLS_ECDH_anon_WITH_AES_128_CBC_SHA = CipherSuite(0xC018)
    TLS_ECDH_anon_WITH_AES_256_CBC_SHA = CipherSuite(0xC019)
    TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA = CipherSuite(0xC01A)
    TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuite(0xC01B)
    TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = CipherSuite(0xC01C)
    TLS_SRP_SHA_WITH_AES_128_CBC_SHA = CipherSuite(0xC01D)
    TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = CipherSuite(0xC01E)
    TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = CipherSuite(0xC01F)
    TLS_SRP_SHA_WITH_AES_256_CBC_SHA = CipherSuite(0xC020)
    TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = CipherSuite(0xC021)
    TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = CipherSuite(0xC022)
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = CipherSuite(0xC023)
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = CipherSuite(0xC024)
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = CipherSuite(0xC025)
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = CipherSuite(0xC026)
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = CipherSuite(0xC027)
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = CipherSuite(0xC028)
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = CipherSuite(0xC029)
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = CipherSuite(0xC02A)
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = CipherSuite(0xC02B)
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = CipherSuite(0xC02C)
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = CipherSuite(0xC02D)
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = CipherSuite(0xC02E)
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = CipherSuite(0xC02F)
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = CipherSuite(0xC030)
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = CipherSuite(0xC031)
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = CipherSuite(0xC032)
    TLS_ECDHE_PSK_WITH_RC4_128_SHA = CipherSuite(0xC033)
    TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA = CipherSuite(0xC034)
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = CipherSuite(0xC035)
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = CipherSuite(0xC036)
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = CipherSuite(0xC037)
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = CipherSuite(0xC038)
    TLS_ECDHE_PSK_WITH_NULL_SHA = CipherSuite(0xC039)
    TLS_ECDHE_PSK_WITH_NULL_SHA256 = CipherSuite(0xC03A)
    TLS_ECDHE_PSK_WITH_NULL_SHA384 = CipherSuite(0xC03B)
    TLS_RSA_WITH_ARIA_128_CBC_SHA256 = CipherSuite(0xC03C)
    TLS_RSA_WITH_ARIA_256_CBC_SHA384 = CipherSuite(0xC03D)
    TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 = CipherSuite(0xC03E)
    TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 = CipherSuite(0xC03F)
    TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 = CipherSuite(0xC040)
    TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 = CipherSuite(0xC041)
    TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 = CipherSuite(0xC042)
    TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 = CipherSuite(0xC043)
    TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 = CipherSuite(0xC044)
    TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 = CipherSuite(0xC045)
    TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 = CipherSuite(0xC046)
    TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 = CipherSuite(0xC047)
    TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 = CipherSuite(0xC048)
    TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 = CipherSuite(0xC049)
    TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 = CipherSuite(0xC04A)
    TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 = CipherSuite(0xC04B)
    TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 = CipherSuite(0xC04C)
    TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 = CipherSuite(0xC04D)
    TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 = CipherSuite(0xC04E)
    TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 = CipherSuite(0xC04F)
    TLS_RSA_WITH_ARIA_128_GCM_SHA256 = CipherSuite(0xC050)
    TLS_RSA_WITH_ARIA_256_GCM_SHA384 = CipherSuite(0xC051)
    TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 = CipherSuite(0xC052)
    TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 = CipherSuite(0xC053)
    TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 = CipherSuite(0xC054)
    TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 = CipherSuite(0xC055)
    TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 = CipherSuite(0xC056)
    TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 = CipherSuite(0xC057)
    TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 = CipherSuite(0xC058)
    TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 = CipherSuite(0xC059)
    TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 = CipherSuite(0xC05A)
    TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 = CipherSuite(0xC05B)
    TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 = CipherSuite(0xC05C)
    TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 = CipherSuite(0xC05D)
    TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 = CipherSuite(0xC05E)
    TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 = CipherSuite(0xC05F)
    TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 = CipherSuite(0xC060)
    TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 = CipherSuite(0xC061)
    TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 = CipherSuite(0xC062)
    TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 = CipherSuite(0xC063)
    TLS_PSK_WITH_ARIA_128_CBC_SHA256 = CipherSuite(0xC064)
    TLS_PSK_WITH_ARIA_256_CBC_SHA384 = CipherSuite(0xC065)
    TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 = CipherSuite(0xC066)
    TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 = CipherSuite(0xC067)
    TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 = CipherSuite(0xC068)
    TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 = CipherSuite(0xC069)
    TLS_PSK_WITH_ARIA_128_GCM_SHA256 = CipherSuite(0xC06A)
    TLS_PSK_WITH_ARIA_256_GCM_SHA384 = CipherSuite(0xC06B)
    TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 = CipherSuite(0xC06C)
    TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 = CipherSuite(0xC06D)
    TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 = CipherSuite(0xC06E)
    TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 = CipherSuite(0xC06F)
    TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 = CipherSuite(0xC070)
    TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 = CipherSuite(0xC071)
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuite(0xC072)
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuite(0xC073)
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuite(0xC074)
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuite(0xC075)
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuite(0xC076)
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuite(0xC077)
    TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuite(0xC078)
    TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuite(0xC079)
    TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuite(0xC07A)
    TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuite(0xC07B)
    TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuite(0xC07C)
    TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuite(0xC07D)
    TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuite(0xC07E)
    TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuite(0xC07F)
    TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuite(0xC080)
    TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuite(0xC081)
    TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuite(0xC082)
    TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuite(0xC083)
    TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuite(0xC084)
    TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuite(0xC085)
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuite(0xC086)
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuite(0xC087)
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuite(0xC088)
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuite(0xC089)
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuite(0xC08A)
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuite(0xC08B)
    TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuite(0xC08C)
    TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuite(0xC08D)
    TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuite(0xC08E)
    TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuite(0xC08F)
    TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuite(0xC090)
    TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuite(0xC091)
    TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuite(0xC092)
    TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuite(0xC093)
    TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuite(0xC094)
    TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuite(0xC095)
    TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuite(0xC096)
    TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuite(0xC097)
    TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuite(0xC098)
    TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuite(0xC099)
    TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuite(0xC09A)
    TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuite(0xC09B)
    TLS_RSA_WITH_AES_128_CCM = CipherSuite(0xC09C)
    TLS_RSA_WITH_AES_256_CCM = CipherSuite(0xC09D)
    TLS_DHE_RSA_WITH_AES_128_CCM = CipherSuite(0xC09E)
    TLS_DHE_RSA_WITH_AES_256_CCM = CipherSuite(0xC09F)
    TLS_RSA_WITH_AES_128_CCM_8 = CipherSuite(0xC0A0)
    TLS_RSA_WITH_AES_256_CCM_8 = CipherSuite(0xC0A1)
    TLS_DHE_RSA_WITH_AES_128_CCM_8 = CipherSuite(0xC0A2)
    TLS_DHE_RSA_WITH_AES_256_CCM_8 = CipherSuite(0xC0A3)
    TLS_PSK_WITH_AES_128_CCM = CipherSuite(0xC0A4)
    TLS_PSK_WITH_AES_256_CCM = CipherSuite(0xC0A5)
    TLS_DHE_PSK_WITH_AES_128_CCM = CipherSuite(0xC0A6)
    TLS_DHE_PSK_WITH_AES_256_CCM = CipherSuite(0xC0A7)
    TLS_PSK_WITH_AES_128_CCM_8 = CipherSuite(0xC0A8)
    TLS_PSK_WITH_AES_256_CCM_8 = CipherSuite(0xC0A9)
    TLS_PSK_DHE_WITH_AES_128_CCM_8 = CipherSuite(0xC0AA)
    TLS_PSK_DHE_WITH_AES_256_CCM_8 = CipherSuite(0xC0AB)
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM = CipherSuite(0xC0AC)
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM = CipherSuite(0xC0AD)
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = CipherSuite(0xC0AE)
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = CipherSuite(0xC0AF)
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = CipherSuite(0xCC14)
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = CipherSuite(0xCC13)

    # TLS 1.3 ciphersuites
    TLS_AES_128_GCM_SHA256 = CipherSuite(0x1301)
    TLS_AES_256_GCM_SHA384 = CipherSuite(0x1302)
    TLS_CHACHA20_POLY1305_SHA256 = CipherSuite(0x1303)
    TLS_AES_128_CCM_SHA256 = CipherSuite(0x1304)
    TLS_AES_128_CCM_8_SHA256 = CipherSuite(0x1305)

    # MBEDTLS
    TLS_ECDH_anon_WITH_AES_128_CBC_SHA256 = CipherSuite(0xFF00)

    def __init__(self, value):
        value.init_from_name(self.name)
        pass

    def __hash__(self) -> int:
        return hash(self.value)

    def __eq__(self, other):
        return int(other) == hash(self.value)

    @property
    def key_exchange(self):
        return self.value.key_exchange

    @property
    def cipher(self):
        try:
            return self.value.cipher
        except AttributeError:
            return 0

    @property
    def cipher_type(self):
        return self.value.cipher.cipher_type

    @property
    def mac(self):
        return self.value.mac

    def get_cipher_func(self, key, iv):
        return self.value.cipher.get_cipher_func(key, iv)

    def is_block_cipher(self):
        return self.value.cipher.cipher_type == 'block'


# class _Cipher:
#     def __init__(self, hash_func):
#         self.hash_func = hash_func
#         self.name = self.hash_func.name if self.hash_func is not None else 'null'
#
#     def __hash__(self):
#         return self.name
#
#     def __eq__(self, other):
#         if other is None and self.hash_func is None:
#             return True
#         return other == self.name
#
#     def __bool__(self):
#         return self.hash_func is not None


class CipherType(Enum):
    stream = 'stream'
    block = 'block'
    aead = 'aead'


def select_preferred_cipher_suite(client_supported, server_supported):
    for i in server_supported:
        assert isinstance(i, CipherSuites)
        if i in client_supported:
            return i

    raise UnsupportedCipherException(
        "Client supported ciphersuites are not supported on the server."
    )
