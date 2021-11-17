import logging

from .enum_props import EnumProps
from ..const.cipher_suites import CipherSuites as EnumCipherSuites

logger = logging.getLogger(__name__)


class CipherSuites(EnumProps):
    supported = [
        'TLS_ECDHE_ECDSA_WITH_AES_128_CCM',
        'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
        'TLS_ECDH_anon_WITH_AES_128_CBC_SHA256'
    ]
    EnumClass = EnumCipherSuites
