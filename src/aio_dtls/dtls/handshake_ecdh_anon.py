from ..constructs import dtls
from ..tls.handshake_ecdh_anon import EcdhAnon as TlsEcdhAnon
from .helper import Helper


class EcdhAnon(TlsEcdhAnon):
    tls_construct = dtls
    helper = Helper

