from .helper import Helper
from ..constructs import dtls
from ..tls.handshake_ecdh_anon import EcdhAnon as TlsEcdhAnon


class EcdhAnon(TlsEcdhAnon):
    tls_construct = dtls
    helper = Helper
