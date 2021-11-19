from . import helper as dtls_helper
from ..constructs import dtls
from ..tls.handshake_ecdh_anon import EcdhAnon as TlsEcdhAnon


class EcdhAnon(TlsEcdhAnon):
    tls_construct = dtls
    tls_helper = dtls_helper
