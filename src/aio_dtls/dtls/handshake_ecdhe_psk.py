from ..constructs import dtls
from ..tls.handshake_ecdhe_psk import EcdhePsk as TlsEcdhePsk
from .helper import Helper


class EcdhePsk(TlsEcdhePsk):
    tls_construct = dtls
    helper = Helper

