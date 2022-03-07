from .helper import Helper
from ..constructs import dtls
from ..tls.handshake_ecdhe_psk import EcdhePsk as TlsEcdhePsk


class EcdhePsk(TlsEcdhePsk):
    tls_construct = dtls
    helper = Helper
