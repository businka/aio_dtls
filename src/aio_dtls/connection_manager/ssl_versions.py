from .enum_props import EnumProps
from ..const import tls, dtls


class SSlVersions(EnumProps):
    def __init__(self, ssl_versions=None, is_dtls=True):
        self.is_dtls = is_dtls
        if self.is_dtls:
            self.EnumClass = dtls.ProtocolVersion
            self.supported = [
                dtls.ProtocolVersion.DTLS_1_2.name
            ]
        else:
            self.EnumClass = tls.ProtocolVersion
            self.supported = [
                tls.ProtocolVersion.TLS_1_2.name
            ]

        super(SSlVersions, self).__init__(ssl_versions)
        pass
