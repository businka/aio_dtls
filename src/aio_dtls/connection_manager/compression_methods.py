from aio_dtls.const import tls


class CompressionMethods:
    def __init__(self, compression_methods=None):
        pass

    @property
    def max(self):
        return [
            tls.CompressionMethod.NULL.value
        ]
