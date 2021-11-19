from ..const import tls


class SignatureScheme:
    def __init__(self, signature_hash_algorithms=None):
        pass

    @property
    def max(self):
        return [
            {
                "hash": tls.HashAlgorithm.SHA512.value,
                "signature": tls.SignatureAlgorithm.ECDSA.value
            },
            {
                "hash": tls.HashAlgorithm.SHA512.value,
                "signature": tls.SignatureAlgorithm.RSA.value
            },
            {
                "hash": tls.HashAlgorithm.SHA384.value,
                "signature": tls.SignatureAlgorithm.ECDSA.value
            },
            {
                "hash": tls.HashAlgorithm.SHA384.value,
                "signature": tls.SignatureAlgorithm.RSA.value
            },
            {
                "hash": tls.HashAlgorithm.SHA256.value,
                "signature": tls.SignatureAlgorithm.ECDSA.value
            },
            {
                "hash": tls.HashAlgorithm.SHA256.value,
                "signature": tls.SignatureAlgorithm.RSA.value
            },
            {
                "hash": tls.HashAlgorithm.SHA224.value,
                "signature": tls.SignatureAlgorithm.ECDSA.value
            },
            {
                "hash": tls.HashAlgorithm.SHA224.value,
                "signature": tls.SignatureAlgorithm.RSA.value
            },
        ]
