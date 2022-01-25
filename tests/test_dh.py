import socket
import ssl
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from aio_dtls.constructs import dtls


class Test1(unittest.TestCase):

    def start_tcp_server(self):
        tcpSocket = socket.socket()
        tcpSocket.bind(('', 22939))
        tcpSocket.listen()

        while True:
            newsocket, fromaddr = tcpSocket.accept()
            sslContext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            sslContext.set_ciphers("ADH-AES128-SHA256:ADH-AES256-SHA")
            sslContext.load_dh_params("dhparam.pem")
            sslSocket = sslContext.wrap_socket(
                newsocket,
                server_side=True,
            )
            try:
                # Later add stuff
                pass
            finally:
                sslSocket.shutdown(socket.SHUT_RDWR)
                sslSocket.close()

    def test_pbkdf2(self):
        import hashlib
        hashlib.pbkdf2_hmac(
            'sha256',  # Используемый алгоритм хеширования
            password.encode('utf-8'),  # Конвертирование пароля в байты
            salt,  # Предоставление соли
            100000,  # Рекомендуется использоваться по крайней мере 100000 итераций SHA-256
            dklen=128
        )


    def test_create_dh_param(self):
        # Generate some parameters. These can be reused.
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        # Generate a private key for use in the exchange.
        private_key = parameters.generate_private_key()
        # In a real handshake the peer_public_key will be received from the
        # other party. For this example we'll generate another private key and
        # get a public key from that. Note that in a DH handshake both peers
        # must agree on a common set of parameters.

        # В реальном рукопожатии peer_public_key будет получен от другой стороны.
        # В этом примере мы сгенерируем еще один закрытый ключ и получим из него открытый ключ.
        # Обратите внимание, что при рукопожатии DH оба одноранговых узла должны согласовать
        # общий набор параметров.

        peer_public_key = parameters.generate_private_key().public_key()
        shared_key = private_key.exchange(peer_public_key)
        # Perform key derivation.
        # Выполнить вывод ключей

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        # For the next handshake we MUST generate another private key, but
        # we can reuse the parameters.
        # Для следующего рукопожатия мы ДОЛЖНЫ сгенерировать еще один закрытый ключ,
        # но мы можем повторно использовать параметры.

        private_key_2 = parameters.generate_private_key()
        peer_public_key_2 = parameters.generate_private_key().public_key()
        shared_key_2 = private_key_2.exchange(peer_public_key_2)
        derived_key_2 = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key_2)

    def test_parse_public_key(self):
        private_key = ec.generate_private_key(
            ec.SECP256R1()
        )
        public_key = private_key.public_key()
        _a = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        b = EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), _a)
        # The ephemeral ECDH public key
        # a = b'A\x04R\xb6\xea\x0c\xb2-\xcf\xff\xe5t(\xeb\x805\x11#6\xeac\xe1(\xb6\x07\xb2\x91p\x9e\x8a\xfa\xcb\xd8\xcb<\xe1\x83\x11}f\xc5\xffcD\xae\xaf\xb9\xe6\x83\x19\x95V\xe7?\xf6d,a6\xd5\x07\x94\x92\xdaI\x83'
        a = b'\x04R\xb6\xea\x0c\xb2-\xcf\xff\xe5t(\xeb\x805\x11#6\xeac\xe1(\xb6\x07\xb2\x91p\x9e\x8a\xfa\xcb\xd8\xcb<\xe1\x83\x11}f\xc5\xffcD\xae\xaf\xb9\xe6\x83\x19\x95V\xe7?\xf6d,a6\xd5\x07\x94\x92\xdaI\x83'

        b = EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), a)
        # b = serialization.load_pem_public_key(a)
        b = serialization.load_der_public_key(a)
        pass

    def test_encrypted(self):
        from cryptography.fernet import Fernet
        from base64 import b64encode
        shared_key = b'\x9a\x17\xab\xe5\x16}\xbfSy\x97\x865\xd0\xa7X\xbd\xef\x91^\xeb\x90X\x16\x99\xc9\x88S\x96\xdb \xbd\xcb'
        master_secret = bytearray(
            b'\xb0\xb2\xa6\nlB\xe2p\xf0Ux<\xe3\xa8ww3k@4aS\xe9cR\xb1\x02/cY\xe7R\xd9\x8e\xbf\xa1\xa3Z\xd2-@\xa66\xc4;\xae\xdcW')
        raw_dtls_record = b'\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x04\x00N\x10\x00\x00B\x00\x02\x00\x00\x00\x00\x00BA\x04\xfb\xae\xbf\xe0\xf7{\xc5\x9f<t[8\x92\xc4i|}"\xa7\x07\xf8VN\xf1(s;\x9b\x87l=of\x81\xee\xbc\xc0\xb3t7\xf6P\xbfE\xc7\xb3\x17\xcfK2\xe2\xd6\x05\xc4A@dS\xb4\x95f\xe3\xa9]\x14\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x05\x00\x01\x01\x16\xfe\xfd\x00\x01\x00\x00\x00\x00\x00\x01\x00P\xe7\xcf\xeb\xccHp\x9e\xba\x8a\xc9\x14\xa9\xd3j\xf0\xed\x9d\xb6\xf6C\x87\xbd\xab\x9a\x85g\xa6\xa8W\x8bQv\xcd= Q\x0eH\x025EH:"\x1a\xd8\x07\xb5v\xf2\x13p\x96\xf3\xe7\xbaF\xe4\xde\x06\x01*\xee\xf7\xcf:\xa5Aw\xb0\xdbk\x92\xd8\x05\x96\xd4\xdb\xe4\xee'
        records = dtls.RawDatagram.parse(raw_dtls_record)
        # raw_handshake = dtls.GenericBlockCipher.parse(finish.fragment)

        finish = records[2].fragment

        a = b64encode(master_secret)
        f = Fernet(a)

        d = f.decrypt(encrypted_data)
        pass
