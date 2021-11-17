# from aio_dtls.protocol import dtls_handshake_ecdh
import base64
import secrets
import time
import unittest

from aio_dtls.constructs import tls, tls_ecc
from aio_dtls.constructs.dtls import Plaintext, ClientHello, RawPlaintext, Datagram, RawDatagram


class TestDTLSPlaintextParsing(unittest.TestCase):
    """
    Tests for parsing of DTLSPlaintext records.
    """

    def test_parse_dtls_plaintext_handshake(self):
        """
        :func:`parse_dtls_plaintext` returns an instance of
        :class:`DTLSPlaintext`, which has attributes representing all the fields
        in the DTLSPlaintext struct.
        """
        packet = (
            b'\x16'  # ContentType 
            b'\xfe\xfd'  # ProtocolVersion
            b'\x00\x00'  # epoch
            b'\x00\x00\x00\x00\x00'  # sequence_number
            b'\x00\x0A'  # big-endian length
            b'0123456789'  # fragment
        )
        packet = bytes(bytearray([
            0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x62, 0x01, 0x00, 0x00,
            0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x56, 0xfe, 0xfd, 0x61, 0x2b, 0xa7, 0x1e, 0xdb,
            0x97, 0xbc, 0x34, 0xee, 0x05, 0x74, 0xc4, 0xd5,
            0x90, 0x18, 0x11, 0x4c, 0x05, 0x2f, 0xb5, 0xb8,
            0x17, 0x83, 0x95, 0x56, 0x45, 0x77, 0xee, 0x5e,
            0xcf, 0xdd, 0x4e, 0x00, 0x00, 0x00, 0x04, 0xff,
            0x00, 0x00, 0xff, 0x01, 0x00, 0x00, 0x28, 0x00,
            0x0d, 0x00, 0x12, 0x00, 0x10, 0x06, 0x03, 0x06,
            0x01, 0x05, 0x03, 0x05, 0x01, 0x04, 0x03, 0x04,
            0x01, 0x03, 0x03, 0x03, 0x01, 0x00, 0x0a, 0x00,
            0x04, 0x00, 0x02, 0x00, 0x17, 0x00, 0x0b, 0x00,
            0x02, 0x01, 0x00, 0x00, 0x17, 0x00, 0x00]))

        # packet = b'\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x02\x00b\x01\x00\x00V\x00\x00\x00\x00\x00\x00\x00V\xfe\xfd`\xc6_,\xdc\x0b&\xcf1L\x98\x15%\xcc\xd6\xf5\xba\xb4\xb5\x93\xd39\rk\xfb\x16l\xf0\xdd\xd9,a\x00\x00\x00\x04\xff\x00\x00\xff\x01\x00\x00(\x00\r\x00\x12\x00\x10\x06\x03\x06\x01\x05\x03\x05\x01\x04\x03\x04\x01\x03\x03\x03\x01\x00\n\x00\x04\x00\x02\x00\x17\x00\x0b\x00\x02\x01\x00\x00\x17\x00\x00'
        record = Plaintext.parse(packet)
        record2 = RawPlaintext.parse(packet)
        build = Plaintext.build(record)
        assert base64.b64encode(build).decode() == base64.b64encode(packet).decode()
        assert record.type == tls.ContentType.HANDSHAKE.name
        assert record.version.major == 254
        assert record.version.minor == 253
        assert record.epoch == 0
        assert record.sequence_number == 2
        assert record.fragment == b'0123456789'

    def test_parse_client_hello(self):
        data = b'\xfe\xfd`\xc6_,\xdc\x0b&\xcf1L\x98\x15%\xcc\xd6\xf5\xba\xb4\xb5\x93\xd39\rk\xfb\x16l\xf0\xdd\xd9,a\x00\x00\x00\x04\xff\x00\x00\xff\x01\x00\x00(\x00\r\x00\x12\x00\x10\x06\x03\x06\x01\x05\x03\x05\x01\x04\x03\x04\x01\x03\x03\x03\x01\x00\n\x00\x04\x00\x02\x00\x17\x00\x0b\x00\x02\x01\x00\x00\x17\x00\x00'
        # b'\xdc\x0b&\xcf1L\x98\x15%\xcc\xd6\xf5\xba\xb4\xb5\x93\xd39\rk\xfb\x16l\xf0\xdd\xd9,a'
        client_hello = ClientHello.parse(data)
        assert client_hello.type == 22

    def test_parse_client_hello_request(self):
        data = b'\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x02\x00b\x01\x00\x00V\x00\x00\x00\x00\x00\x00\x00V\xfe\xfd`\xc6_,\xdc\x0b&\xcf1L\x98\x15%\xcc\xd6\xf5\xba\xb4\xb5\x93\xd39\rk\xfb\x16l\xf0\xdd\xd9,a\x00\x00\x00\x04\xff\x00\x00\xff\x01\x00\x00(\x00\r\x00\x12\x00\x10\x06\x03\x06\x01\x05\x03\x05\x01\x04\x03\x04\x01\x03\x03\x03\x01\x00\n\x00\x04\x00\x02\x00\x17\x00\x0b\x00\x02\x01\x00\x00\x17\x00\x00'
        record = Plaintext.parse(data)
        pass

    def test_parse_hello_verify_request(self):
        data = b'\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x02\x00/\x03\x00\x00#\x00\x00\x00\x00\x00\x00\x00#\xfe\xfd `\xcb;0?A\x10\x90\x92i\x84%\xb4\xa2J\xe3\x867A[\xb21/\r\n\xa3N\x18V\xc4s\x95'
        record = Plaintext.parse(data)

    def test_parse_client_finished(self):
        data = b'\xb4D6\xfeP}Qou\x0b\xad\x92\x01\xbe\x7f\xe8\x14\x00\x00\x0c\xe5K\xb7\x9c\x1f\xe3)Q\xa1\x08fD\x83liN\xf4\xf9U*\xf3\\1\xdc)\xe9\xac\x1b>P=|\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
        tls_ciphertext_length = len(data)

        record_iv_length = 16
        mac_length = 20
        padding_length = data[-1]
        tls_compressed_length = tls_ciphertext_length - record_iv_length - mac_length - 1 - padding_length

        params = dict(
            cipher_type='block',
            record_iv_length=record_iv_length,
            mac_length=mac_length,
            tls_compressed_length=tls_compressed_length,

        )
        res = tls.GenericBlockCipher.parse(data, **params)
        res1 = tls.BlockCipher.parse(data, **params)
        res2 = tls.Handshake.parse(res.block_ciphered.content)
        pass

    def test_buid_server_hello(self):
        resp1 = ServerHello.build({
            "server_version": tls.ProtocolVersion.DTLS_1_2.value,
            "random": {
                "gmt_unix_time": int(time.time()),
                "random_bytes": secrets.token_bytes(28)
            },
            "session_id": secrets.token_bytes(32),
            "cipher_suites": [0xFF00],
            "compression_methods": [0],
            "extension": [
                {
                    "type": tls.ExtensionType.RENEGOTIATION_INFO.value,
                    "data": b'\x00'
                },
                {
                    "type": tls.ExtensionType.EXTENDED_MASTER_SECRET.value,
                    "data": b''
                },
                {
                    "type": tls.ExtensionType.EC_POINT_FORMATS.value,
                    "data": b'\x00\x02\x01\x00'
                }

            ],
        })

    def test_decode_server_key_exchange(self):
        data = b'\x03\x00\x17\x41\x04\x52\xb6\xea\x0c\xb2\x2d\xcf\xff\xe5\x74\x28\xeb\x80\x35\x11\x23\x36\xea\x63\xe1\x28\xb6\x07\xb2\x91\x70\x9e\x8a\xfa\xcb\xd8\xcb\x3c\xe1\x83\x11\x7d\x66\xc5\xff\x63\x44\xae\xaf\xb9\xe6\x83\x19\x95\x56\xe7\x3f\xf6\x64\x2c\x61\x36\xd5\x07\x94\x92\xda\x49\x83'
        #
        res = tls_ecc.ServerKeyExchangeECDH.parse(data)
        a = b'\x03\x00\x17A\x04>\x9a+\xa1\xb5\x9f\xc9\x89\xed\xe8\x1bd\xba\x0b\x82\xae\xb3\x80;&\x9d\x1a\x8d\xadc6\xab\xde\xa7\xd5[BS\x8dp\x85\xf0\x01\xfcr\xc2\xd6?7\xae\x8f!\x93\xfb\x08\xab>2*)I\xa9fihy\xe0o\xc3'
        res = Plaintext.parse(a)
        pass

    def test_client_key_exchange(self):
        # data = b'\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x06\x00N\x10\x00\x00B\x00\x02\x00\x00\x00\x00\x00BA\x04\xd7\x0cX\x0f\xae\xcd\x87ZX\xd7\xbcvY\xe3UR6|j\xac\xbf&[$\x11\xfd\x9cX\t\x9b)]Rw\xce \xbb\xf4p\x01r?9\xe0P\x13F\x90t\xd2o\x94m)\x1c\xad\xd0l\x80\xe8\x98Y}\x9d\x14\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x07\x00\x01\x01\x16\xfe\xfd\x00\x01\x00\x00\x00\x00\x00\x02\x00P\xbb4\x82,\x13\x06\x86J\x13z\x9e\xd0\xeds\xf4\x83rC\x18\xb88\x83R\xef\xc6 \xf9\x10f\x8c\x15\xfe}\xa5\xff\xf1h\xfdJ\xec\x04\xe2K\x80;A-\xa3\xf4"&KWm\x84{\x8f\xe6\xd05\xa8\'91\xf2\x08\xc8A\xab\x0e\x89\xe6jo,\xda\xf1\xf3\xc1\xe9'
        # data = b'\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x02\x00N\x10\x00\x00B\x00\x02\x00\x00\x00\x00\x00BA\x04\xb8s\xef\x192\x8ef\x138Zw\xa7\x18oB>YdY+\xb6\xf0]\xd4\x88!D\x0f\xf0nOK\x133\x96\x99\xba5R\x07\xc8SM\xb2\xa8\xf3\xf0\xb0kV\xf2\xe8\tp\x06\xdc\x82\xf3k`xX\xbf\xd1\x14\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x03\x00\x01\x01\x16\xfe\xfd\x00\x01\x00\x00\x00\x00\x00\x00\x00P\re\x12\xf5u\x0f\x8c\x94\xd2\xd5\xdc\x9a\x1e\xcd\x98Vj\x07A\xec\xeb\x9d\x95\x17/s\x15\x1a\r\x85\xf5I\x92\xcd^\xed2"\xaa\xc1\xbd\x1f^\xca\xf7][\xe0-v\xe8\xb9\xfb\x0b\xb7_\xf6\x12\xc4EY\xf2\x16V{\x89\x02\xecZ\xf1\x0bv\x0e\xa7\xb2\xd3\x91\x11\xc3\xe1'
        # data = b'\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x06\x00N\x10\x00\x00B\x00\x02\x00\x00\x00\x00\x00BA\x04u\xcc\x9az_t\xa8\xd38MD\xafA%\xa4sR\x8fh\xa3\xb4\x08\x85;7s%\x8d\xa9\x7f\xd6\x1bkt\x8e8\xb6\x1dT\x96\xf8\xe2\xbd\x13\xd7\xa5\xcdnTe\xacD8\xbe@\xe8\xd7Y\xc9D\xef\x06\x06\x9c\x14\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x07\x00\x01\x01\x16\xfe\xfd\x00\x01\x00\x00\x00\x00\x00\x02\x00P\xd9\xea?\xfa2\xb9\x14\xd4\x92\xc0\x8f\xee"\x9e\xcfs\xbd\x00T\x8f\xb9\x90\xef\xe6ejby\xe6\xa1|\x85G\x07^*\xd4-?\xed\xb1\xca\x8ce|?\x89\xa1)g]@\x87\x83E\x8b\xb4\xb6\x0f`f\x05\xb3V\xd0\x93\xa2G)0\xf6\xa9\x8b@\xb5\xc5S{N\x8e'
        # data = b'16fefd000100000000000000501b0bb04fb0137f3caaecebe529d2c9d86d4ba37debe7052f9e62fc92f396ae347ab2d959a6811830fa10e1fd22e58b48b57c54ac884a004fbb22267cb58f487362c38dbd788a80f24cdeae25a3b4d69f'
        data = b'\x16\xfe\xfd\x00\x01\x00\x00\x00\x00\x00\x00\x00\x50\x1b\x0b\xb0\x4f\xb0\x13\x7f\x3c\xaa\xec\xeb\xe5\x29\xd2\xc9\xd8\x6d\x4b\xa3\x7d\xeb\xe7\x05\x2f\x9e\x62\xfc\x92\xf3\x96\xae\x34\x7a\xb2\xd9\x59\xa6\x81\x18\x30\xfa\x10\xe1\xfd\x22\xe5\x8b\x48\xb5\x7c\x54\xac\x88\x4a\x00\x4f\xbb\x22\x26\x7c\xb5\x8f\x48\x73\x62\xc3\x8d\xbd\x78\x8a\x80\xf2\x4c\xde\xae\x25\xa3\xb4\xd6\x9f'
        res = RawDatagram.parse(data)
        res2 = Datagram.parse(data)
        self.assertEqual(len(res), 2)
        res2 = tls_ecc.ClientKeyExchangeECDH.parse(res[0].fragment.fragment)
        pass

    def test_parse_chipher_text_zero_padding(self):
        data = b'\xa5\xb9\x89\xd9\xfa\xe2\xe8\xe1#U\xb1C~"\xb9\xb4H\x02[\xce\x15\xff}|\x83\xc5\xcd\x81\xb3oic\x03sec\x05pstat\x12\'\x10R\'\x10\xe2\x06\xe3\x08\x00B\x08\x00\xff\xbfbom\x04\xff\x99\xf0\x13\xc5\xf67y\xad\x06v+\x1a\x12\xcd5\xe6\xbb\xef\x86\x1c-\xfc\xc0\x96\xcf\xe1I\x9f\x98\xcb\x93x\x00'
        print(data.hex(" "))
        data_length = len(data)
        record_iv_length = 16
        mac_length = 32
        padding_length = data[-1]
        tls_compressed_length = data_length - record_iv_length - mac_length - 1 - padding_length
        res = tls.CiphertextFragment.parse(
            data,
            cipher_type='block',
            record_iv_length=record_iv_length,
            mac_length=mac_length,
            tls_compressed_length=tls_compressed_length,
        )
