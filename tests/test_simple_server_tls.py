import asyncio
import logging
import unittest

from aio_dtls.const import tls as const
from aio_dtls.const.cipher_suites import CipherSuites
from aio_dtls.constructs import tls
from aio_dtls.tls.socket import TlsSocket
from tests.dtls_test_obj import DemoProtocolClass

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


class TestServer(unittest.IsolatedAsyncioTestCase):
    async def test_server(self):
        self.server_address = ('192.168.1.13', 10001)
        ciphers = [
            'TLS_ECDH_anon_WITH_AES_256_CBC_SHA',
            # 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM',
            # 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
            # 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA256',
        ]
        _sock = TlsSocket(ciphers=ciphers)
        await _sock.listen(None, DemoProtocolClass, self.server_address[0], self.server_address[1])
        await asyncio.sleep(999)

    async def test_anon_client(self):
        # print(f'Received: {data.decode()!r}')
        #
        # print('Close the connection')
        # writer.close()
        self.server_address = ('192.168.1.13', 10002)
        ciphers = [
            # 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM',
            # 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
            # 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA256',
            # 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA'
            'TLS_ECDH_anon_WITH_AES_128_CBC_SHA'
        ]
        _sock = TlsSocket(ciphers=ciphers)
        await _sock.connect(self.server_address)
        # await _sock.listen(None, DemoProtocolClass, self.server_address[0], self.server_address[1])
        await _sock.send(b"Congratulations!")
        await asyncio.sleep(9999)
        pass

    async def test_ecdsa_client(self):
        # print(f'Received: {data.decode()!r}')
        #
        # print('Close the connection')
        # writer.close()
        self.server_address = ('192.168.1.13', 10002)
        ciphers = [
            'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
            # 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM',
            # 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
            # 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA256',
            # 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA'
        ]
        _sock = TlsSocket(ciphers=ciphers)
        await _sock.connect(self.server_address)
        # await _sock.listen(None, DemoProtocolClass, self.server_address[0], self.server_address[1])
        await _sock.send(b"Congratulations!")
        await asyncio.sleep(9999)
        pass

    async def test_send_hello(self):
        self.server_address = ('192.168.1.13', 10001)
        client_hello = b'\x16\x03\x01\x02\x04\x01\x00\x02\x00\x03\x03\xd0\x1c"\x05=>`\xa6\x0b[$\xaeR\x06Z\xe8\x90\xd1kc,\xc89y\xdd\xadtK\xa4\xb2m\xa7 \xfc\x05nIy\xcd\xe6e\xab\xeai\xda\x18\xb1\x8e\x8e\x94\xcf\x9fM\n~\xa2\xb2\x8a{\n\xfb\xa7G`\xbd\x00^\x00\xff\x13\x02\x13\x01\x13\x03\x13\x04\xcc\xa9\xc0,\xc0+\xc0\xad\xc0\xac\xc0$\xc0#\xc0\n\xc0\t\xc0\x08\xcc\xa8\xc00\xc0/\xc0(\xc0\'\xc0\x14\xc0\x13\xc0\x12\xcc\xaa\x00\x9f\x00\x9e\xc0\x9f\xc0\x9e\x00k\x00g\x009\x003\x00\x16\x00\x9d\x00\x9c\xc0\x9d\xc0\x9c\x00=\x00<\x005\x00/\x00\n\x00\x13\x002\x008\x00\xa2\x00\xa3\x01\x00\x01Y\x00\x16\x00\x00\x00\x17\x00\x00\x00\r\x000\x00.\x08\x07\x08\x08\x06\x03\x05\x03\x04\x03\x03\x03\x02\x03\x06\x02\x05\x02\x04\x02\x03\x02\x02\x02\x08\x06\x08\x0b\x08\x05\x08\n\x08\x04\x08\t\x06\x01\x05\x01\x04\x01\x03\x01\x02\x01\x00+\x00\t\x08\x03\x04\x03\x03\x03\x02\x03\x01\x003\x00k\x00i\x00\x17\x00A\x04U\xa1s\xda"\xf4\xf7\xb6\xe6\x86\xef\xf6c;\xa1\xbf\x87\x0c\xaa\xd2\xb9K\xc9\xd0\xe8\x96QG\xe1\xfd\xcf\x95\xbat\xff\xe0\xf8\x073\xe8\x93\xcb\xf9V\x12{ \xed5\x9faoP\xf0\x00}\xe55x\xcd@\xb8\xae\xe9\x00\x1d\x00 \xd3o[\x91c\x05\xecG\x974.\xc1\xd0\xb5V\x13\x08\x8e\xc6\x9a\xc5\xf0/\xd2\x9bdf#\x85;\x01\x15\x00-\x00\x03\x02\x01\x00\x00\x0b\x00\x02\x01\x00\x00\n\x00\x16\x00\x14\x00\x17\x00\x1d\x00\x1e\x00\x18\x00\x19\x01\x00\x01\x01\x01\x02\x01\x03\x01\x04\x00\x0f\x00\x01\x01\x00\x1c\x00\x02@\x01\x00\t\x00\x02\x01\x00\x00\x15\x00e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        res = tls.Plaintext.parse(client_hello)
        client_hello2 = tls.Plaintext.build({
            "type": const.ContentType.HANDSHAKE.value,
            "version": const.ProtocolVersion.TLS_1.value,
            "fragment": {
                "handshake_type": const.HandshakeType.CLIENT_HELLO.value,
                "fragment": {
                    "cipher_suites": [
                        CipherSuites['TLS_ECDH_anon_WITH_AES_256_CBC_SHA'].value,
                    ],
                    "client_version": const.ProtocolVersion.TLS_1_2.value,
                    "compression_methods": [const.CompressionMethod.NULL.value],
                    "random": b'\xd0\x1c"\x05=>`\xa6\x0b[$\xaeR\x06Z\xe8\x90\xd1kc,\xc89y\xdd\xadtK\xa4\xb2m\xa7',
                    # session_id=b'\xfc\x05nIy\xcd\xe6e\xab\xeai\xda\x18\xb1\x8e\x8e\x94\xcf\x9fM\n~\xa2\xb2\x8a{\n\xfb\xa7G`\xbd',
                    "extension": [
                        {
                            "type": const.ExtensionType.SIGNATURE_ALGORITHMS.value,
                            "data": [{
                                "hash": const.HashAlgorithm.SHA256.value,
                                "signature": const.SignatureAlgorithm.ECDSA.value
                            }, ]
                        },
                        {
                            "type": const.ExtensionType.ELLIPTIC_CURVES.value,
                            "data": {"elliptic_curve_list": [const.NamedCurve['secp256r1'].value]}
                        },
                        {
                            "type": const.ExtensionType.RENEGOTIATION_INFO.value,
                            "data": b'\x00'
                        },
                        {
                            "type": const.ExtensionType.EXTENDED_MASTER_SECRET.value,
                            "data": b''
                        },
                        {
                            "type": const.ExtensionType.EC_POINT_FORMATS.value,
                            "data": {"ec_point_format_list": [
                                const.ECPointFormat.uncompressed.value
                            ]}
                        }]

                }
            }
        })
        ciphers = [
            # 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM',
            # 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
            'TLS_ECDH_anon_WITH_AES_128_CBC_SHA256',
        ]
        _sock = TlsSocket(ciphers=ciphers)
        await _sock.connect(self.server_address)
        # await _sock.listen(None, DemoProtocolClass, self.server_address[0], self.server_address[1])
        _sock.raw_send(client_hello2)
        data = await _sock._reader.read()
        server_hello = tls.Plaintext.parse(data)
        data = await _sock._reader.read()
        cert = tls.Plaintext.parse(data)
        pass

    def test_create_server_finished(self):
        from aio_dtls.connection_manager.connection import Connection
        from aio_dtls.tls import helper as tls_helper
        from aio_dtls.const.cipher_suites import CipherSuites

        connection = Connection(('127.0.0.1', 11111))
        connection.ssl_version = const.ProtocolVersion.TLS_1_2
        connection.cipher = CipherSuites.TLS_ECDH_anon_WITH_AES_256_CBC_SHA
        connection.security_params.client_random = bytearray(
            b'\x9d\x16\xc9\\u\xb4Rc\x03\xccg\xa9|\xa8\x94\x91I\x8eJ\x93\t2\xfa\x99\x19\xff\xfb3U\xb2\xd2\x07')
        connection.security_params.server_random = bytearray(
            b'ak\xfe,\xca7ac\t!\x81F\xfa\x7f\xeb\x9dy\xd8\x8b\xcc|\xfd\x7f\x17\xa2*_\xf8\xb4\xa6\x0b\x1a')
        connection.security_params.master_secret = bytearray(
            b'I\x84u\x07\xa8$\xcd\xfb\xd9B>\xa6\xaf\xb8\x02\x07\xef3\x984\r\xdd\x97n\xa6c\xac\xb4\x08\x8d OjO&\xa6\xf8\xb6I5\xdcT\xcb\x99\xf3\x0e~C')

        connection.handshake_params.handshake_messages = bytearray(
            b'\x01\x00\x02\x00\x03\x03\x9d\x16\xc9\\u\xb4Rc\x03\xccg\xa9|\xa8\x94\x91I\x8eJ\x93\t2\xfa\x99\x19\xff\xfb3U\xb2\xd2\x07 \x9b\xdf\xa0n\x8e\xa2\x98\x16:\xe4\xf7\x10\xf7\x0390\x9c\x83M0\x88\xe8t\xbcFl\xe0\xcfI;\x8a\x0e\x00\x16\x00\xff\xc0\x19\xc0\x18\xc0\x17\x00\xa7\x00\xa6\x00m\x00:\x00l\x004\x00\x1b\x01\x00\x01\xa1\x00\x16\x00\x00\x00\x17\x00\x00\x00\r\x000\x00.\x08\x07\x08\x08\x06\x03\x05\x03\x04\x03\x03\x03\x02\x03\x06\x02\x05\x02\x04\x02\x03\x02\x02\x02\x08\x06\x08\x0b\x08\x05\x08\n\x08\x04\x08\t\x06\x01\x05\x01\x04\x01\x03\x01\x02\x01\x00+\x00\t\x08\x03\x04\x03\x03\x03\x02\x03\x01\x003\x00k\x00i\x00\x17\x00A\x04Jn>_\xe4\xc3\x00?Q\x83\xf7w[\x93\xcd\x10w\x86\xbb\x7f\xc2U\xd1\xcdY4\xe7\x1c\x88\xbb\\\xfd\xc6\xcb`\xcb\x96\xd5\xe08\xc9x\xfd]/\x83O\xc4\x05\xef\x9a\x98\xd1\x02{\x95E\xc7s\xdb\xe2\xef\xf0m\x00\x1d\x00 y\xcb\r\x1f\xe2pwG\x14z[\xf2\x95ae-\xca9(6+6\xa0S\x84\x08&)?e.i\x00-\x00\x03\x02\x01\x00\x00\x0b\x00\x02\x01\x00\x00\n\x00\x16\x00\x14\x00\x17\x00\x1d\x00\x1e\x00\x18\x00\x19\x01\x00\x01\x01\x01\x02\x01\x03\x01\x04\x00\x0f\x00\x01\x01\x00\x1c\x00\x02@\x01\x00\t\x00\x02\x01\x00\x00\x15\x00\xad\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00W\x03\x03ak\xfe,\xca7ac\t!\x81F\xfa\x7f\xeb\x9dy\xd8\x8b\xcc|\xfd\x7f\x17\xa2*_\xf8\xb4\xa6\x0b\x1a U\xb4\x90\x85\xfb\xc2[\xf3PW\x0f\x8b\xce\x80?\x1e\x02\xae\t\xb7\xb4\x83\xe7A\xe5\xdd\x85Y\xe6\xff=G\xc0\x19\x00\x00\x0f\xff\x01\x00\x01\x00\x00\x17\x00\x00\x00\x0b\x00\x02\x01\x00\x0c\x00\x00E\x03\x00\x17A\x04S\xd2\xd7I/\xb6\x8e*\xfc82p\xb0\x99\\\xe5l}D\x9b\xc5*\xa4\xf4\xec/d[?\xd8I\x9a\xa2pV`\xd7\xdb\xee\xb3af\xd9)\r<\xaegXD\xf0{\xa3 \xc03\xa2\xc8\xba\xa5\xee\xb3]\x00\x0e\x00\x00\x00\x10\x00\x00BA\x04a\x06\x1ep\xba\x9e\xa3\xdd\xbbL\xf3\xcejI\xae<\xf4\x84\xbe\xdf\xad\x1e\xa1`\x9c\x1e\x0c\xc8\xc2\xee[x\xce\x1cEO\xdd\xbc`\x05\xa2\x040q7C\x13\x14\xdcpg\x07\xf6\xa8\xc2zK\x9d\xcb\x91%\x13\xe9\x92')

        key_length = connection.cipher.cipher.key_material
        iv_length = connection.cipher.cipher.iv_size
        mac_length = connection.cipher.mac.mac_length
        digestmod = connection.cipher.mac.hash_func.name

        self.assertEqual(32, key_length, 'key_length')
        self.assertEqual(16, iv_length, 'iv_length')
        self.assertEqual(20, mac_length, 'mac_length')
        self.assertEqual('sha1', digestmod, 'digestmod')

        tls_helper.calc_pending_states(connection)

        connection.fixed_iv_block = bytearray(b'+&\x01k\xe5/8\xcd| \xed(\xb1c\xfc\x95')

        self.assertEqual(bytearray(b'\x13\xdf\x04A\xda\xfd\x99-\xd7\xb6b_\xb4z\xc3z(\xd1\xcf\x84'),
                         connection.client_write_MAC_key, 'client_write_MAC_key')
        self.assertEqual(bytearray(b'Duw\xedA\xa4\r\x17\x8f\x83\xa8\xa2w\xf3b\xd8\x9b\x81\xaaY'),
                         connection.server_write_MAC_key, 'server_write_MAC_key')
        self.assertEqual(bytearray(b'1Vo\x92\x04[\xa0\x8arrHl\xd7H\xc5\xf9\xc8\r\x90G.\x81\xc7=\xa8YQ\x9c\xe9}4H'),
                         connection.client_write_encryption_key, 'client_write_encryption_key')
        self.assertEqual(bytearray(b'\xf1\xf9D\x10\x11\xdf\x84\x9b"y\x8e[BKZ\xa5/wh\x10B\\\x08o\xe9$<2\x18[\xe1\x9e'),
                         connection.server_write_encryption_key, 'server_write_encryption_key')
        self.assertEqual(bytearray(b'\xffN\x1f\x1a3\x057\x99\x18A\xe6\x90\xfc\xe9t\xc9'),
                         connection.client_write_iv, 'client_write_iv')
        self.assertEqual(bytearray(b'Y7@7\xbc\x04#\xce\xc7\xbd\xa1\x10\xc5\x19\x8e\xa2'),
                         connection.server_write_iv, 'server_write_iv')

        verify_data = tls_helper.generate_finished_verify_data(connection, b'client finished')
        self.assertEqual(bytearray(b'R\xb6\xb9\xcfp\xfc\xccn\xd6\x1ey\xec'), verify_data, 'verify_data')
        finished_fragment = tls_helper.build_handshake_fragment_finished(connection)
        record = tls_helper.build_handshake_record(None, connection, const.HandshakeType.FINISHED.value,
                                                   finished_fragment)
        data = bytearray(record.fragment)
        if connection.client_mac_func:
            # seq_num = connection.state.get_sequence_number()
            mac = tls_helper.build_mac(connection, connection.client_mac_func, 0,
                                       const.ContentType.HANDSHAKE.value, record.fragment)
            data += mac
            self.assertEqual(bytearray(b'-\xde[\x17+\xe2r\x94B/G\xcc\x9e\x97\xbe\xf7&\xfeTc'), mac, mac)
        if connection.cipher.is_block_cipher():
            if connection.client_cipher_func:
                data = connection.fixed_iv_block + data
                data = tls_helper.add_padding(connection, data)

                self.assertEqual(
                    bytearray(
                        b'+&\x01k\xe5/8\xcd| \xed(\xb1c\xfc\x95\x14\x00\x00\x0cR\xb6\xb9\xcfp\xfc\xccn\xd6\x1ey\xec-\xde[\x17+\xe2r\x94B/G\xcc\x9e\x97\xbe\xf7&\xfeTc\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'),
                    data
                )

                encryptor = connection.client_cipher_func.encryptor()
                res2 = encryptor.update(data) + encryptor.finalize()
                self.assertEqual(
                    bytearray(
                        b';\xfaa#"X\xdaT\xe98\x89\x1dm\x17D\x10t[J\x00Z\xf5\x07\xaa~\x91\xa4\x06\x16\xe2Pi\xaf\xb3q\xfb\xa3\x9b\xdb@\xff\x81\xa9\x0e\xda\x13\xce,xT\x16\x11W\xfd\xe4M\xea\x8a\xdb;\x93!d\x82'),
                    res2
                )
                pass

        pass

    async def test_build_client_hello(self):
        from aio_dtls import ConnectionManager, Connection
        from aio_dtls.tls.handshake import Handshake
        from aio_dtls.constructs.tls import Plaintext
        ciphers = [
            # 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM',
            # 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
            'TLS_ECDH_anon_WITH_AES_128_CBC_SHA256',
        ]
        connection_manager = ConnectionManager(ciphers=ciphers)
        connection = Connection(('127.0.0.1', 10001))
        raw_handshake = Handshake.build_client_hello_record(connection_manager, connection)
        handshake = Plaintext.parse(raw_handshake)
        self.assertEqual(1, len(handshake.fragment.fragment.cipher_suites), 'count ciphers')
        pass
