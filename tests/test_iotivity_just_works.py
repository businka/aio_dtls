# from tests.demo_server import DemoServer, DemoEndpoint, DemoProtocolClass, ClientEndpoint
from aio_dtls.connection_manager.connection import Connection
from aio_dtls.const import tls
from aio_dtls.constructs import dtls
from aio_dtls.dtls.handshake import Handshake
from aio_dtls.tls import helper as tls_helper
from tests.data import iotivity_simple_server as iotivity_simple
from tests.dtls_helper import DtlsHelper


class TestIotivityJustWorksOTM(DtlsHelper):
    def setUp(self) -> None:
        super(TestIotivityJustWorksOTM, self).setUp()

    def test_handshake(self):
        self.assertEqual(0, len(self.client_connection_manager.connections), 'count connections on client')
        self.assertEqual(0, len(self.server_connection_manager.connections), 'count connections on server')

        connection = self.client_connection_manager.get_connection(self.server_address)
        self.client_connection_manager.new_client_connection(connection)

        client_hello_empty_cookie = Handshake.build_client_hello(
            self.client_endpoint._sock.connection_manager,
            connection)
        _answer1 = dtls.Plaintext.parse(client_hello_empty_cookie)
        _answer2 = dtls.Plaintext.parse(iotivity_simple.client_hello_empty_cookie)
        self.assertEqual(client_hello_empty_cookie, iotivity_simple.client_hello_empty_cookie)
        connection.sequence_number += 1

        hello_verify_request = self.check_request(client_hello_empty_cookie, iotivity_simple.hello_verify_request)
        self.assertEqual(1, len(self.client_connection_manager.connections), 'count connections on client')
        self.assertEqual(0, len(self.server_connection_manager.connections), 'count connections on server')

        client_hello_with_cookie = self.check_answer(hello_verify_request, iotivity_simple.client_hello_with_cookie)

        server_hello = self.check_request(client_hello_with_cookie, iotivity_simple.server_hello)

        self.assertEqual(1, len(self.client_connection_manager.connections), 'count connections on client')
        self.assertEqual(1, len(self.server_connection_manager.connections), 'count connections on server')

        client_change_cipher = self.check_answer(server_hello, iotivity_simple.client_change_cipher)

        client_connection: Connection = self.client_connection_manager.get_connection(self.server_address)
        server_connection: Connection = self.server_connection_manager.get_connection(self.client_address)
        _random = self.client_connection_manager.generate_tls_random()
        self.assertEqual(_random, client_connection.client_random, 'client client.random')
        self.assertEqual(_random, client_connection.server_random, 'client server.random')
        self.assertEqual(_random, server_connection.client_random, 'server client.random')
        self.assertEqual(_random, server_connection.server_random, 'server server.random')

        self.check_request(client_change_cipher, iotivity_simple.server_change_cipher)

    @staticmethod
    def f_bytearray(data):
        return bytes.fromhex(data.replace(' ', ''))

    def test_generate_mbed_master_secret(self):
        label = b"master secret"
        pre_master_secret = self.f_bytearray(
            "2f 73 8f 90 fb 32 0d 33 0b 98 4f 99 92 21 dd 17 "
            "85 c3 66 9e 4e a4 ea e0 4b da f2 64 28 d0 fd fa")
        seed = self.f_bytearray(
            "61 92 60 58 08 d6 33 fd 22 1c 37 11 02 f8 95 a3 "
            "86 46 09 1f d4 ec 6b eb 18 77 11 08 a7 3a 8a 8e "
            "61 92 60 58 eb 33 6f 9b 81 9b 0b 52 fb 23 77 97 "
            "e6 12 56 c7 05 7d 09 b1 4c ac a7 92 e8 93 9d 15"
        )
        master_secret = self.f_bytearray(
            "63 bf b9 25 11 9b 3e d3 ba db 75 58 60 5d 37 55 "
            "a3 59 7f d3 77 1c 45 0e b3 74 c1 4d 0c 0b 67 25 "
            "ef 85 17 ec 01 24 15 ef 5f 50 72 5c a9 5d 00 36"
        )

        res = tls_helper.prf("sha256", pre_master_secret, label, seed, 48)

        self.assertEqual(master_secret, res)

    def test_generate_mbed_ext_master_secret(self):
        label = b"extended master secret"
        pre_master_secret = self.f_bytearray(
            "18 26 f8 69 1b 58 4a d9 4b 83 f7 da b7 1b 76 2f 36 bb 86 4d fa 0f 81 8a 8a bc 0b db 6f b5 43 a1")
        seed = self.f_bytearray(
            "ab dc f0 2a f3 b1 bd 41 9a 2d a5 d9 5c 55 81 29 40 ef bc bb ea 98 20 3f 4b 13 8c 6d 7d 77 0f 7a")

        a0 = "254 191"
        a1 = "46 123"

        master_secret = self.f_bytearray(
            "f9 c6 86 f6 69 6d 72 18 25 74 9e b1 f4 03 6a 4d "
            "b7 74 1f db b1 2f f9 b4 d3 0c 25 73 ef 39 92 2f "
            "05 ee 3e 69 a9 a1 ea 18 d5 9f 05 d9 82 f8 ce 51"
        )

        res = tls_helper.prf("sha256", pre_master_secret, label, seed, 48)

        self.assertEqual(master_secret, res)

    def test_hash(self):
        print(tls.HandshakeType(1).name)
    #     from cryptography.hazmat.primitives import hashes
    #     hash_func = hashes.Hash(hashes.SHA256())
    #     hash_func.update(b'1')
    #     hash_func2 = hash_func.copy()
    #     b = hash_func2.finalize()
    #     hash_func.update(b'2')
    #     a = hash_func.finalize()
    #     hash_func = hashes.Hash(hashes.SHA256(), ctx=b)
    #     hash_func.update(b'2')
    #     c = hash_func.finalize()
    #     pass
