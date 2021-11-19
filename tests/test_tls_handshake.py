# from tests.demo_server import DemoServer, DemoEndpoint, DemoProtocolClass, ClientEndpoint
from aio_dtls.connection_manager.connection import Connection
from tests.data import tls_lite_ng as demo
from tests.tls_helper import TlsHelper


class TestTlsHandshake(TlsHelper):
    def setUp(self) -> None:
        self.ciphers = [
            'TLS_ECDHE_ECDSA_WITH_AES_128_CCM',
            'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
            'TLS_ECDH_anon_WITH_AES_128_CBC_SHA256',
        ]
        super(TestTlsHandshake, self).setUp()

    async def test_handshake(self):
        self.assertEqual(0, len(self.client.connection_manager.connections), 'count connections on client')
        self.assertEqual(0, len(self.server.connection_manager.connections), 'count connections on server')

        await self.client.send('hello')
        server_hello = self.check_request(demo.client_hello, demo.server_hello)

        self.assertEqual(1, len(self.server.connection_manager.connections), 'count connections on server')

        client_change_cipher = self.check_answer(server_hello, demo.client_change_cipher)

        self.assertEqual(1, len(self.client.connection_manager.connections), 'count connections on client')

        client_connection: Connection = self.client.connection_manager.get_connection(self.server_address)
        server_connection: Connection = self.server.connection_manager.get_connection(self.client_address)
        _random = self.client.connection_manager.generate_tls_random()
        self.assertEqual(_random, client_connection.client_random, 'client client.random')
        self.assertEqual(_random, client_connection.server_random, 'client server.random')
        self.assertEqual(_random, server_connection.client_random, 'server client.random')
        self.assertEqual(_random, server_connection.server_random, 'server server.random')

        self.check_request(client_change_cipher, iotivity.server_change_cipher)
