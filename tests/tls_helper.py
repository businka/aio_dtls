import unittest
from tests.tls_test_obj import DemoTlsSocket, DemoConnectionManager
from aio_dtls.tls.protocol import TLSProtocol
from aio_dtls.constructs import tls


#     RawDatagram, Datagram


class TlsHelper(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self) -> None:
        self.client_address = ('192.168.1.18', 20102)
        self.server_address = ('192.168.1.13', 20103)
        self.ciphers = self.ciphers if self.ciphers else [
            'TLS_ECDHE_ECDSA_WITH_AES_128_CCM',
            'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
            'TLS_ECDH_anon_WITH_AES_128_CBC_SHA256',
        ]
        self.server_connection_manager = DemoConnectionManager(
            ciphers=self.ciphers
        )
        self.client_connection_manager = DemoConnectionManager(
            ciphers=self.ciphers
        )
        self.server_protocol = TLSProtocol(None, self.server_connection_manager, None, None)
        self.server = DemoTlsSocket(
            connection_manager=self.server_connection_manager,
            protocol=self.server_protocol
        )
        await self.server.connect(self.client_address)
        # self.server.listen(None, DemoProtocolClass, self.server_address[0], self.server_address[1])

        self.client_protocol = TLSProtocol(None, self.client_connection_manager, None, None)
        self.client = DemoTlsSocket(
            connection_manager=self.client_connection_manager,
            protocol=self.client_protocol
        )
        await self.client.connect(self.server_address)

    def check_request(self, request, trust_answer):
        return self.check(self.server, request, trust_answer, self.client_address)

    def check_answer(self, request, trust_answer):
        return self.check(self.client, request, trust_answer, self.server_address)

    def check(self, socket: DemoTlsSocket, request: bytes, trust_answer: bytes, address: tuple):
        request_data = tls.Datagram.parse(request)
        _size_before = len(socket._writer.send_data)

        socket.protocol.data_received(request)
        _size_after = len(socket._writer.send_data)
        answer = socket._writer.send_data[-1]
        answer_data = tls.Datagram.parse(answer)
        trust_answer_data = tls.Datagram.parse(trust_answer)
        self.assertEqual(len(trust_answer_data), len(answer_data), f'count answer record {request_data[0].type} {request_data[0].fragment.handshake_type}')
        self.assertEqual(trust_answer, answer, f'{request_data[0].type} {request_data[0].fragment.handshake_type}')
        return answer
