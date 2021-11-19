import unittest

from aio_dtls.constructs.dtls import Plaintext, Datagram
from tests.dtls_test_obj import DemoDtlsEndpoint, DemoProtocolClass


class DtlsHelper(unittest.TestCase):

    def setUp(self) -> None:
        self.client_address = ('192.168.1.18', 20102)
        self.server_address = ('192.168.1.13', 20103)

        self.server_endpoint = DemoDtlsEndpoint(address=self.server_address)
        self.client_endpoint = DemoDtlsEndpoint(address=self.client_address,
                                                ciphers=['TLS_ECDH_anon_WITH_AES_128_CBC_SHA256'])

        self.client_endpoint.listen(DemoProtocolClass)
        self.server_endpoint.listen(DemoProtocolClass)

        self.client_connection_manager = self.client_endpoint._sock.connection_manager
        self.server_connection_manager = self.server_endpoint._sock.connection_manager

    def check_request(self, request, trust_answer):
        return self.check(self.server_endpoint, request, trust_answer, self.client_address)

    def check_answer(self, request, trust_answer):
        return self.check(self.client_endpoint, request, trust_answer, self.server_address)

    def check(self, endpoint: DemoDtlsEndpoint, request: bytes, trust_answer: bytes, address: tuple):
        _request = Plaintext.parse(request)
        _size_before = len(endpoint._sock._sock.sending_data)
        endpoint._sock.protocol.datagram_received(request, address)
        _size_after = len(endpoint._sock._sock.sending_data)
        answer = endpoint._sock._sock.sending_data[-1][0]
        _answer1 = Datagram.parse(answer)
        _answer2 = Datagram.parse(trust_answer)
        self.assertEqual(trust_answer, answer, f'{_request.type} {_request.fragment.handshake_type}')
        return answer
