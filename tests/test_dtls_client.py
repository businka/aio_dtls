from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from aio_dtls import DtlsSocket
from tests.dtls_helper import DtlsHelper
from tests.data import iotivity_simple_server as iotivity_simple
from tests.dtls_test_obj import DemoServer, DemoProtocolClass, DemoDtlsEndpoint, DemoDtlsSocket
import unittest


class TestDtlsClient(DtlsHelper):
    def test_handshake(self):
        self.client_endpoint.sendto(b'hello world', self.server_address)
        client_hello_empty_cookie = self.client_endpoint._sock._sock.sending_data[-1][0]
        self.assertEqual(iotivity_simple.client_hello_empty_cookie, client_hello_empty_cookie)
        hello_verify_request = self.check_request(client_hello_empty_cookie, iotivity_simple.hello_verify_request)
        client_hello_with_cookie = self.check_answer(hello_verify_request, iotivity_simple.client_hello_with_cookie)
        server_hello = self.check_request(client_hello_with_cookie, iotivity_simple.server_hello)
        client_hello_with_cookie = self.check_answer(server_hello, iotivity_simple.client_change_cipher)
        pass