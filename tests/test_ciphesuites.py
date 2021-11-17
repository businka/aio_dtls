import unittest
from aio_dtls.const.cipher_suites import CipherSuites


class TestCipherSuites(unittest.TestCase):
    def test_init(self):
        for cipher in CipherSuites:
            if cipher.value.cipher:
                # if cipher.value.cipher.mac_algorithm:
                # self.assertIsNotNone(cipher.primitive, 'primitive')
                # self.assertIsNotNone(cipher.hash_function, 'hash_function')
                self.assertIsNotNone(cipher.cipher.iv_size, 'iv_size')
                self.assertIsNotNone(cipher.mac.mac_length, 'mac_length')
            # self.assertIsNotNone(cipher.key_length, 'key_length')

            a = 1