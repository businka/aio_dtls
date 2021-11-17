from __future__ import absolute_import, division, print_function

# from construct.adapters import ValidationError

# from construct.core import FieldError

import pytest

from dtls import enums

from dtls.record import (ProtocolVersion, TLSPlaintext)  # TLSCiphertext, TLSCompressed,


class TestDTLSPlaintextParsing(object):
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
        packet = b'\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x02\x00b\x01\x00\x00V\x00\x00\x00\x00\x00\x00\x00V\xfe\xfd`\xc6_,\xdc\x0b&\xcf1L\x98\x15%\xcc\xd6\xf5\xba\xb4\xb5\x93\xd39\rk\xfb\x16l\xf0\xdd\xd9,a\x00\x00\x00\x04\xff\x00\x00\xff\x01\x00\x00(\x00\r\x00\x12\x00\x10\x06\x03\x06\x01\x05\x03\x05\x01\x04\x03\x04\x01\x03\x03\x03\x01\x00\n\x00\x04\x00\x02\x00\x17\x00\x0b\x00\x02\x01\x00\x00\x17\x00\x00'
        record = TLSPlaintext.from_bytes(packet)
        assert record.type == enums.ContentType.HANDSHAKE
        assert record.version.major == 254
        assert record.version.minor == 253
        assert record.epoch == 0
        assert record.sequence_number == 0
        assert record.fragment == b'0123456789'
