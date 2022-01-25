import logging
from enum import Enum
from typing import Tuple

from cryptography.hazmat.primitives import hashes

from ..const.cipher_suites import MACAlgorithm
from ..const.tls import NamedCurve, CompressionMethod, ConnectionEnd, PRFAlgorithm, BulkCipherAlgorithm

logger = logging.getLogger(__name__)


# from ..const.handshake import M


class TLSConnectionState(Enum):
    PENDING_READ = 10
    PENDING_WRITE = 20
    CURRENT_READ = 30
    CURRENT_WRITE = 40


class HandshakeParams:
    """
    session identifier
      Произвольная последовательность байтов, выбираемая сервером для идентификации
      активного или возобновляемого состояния сеанса.

    peer certificate
      X509v3 [PKIX] сертификат партнера. Этот элемент состояния может быть нулевым.

    compression method
      Алгоритм, используемый для сжатия данных перед шифрованием.

    cipher spec
      Задает псевдослучайную функцию (PRF), используемую для генерации ключевого
      материала, алгоритм шифрования данных (например, null, AES и т. Д.) И алгоритм
      MAC (например, HMAC-SHA1). Он также определяет криптографические атрибуты, такие
      как mac_length. (См. Формальное определение в Приложении A.6.)

    master secret
      48-байтовый секрет, совместно используемый клиентом и сервером.

    is resumable
      Флаг, указывающий, можно ли использовать сеанс для инициирования новых подключений.
    """

    def __init__(self):
        self.session_identifier = None
        self.peer_certificate = None
        self.compression_method = None
        self.cipher_spec = None
        self.master_secret = None
        self.is_resumable = None
        self.extended_master_secret = True  # rfc 7627
        self.handshake_messages = []
        self.handshake_hash = b''

    @property
    def full_handshake_messages(self):
        return b''.join(self.handshake_messages)


class SecurityParameters:

    def __init__(self):
        self.entity: ConnectionEnd(None) = None
        self.prf_algorithm: PRFAlgorithm(None) = None
        self.bulk_cipher_algorithm: BulkCipherAlgorithm(None) = None
        self.enc_key_length: int = 0
        self.block_length: int = 0
        self.fixed_iv_length: int = 0
        self.mac_algorithm: MACAlgorithm(None) = None
        self.mac_key_length: int = 0
        self.compression_algorithm: CompressionMethod = CompressionMethod.NULL
        self.master_secret: bytes = b''
        self.client_random: bytes = b''
        self.server_random: bytes = b''
        self.cipher = None

    @property
    def cipher_type(self):
        return self.cipher.cipher_type

    @property
    def record_iv_length(self):
        return self.cipher.cipher.iv_size

    @property
    def mac_length(self):
        return self.cipher.mac.mac_length


class ConnectionState:
    '''

    '''

    def __init__(self):
        self.compression_state = None
        self.cipher_state = None
        self.MAC_key = None
        self.sequence_number = {}
        self.value = None


class Connection:
    def __init__(self, address: Tuple[str, int], **kwargs):
        self.user_props = kwargs
        self.security_params: SecurityParameters = SecurityParameters()
        self.state: ConnectionState = ConnectionState()
        self.handshake_params: HandshakeParams = HandshakeParams()

        self.premaster_secret = None

        self.client_write_MAC_key = None
        self.server_write_MAC_key = None
        self.client_write_encryption_key = None
        self.server_write_encryption_key = None
        self.client_write_iv = None
        self.server_write_iv = None

        self.client_mac_func = None
        self.client_cipher_func = None

        self.client_mac_func = None
        self.server_mac_func = None
        self.client_cipher_func = None
        self.server_cipher_func = None
        self.client_fixed_nonce = None
        self.server_fixed_nonce = None

        self.fixed_iv_block = None

        self.address = address

        self.mac = None
        self.cookie = None
        self.uid = None
        self.queue_request = {}
        self.begin = None
        self.ec: NamedCurve(None) = None  # Elliptic Curve Cryptography rfc-4492
        self.ec_point_format = None

        self.server_private_key = None
        self.server_public_key = None
        #
        self.client_private_key = None
        self.client_public_key = None

        self.ssl_version = None

        self.next_receive_seq = 0
        self.next_receive_epoch = 0
        self.message_seq = 0
        self.epoch = 0

        self.flight_buffer = []

    @property
    def id(self):
        return self.get_id(self.address)

    @staticmethod
    def get_id(address):
        return f'{address[0]}:{address[1]}'

    def __bool__(self):
        return self.security_params.entity is not None

    @property
    def cipher(self):
        return self.security_params.cipher

    @cipher.setter
    def cipher(self, value):
        self.security_params.cipher = value

    @property
    def hash_func(self):
        if not self.cipher:
            return None
        if self.cipher.mac.hash_func.digest_size < 32:
            return hashes.SHA256
        return self.cipher.mac.hash_func

    @property
    def digestmod(self) -> str:
        if not self.cipher:
            return ''
        if self.cipher.mac.hash_func.digest_size < 32:
            return hashes.SHA256.name
        return self.cipher.mac.hash_func.name

    def update_handshake_hash(self, message, *, clear=False, name=''):
        # if self.cipher:
        #     hash_func = self.hash_func
        #     if not self.handshake_params.handshake_hash:
        #         digest = hashes.Hash(hash_func())
        #         for msg in self.handshake_params.handshake_messages:
        #             digest.update(msg)
        #         self.handshake_params.handshake_hash = digest.finalize()
        if clear:
            self.handshake_params.handshake_messages = []
            logger.debug(f'clear handshake hash')
        logger.debug(f'update handshake {name} buf ({len(message)}) {message.hex(" ")}')
        self.handshake_params.handshake_messages.append(message)

        hash_func = hashes.SHA256  # self.hash_func
        if hash_func:
            # if not self.handshake_params.handshake_hash:
            digest = hashes.Hash(hash_func())
            for msg in self.handshake_params.handshake_messages:
                digest.update(msg)
            _hash = digest.finalize()
            self.handshake_params.handshake_hash = _hash
            logger.debug(
                f'update handshake {name} hash {len(self.handshake_params.handshake_messages)}({len(_hash)}) {_hash.hex(" ")}')

    def get_sequence_number(self, epoch=None):
        epoch = str(self.epoch) if epoch is None else str(epoch)
        if epoch not in self.state.sequence_number:
            self.state.sequence_number[epoch] = 0
        number = self.state.sequence_number[epoch]
        self.state.sequence_number[epoch] += 1
        return number

    @property
    def sequence_number(self):
        epoch = str(self.epoch)
        if epoch not in self.state.sequence_number:
            self.state.sequence_number[epoch] = 0
        return self.state.sequence_number[epoch]

    @sequence_number.setter
    def sequence_number(self, value):
        self.state.sequence_number[str(self.epoch)] = value
