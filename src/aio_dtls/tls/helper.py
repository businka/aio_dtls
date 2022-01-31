import logging
import secrets
from typing import List

from cryptography.hazmat.primitives import hashes

from .. import math
from ..connection_manager.connection import Connection
from ..const import tls as const_tls
from ..constructs import tls

logger = logging.getLogger(__name__)


class Helper:
    @classmethod
    def build_plaintext(cls, connection: Connection, records_data: List[tls.AnswerRecord]):
        records = []
        for record in records_data:
            records.append({
                "type": record.content_type,
                "version": connection.ssl_version.value,
                "fragment": record.fragment
            })
        plaintext = tls.RawDatagram.build(records)
        return plaintext

    @classmethod
    def encrypt_ciphertext_fragment(cls, connection: Connection, content_type: const_tls.ContentType, fragment: bytes):
        logger.debug(f'encrypted fragment {fragment.hex(" ")}')
        is_client = connection.security_params.entity == const_tls.ConnectionEnd.client

        if is_client:
            mac_func = connection.client_mac_func
            cipher_func = connection.client_cipher_func
        else:
            mac_func = connection.server_mac_func
            cipher_func = connection.server_cipher_func

        data = bytearray(fragment)
        if mac_func:
            mac = cls.build_mac(connection, None, mac_func, content_type.value, fragment)
            logger.debug(f'mac {mac.hex(" ")}')
            data += mac
        if connection.cipher.is_block_cipher():
            if cipher_func:
                data = connection.fixed_iv_block + data
                data = cls.add_padding(connection, data)

                logger.debug(f'encrypted message {data.hex(" ")}')

                encryptor = cipher_func.encryptor()
                return encryptor.update(data) + encryptor.finalize()
        raise NotImplemented()  # todo надо разобраться что делать в этом случае

    @classmethod
    def decrypt_ciphertext_fragment(cls, connection: Connection, record) -> tls.CiphertextFragment:
        is_client = connection.security_params.entity == const_tls.ConnectionEnd.client

        if is_client:
            cipher_func = connection.server_cipher_func
            mac_func = connection.server_mac_func
        else:
            cipher_func = connection.client_cipher_func
            mac_func = connection.client_mac_func

        logger.debug(f'ecrypted data {record.fragment.hex(" ")}')

        decryptor = cipher_func.decryptor()
        data = decryptor.update(record.fragment) + decryptor.finalize()
        logger.debug(f'decrypted data {data.hex(" ")}')
        data_length = len(data)
        record_iv_length = connection.security_params.record_iv_length
        mac_length = connection.security_params.mac_length
        padding_length = data[-1]
        tls_compressed_length = data_length - record_iv_length - mac_length - 1 - padding_length
        cipher_text = tls.CiphertextFragment.parse(
            data,
            cipher_type=connection.security_params.cipher_type,
            record_iv_length=record_iv_length,
            mac_length=mac_length,
            tls_compressed_length=tls_compressed_length,
        )
        mac = cls.build_mac(
            connection, record, mac_func, int(record.type), cipher_text.block_ciphered.content)

        if cipher_text.block_ciphered.MAC != mac:
            logger.error('bad mac')
            logger.debug(f'mac {mac.hex(" ")}')
            logger.debug(f'incoming mac {cipher_text.block_ciphered.MAC.hex(" ")}')
            raise BadMAC()

        return cipher_text

    @classmethod
    def build_mac(cls, connection: Connection, record, mac_func, content_type: int, fragment: bytes):
        version = connection.ssl_version.value if record is None else int(record.version)
        return math.build_mac(mac_func, int(0).to_bytes(8, 'big'), content_type, version, fragment)

    @classmethod
    def build_handshake_answer(cls, connection: Connection, fragment: bytes):
        return tls.AnswerRecord(
            content_type=const_tls.ContentType.HANDSHAKE.value,
            fragment=fragment
        )

    @classmethod
    def build_handshake_fragment(cls, connection: Connection, handshake_type: const_tls.HandshakeType,
                                 handshake_fragment: bytes):
        fragment = tls.RawHandshake.build({
            "handshake_type": handshake_type.value,
            "fragment": handshake_fragment
        })
        return fragment

    @classmethod
    def build_handshake_record(cls, connection: Connection, handshake_type: const_tls.HandshakeType,
                               handshake_fragment: bytes,
                               clear_handshake_hash=False):
        fragment = cls.build_handshake_fragment(connection, handshake_type, handshake_fragment)

        connection.update_handshake_hash(fragment, name=handshake_type.name, clear=clear_handshake_hash)
        return cls.build_handshake_answer(connection, fragment)

    @classmethod
    def generate_finished_verify_data(cls, connection: Connection, label: bytes):
        seed = cls.get_seed_by_handshake_messages(connection)

        logger.debug(f'digestmod {connection.digestmod} label {label}')
        logger.debug(f'verify data seed {seed.hex(" ")}')
        return math.prf(
            connection.digestmod, connection.security_params.master_secret, label, seed, 12)

    @classmethod
    def generate_master_secret(cls, connection: Connection):
        if connection.handshake_params.extended_master_secret:
            seed = cls.get_seed_by_handshake_messages(connection)
            label = b"extended master secret"  # rfc7627
            logger.debug(
                f'generate extended master secret {connection.handshake_params.full_handshake_messages.hex(" ")}')
        else:
            seed = connection.security_params.client_random + connection.security_params.server_random
            label = b"master secret"
        logger.debug(f'premaster secret {connection.premaster_secret.hex(" ")}')
        logger.debug(f'digestmod {connection.digestmod} label {label}')
        logger.debug(f'seed {seed.hex(" ")}')

        master_secret = math.prf(connection.digestmod, connection.premaster_secret, label, seed, 48)
        logger.debug(f'master secret {master_secret.hex(" ")}')

        logger.error(f'master secret {bytes(master_secret)}')
        logger.error(f'client random {connection.security_params.client_random}')
        logger.error(f'server random {connection.security_params.server_random}')
        connection.premaster_secret = b''
        return master_secret

    @classmethod
    def generate_owner_psk(cls, connection: Connection, oxm, owner_subject_uuid, device_uuid):
        seed = connection.security_params.server_random + connection.security_params.client_random
        label = "key expansion".encode()
        logger.debug(f'master secret {connection.security_params.master_secret.hex(" ")}')
        logger.debug(f'digestmod {connection.digestmod} label {label}')
        logger.debug(f'seed {seed.hex(" ")}')

        key_block_len = 2 * (
                connection.cipher.mac.mac_length +
                connection.cipher.cipher.key_material +
                connection.cipher.cipher.iv_size_ocf
        )

        key_block = math.p_hash(
            connection.digestmod,
            connection.security_params.master_secret,
            label + connection.security_params.server_random + connection.security_params.client_random,
            key_block_len)  # todo не стандартно размер зависит от chipher

        seed = oxm + owner_subject_uuid + device_uuid
        logger.debug(f'master secret {connection.security_params.master_secret.hex(" ")}')
        logger.debug(f'digestmod {connection.digestmod} label {label}')
        logger.debug(f'seed {seed.hex(" ")}')

        psk = math.p_hash(connection.digestmod, key_block, seed, 16)

        logger.debug(f'PSK {psk.hex(" ")}')
        return psk

    @classmethod
    def get_seed_by_handshake_messages(cls, connection: Connection):
        digest = hashes.Hash(connection.hash_func())
        digest.update(connection.handshake_params.full_handshake_messages)
        seed = digest.finalize()
        return seed

    @classmethod
    def calc_pending_states(cls, connection):
        """Create pending states for encryption and decryption."""

        def _get_fixed_bytes(_key_block, length, begin):
            end = begin + length
            return _key_block[begin: end], end

        key_length = connection.cipher.cipher.key_material
        iv_length = connection.cipher.cipher.iv_size
        mac_length = connection.cipher.mac.mac_length
        digestmod = connection.cipher.mac.digestmod

        output_length = (mac_length * 2) + (key_length * 2) + (iv_length * 2)

        # Calculate Keying Material from Master Secret
        seed = connection.security_params.server_random + connection.security_params.client_random
        key_block = math.prf("sha256", connection.security_params.master_secret, b"key expansion", seed, output_length)
        logger.debug(f'server random: {connection.security_params.server_random.hex(" ")}')
        logger.debug(f'client random: {connection.security_params.client_random.hex(" ")}')
        logger.debug(f'key block ({len(key_block)}): {key_block.hex(" ")}')
        # key_block = bytearray(key_block)
        # Slice up Keying Material
        connection.client_write_MAC_key, i = _get_fixed_bytes(key_block, mac_length, 0)
        connection.server_write_MAC_key, i = _get_fixed_bytes(key_block, mac_length, i)
        connection.client_write_encryption_key, i = _get_fixed_bytes(key_block, key_length, i)
        connection.server_write_encryption_key, i = _get_fixed_bytes(key_block, key_length, i)
        connection.client_write_iv, i = _get_fixed_bytes(key_block, iv_length, i)
        connection.server_write_iv, i = _get_fixed_bytes(key_block, iv_length, i)

        if digestmod:
            #     # Legacy cipher
            logger.debug(f'client_write_MAC_key ({mac_length}) {connection.client_write_MAC_key.hex(" ")}')
            logger.debug(f'server_write_MAC_key ({mac_length}) {connection.server_write_MAC_key.hex(" ")}')
            logger.debug(
                f'client_write_encryption_key ({key_length}) {connection.client_write_encryption_key.hex(" ")}')
            logger.debug(
                f'server_write_encryption_key ({key_length}) {connection.server_write_encryption_key.hex(" ")}')
            logger.debug(f'client_write_iv ({iv_length}) {connection.client_write_iv.hex(" ")}')
            logger.debug(f'server_write_iv ({iv_length}) {connection.server_write_iv.hex(" ")}')

            connection.client_mac_func = math.create_hmac(connection.client_write_MAC_key, digestmod)
            connection.server_mac_func = math.create_hmac(connection.server_write_MAC_key, digestmod)
            if connection.cipher.cipher.is_cipher:
                connection.client_cipher_func = connection.cipher.get_cipher_func(
                    connection.client_write_encryption_key, connection.client_write_iv
                )
                connection.server_cipher_func = connection.cipher.get_cipher_func(
                    connection.server_write_encryption_key, connection.server_write_iv
                )

        else:
            # AEAD
            raise NotImplemented()
            # connection.client_mac_func = None
            # connection.server_mac_func = None
            # connection.client_cipher_func = create_mac_func(connection.client_write_encryption_key)
            # connection.server_cipher_func = create_mac_func(connection.server_write_encryption_key)
            # connection.client_fixed_nonce = connection.client_write_iv
            # connection.server_fixed_nonce = connection.server_write_iv

        connection.fixed_iv_block = secrets.token_bytes(connection.cipher.cipher.iv_size)

    # def mac_encrypt(connection: Connection, record):
    #     seq_num = connection.state.get_sequence_number()
    #     build_mac(connection, connection.client_mac_func, seq_num, record.content_type, record.fragment)
    #     pass

    @classmethod
    def build_cbc_block_cipher(cls, mac_):
        pass

    @classmethod
    def add_padding(cls, connection: Connection, data):
        """Add padding to data so that it is multiple of block size"""
        current_length = len(data)
        block_length = connection.cipher.cipher.block_size
        padding_length = block_length - 1 - (current_length % block_length)

        padding_bytes = bytearray([padding_length] * (padding_length + 1))
        data += padding_bytes
        return data

    @classmethod
    def build_alert(cls, connection: Connection, level: const_tls.AlertLevel, description: const_tls.AlertDescription):
        return tls.AnswerRecord(
            content_type=const_tls.ContentType.ALERT.value,
            fragment=tls.Alert.build({
                "level": level.value,
                "description": description.value

            })
        )

    @classmethod
    def extensions_to_dict(cls, extensions):
        data = {}
        for extension in extensions:
            name = str(extension.type)
            if name not in data:
                data[name] = [extension]
            else:
                data[name].append(extension)
        return data

    @classmethod
    def build_change_cipher(cls, connection: Connection):
        return tls.AnswerRecord(
            content_type=const_tls.ContentType.CHANGE_CIPHER_SPEC.value,
            fragment=b'\x01'
        )

    @classmethod
    def build_application_record(cls, connection: Connection, fragments):
        records = []
        logger.debug(f'prepare {len(fragments)} application data for send')
        for fragment in fragments:
            encrypted_data = cls.encrypt_ciphertext_fragment(
                connection, const_tls.ContentType.APPLICATION_DATA, fragment)
            records.append(tls.AnswerRecord(
                content_type=const_tls.ContentType.APPLICATION_DATA.value,
                fragment=encrypted_data
            ))
        return records

    @classmethod
    def send_records(cls, connection: Connection, answers, writer):
        plaintext = cls.build_plaintext(connection, answers)
        writer(plaintext)
