import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .cipher import Cipher as _Cipher


class AesXxxCbc(_Cipher):
    cipher_type = 'block'
    key_material = 0
    iv_size = 0
    block_size = 0

    @classmethod
    def get_cipher_func(cls, key, iv):
        return Cipher(algorithms.AES(key), modes.CBC(iv))

    @classmethod
    def encrypt(cls, key, plaintext, associated_data):
        iv = os.urandom(12)

        # Construct an AES-GCM Cipher object with the given key and a
        # randomly generated IV.
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
        ).encryptor()

        # associated_data will be authenticated but not encrypted,
        # it must also be passed in on decryption.
        encryptor.authenticate_additional_data(associated_data)

        # Encrypt the plaintext and get the associated ciphertext.
        # GCM does not require padding.
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return (iv, ciphertext, encryptor.tag)
