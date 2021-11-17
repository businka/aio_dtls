from .aes_xxx_cbc import AesXxxCbc


class Aes256Cbc(AesXxxCbc):
    cipher_type = 'block'
    key_material = 32
    iv_size = 16
    block_size = 16
