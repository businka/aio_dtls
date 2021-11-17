from .aes_xxx_cbc import AesXxxCbc


class Aes128Cbc(AesXxxCbc):
    cipher_type = 'block'
    key_material = 16
    iv_size = 16
    block_size = 16
