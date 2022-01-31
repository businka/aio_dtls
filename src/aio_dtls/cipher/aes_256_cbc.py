from .aes_128_cbc import Aes128Cbc


class Aes256Cbc(Aes128Cbc):
    key_material = 32
