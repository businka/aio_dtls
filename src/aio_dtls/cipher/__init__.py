from .aes_128_cbc import Aes128Cbc
from .aes_256_cbc import Aes256Cbc

cipher = {
    "NULL": None,
    "RC4_128": None,
    "AES_128_CBC": Aes128Cbc,
    "AES_256_CBC": Aes256Cbc,
    "3DES_EDE_CBC": None
}
