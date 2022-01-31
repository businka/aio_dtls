from typing import Optional


class Cipher:
    cipher_type: Optional[str] = None
    key_material: Optional[int] = None
    iv_size: Optional[int] = None
    iv_size_ocf: Optional[int] = None
    block_size: Optional[int] = None
    is_cipher = True
