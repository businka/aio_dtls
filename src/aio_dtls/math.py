import hmac
import logging

from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)


def p_hash(hash_function, secret, seed, length):
    """Internal method for calculation the PRF in TLS."""

    ret = bytearray(length)
    a = seed
    index = 0
    mac = hmac.new(secret, digestmod=hash_function)
    while index < length:
        a_fun = mac.copy()
        a_fun.update(a)
        a = a_fun.digest()
        out_fun = mac.copy()
        out_fun.update(a)
        out_fun.update(seed)
        output = out_fun.digest()

        how_many = min(length - index, len(output))
        ret[index:index + how_many] = output[:how_many]
        index += how_many
    return ret


def prf(hash_function: str, secret: bytes, label: bytes, seed: bytes, length: int):
    return p_hash(hash_function, secret, label + seed, length)


def create_hmac(k, hash_function="sha1"):
    hash_alg = getattr(hashes, hash_function.upper())()
    h = hmac.HMAC(k, digestmod=hash_function)
    if not hasattr(h, 'block_size'):
        h.block_size = hash_alg.block_size
    assert h.block_size == hash_alg.block_size
    return h


def build_mac(mac_func, seq_num, content_type: int, ssl_version: int, fragment: bytes):
    logger.debug(f'build mac {seq_num} {content_type:x} {ssl_version:x} {fragment.hex(" ")}')
    fragment_len = len(fragment)
    _mac_func = mac_func.copy()
    _mac_func.update(seq_num)
    _mac_func.update(bytearray([content_type]))
    _mac_func.update(bytearray([ssl_version // 256]))
    _mac_func.update(bytearray([ssl_version % 256]))
    _mac_func.update(bytearray([fragment_len // 256]))
    _mac_func.update(bytearray([fragment_len % 256]))
    _mac_func.update(fragment)
    return bytearray(_mac_func.digest())
    pass
