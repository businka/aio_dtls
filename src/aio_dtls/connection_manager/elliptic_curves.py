import logging

from .enum_props import EnumProps
from ..const.tls import NamedCurve

logger = logging.getLogger(__name__)


class EllipticCurves(EnumProps):
    supported = [
        'secp256r1'
    ]
    EnumClass = NamedCurve
