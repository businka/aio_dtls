from construct import Prefixed, GreedyBytes, Default, Pointer
from construct import Struct, Int8ub, Int16ub, Enum, Switch

from ..const import tls

ServerDHParams = Struct(
    "dh_p" / Prefixed(Int16ub, GreedyBytes),
    "dh_g" / Prefixed(Int16ub, GreedyBytes),
    "dh_Ys" / Prefixed(Int16ub, GreedyBytes),
)

ServerKeyExchangeDHAnon = Struct(
    "param" / ServerDHParams
)

ECParametersExplicitPrime = Struct()
ECParametersExplicitChar2 = Struct()
ECParametersNamedCurve = Struct(
    "curve_type" / Enum(Int8ub, tls.ECCurveType),
    "namedcurve" / Enum(Int16ub, tls.NamedCurve)
)

ECParameters = Struct(
    "curve_type" / Enum(Int8ub, tls.ECCurveType),
    Switch(lambda ctx: int(ctx.curve_type), {
        tls.ECCurveType.explicit_prime: ECParametersExplicitPrime,
        tls.ECCurveType.explicit_char2: ECParametersExplicitChar2,
        tls.ECCurveType.named_curve.value: ECParametersNamedCurve
    })
)

ECPoint = Struct(
    "point" / Prefixed(Int8ub, GreedyBytes)  # GreedyRange(Int8ub))
)

ServerECDHParams = Struct(

    "curve_type" / Pointer(0, Enum(Int8ub, tls.ECCurveType)),
    "curve_params" / Switch(lambda ctx: int(ctx.curve_type), {
        tls.ECCurveType.explicit_prime.value: ECParametersExplicitPrime,
        tls.ECCurveType.explicit_char2.value: ECParametersExplicitChar2,
        tls.ECCurveType.named_curve.value: ECParametersNamedCurve
    }),
    "public" / ECPoint
)

ServerKeyExchangeECDH = Struct(
    "param" / ServerECDHParams,
    "signed_params" / Default(GreedyBytes, b'')
)

ClientDiffieHellmanPublic = Struct(
    "dh_public" / Struct(
        "dh_Yc" / Prefixed(Int8ub, GreedyBytes)
    )
)

ClientKeyExchange = Struct(
    "exchange_keys" / ClientDiffieHellmanPublic,
)
