from construct import Prefixed, GreedyBytes, Default, Struct, Int8ub, Int16ub, Enum, Switch, this, Peek

from ..const import tls

ServerDHParams = Struct(
    dh_p=Prefixed(Int16ub, GreedyBytes),
    dh_g=Prefixed(Int16ub, GreedyBytes),
    dh_Ys=Prefixed(Int16ub, GreedyBytes),
)

ServerKeyExchangeDHAnon = Struct(
    param=ServerDHParams
)

ExplicitPrime = Struct()
ExplicitChar2 = Struct()

NamedCurve = Struct(
    curve_type=Enum(Int8ub, tls.ECCurveType),
    namedcurve=Enum(Int16ub, tls.NamedCurve)
)

ECPoint = Struct(
    point=Prefixed(Int8ub, GreedyBytes)  # GreedyRange(Int8ub))
)

ServerECDHParams = Struct(
    curve_type=Peek(Enum(Int8ub, tls.ECCurveType)),
    curve_params=Switch(lambda ctx: int(ctx.curve_type), {
        tls.ECCurveType.named_curve.value: NamedCurve,
        tls.ECCurveType.explicit_prime.value: ExplicitPrime,
        tls.ECCurveType.explicit_char2.value: ExplicitChar2
    }),
    public=ECPoint
)

ServerKeyExchangeECDH = Struct(
    param=ServerECDHParams,
    signed_params=Default(GreedyBytes, b'')
)

ServerKeyExchangeECDHPSK = Struct(
    psk_identity_hint=Prefixed(Int16ub, GreedyBytes),  # rfc4279
    param=ServerECDHParams
)

ServerKeyExchange = Switch(this._params.key_exchange_algorithm, {
    'ec_diffie_hellman': ServerKeyExchangeECDH,
    'ec_diffie_hellman_psk': ServerKeyExchangeECDHPSK
}, default=GreedyBytes)

ClientDiffieHellmanPublic = Struct(
    dh_public=Struct(
        dh_Yc=Prefixed(Int8ub, GreedyBytes)
    )
)

ClientKeyExchangeECDH = Struct(
    exchange_keys=ClientDiffieHellmanPublic,
)

ClientKeyExchangeECDHPSK = Struct(
    psk_identity=Struct(
        dh_public_Yc=Prefixed(Int16ub, GreedyBytes),
        psk=Prefixed(Int16ub, GreedyBytes)
    )
)

ClientKeyExchange = Switch(this._params.key_exchange_algorithm, {
    'ec_diffie_hellman': ClientKeyExchangeECDH,
    'ec_diffie_hellman_psk': ClientKeyExchangeECDHPSK
}, default=GreedyBytes)
