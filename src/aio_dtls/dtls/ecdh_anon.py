from cryptography.hazmat.primitives.asymmetric import ec as elliptic_curves


def generate_ecdh_key(_ec):
    # Generate a private key for use in the exchange.
    ec_name = _ec.name.upper()
    try:
        elliptic_curve = getattr(elliptic_curves, ec_name)
    except AttributeError:
        raise Exception(f'ec {ec_name} not supported')
        pass

    private_key = elliptic_curves.generate_private_key(
        elliptic_curve()
    )
    return private_key
