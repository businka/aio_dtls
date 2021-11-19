from ..const import tls


class ECPointFormats:
    def __init__(self, ec_point_formats=None):
        pass

    @property
    def max(self):
        return {"ec_point_format_list": [
            tls.ECPointFormat.uncompressed.value
        ]}
