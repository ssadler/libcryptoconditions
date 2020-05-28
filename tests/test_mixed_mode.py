import json
import base64
import hashlib
from .test_vectors import jsonRPC


def test_reencode_mixed():
    preimage_ffill = {'type': 'preimage-sha-256', 'preimage': ''}
    preimage_cond = jsonRPC('decodeCondition', jsonRPC('encodeCondition', preimage_ffill))['condition']

    cc = {
        'type': 'threshold-sha-256',
        'threshold': 2,
        'subfulfillments': [
            {'type': 'eval-sha-256', 'code': '6w'},
            preimage_ffill
        ]
    }

    ffill_bin = jsonRPC('encodeFulfillment', cc)
    ffill_bin_mixed = jsonRPC('encodeFulfillmentMixedMode', cc)

    decoded1 = jsonRPC('decodeFulfillment', ffill_bin)
    decoded2 = jsonRPC('decodeFulfillmentMixedMode', ffill_bin_mixed)
    assert decoded1 == decoded2
