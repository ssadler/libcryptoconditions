import json
import base64
import hashlib
from .test_vectors import jsonRPC




def test_decode_mixed_mode():

    ffill = "a23ba00aa003800102af038001eba12da22b80201f5fdee5c76b3ed83d6c683eded5999de53cd500d311d5a9908dbd46a24d02a8810302040082020204"

    r = jsonRPC('decodeFulfillmentMixed', {
        "fulfillment": ffill
    })

    assert r == {'type': 'threshold-sha-256', 'threshold': 2, 'subfulfillments': [{'type': 'eval-sha-256', 'code': '6w'}, {'type': '(anon)', 'fingerprint': 'H1_e5cdrPtg9bGg-3tWZneU81QDTEdWpkI29RqJNAqg', 'cost': 132096, 'subtypes': 32}]}

