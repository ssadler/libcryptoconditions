import json
import ctypes
import base64
from ctypes import *


so = cdll.LoadLibrary('.libs/libcryptoconditions.so')
so.jsonRPC.restype = c_char_p


def _read_vectors(name):
    path = 'ext/crypto-conditions/test-vectors/valid/%s.json' % name
    return json.load(open(path))


def jsonRPC(method, params):
    out = so.jsonRPC(json.dumps({
        'method': method,
        'params': params,
    }))
    print repr(out)
    return json.loads(out)


def test_ed25519_make_condition():
    vectors = _read_vectors('0004_test-minimal-ed25519')
    response = jsonRPC('makeCondition', {
        'public_key': vectors['json']['publicKey']
    })
    assert response == {'uri': vectors['conditionUri']}


def test_ed25519_decode_fulfillment():
    vectors = _read_vectors('0004_test-minimal-ed25519')
    response = jsonRPC('decodeFulfillment', {
        'fulfillment': base64.b64encode(base64.b16decode(vectors['fulfillment'])),
    })
    assert response == {'uri': vectors['conditionUri']}


def test_ed25519_verify():
    vectors = _read_vectors('0004_test-minimal-ed25519')
    req = {
        'fulfillment': base64.b64encode(base64.b16decode(vectors['fulfillment'])),
        'message': '',
        'uri': vectors['conditionUri'],
    }
    assert jsonRPC('verifyFulfillment', req) == {'valid': True}
    req['message'] = 'a'
    assert jsonRPC('verifyFulfillment', req) == {'valid': False}


def test_preimage():
    vectors = _read_vectors('0000_test-minimal-preimage')
    response = jsonRPC('makeCondition', {
        'preimage': '',
    })
    assert response == {'uri': vectors['conditionUri']}


def test_threshold():
    vectors = _read_vectors('0002_test-minimal-threshold')
    response = jsonRPC('makeCondition', {
        'preimage': '',
    })
    assert response == {'uri': vectors['conditionUri']}


def decode_base64(data):
    """Decode base64, padding being optional.

    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.

    """
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data)
