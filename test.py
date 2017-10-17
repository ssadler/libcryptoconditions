import json
import ctypes
import base64
import pytest
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
    return json.loads(out)


def b16_to_b64(b16):
    return base64.urlsafe_b64encode(base64.b16decode(b16)).rstrip('=')


v0000 = '0000_test-minimal-preimage'
v0001 = '0001_test-minimal-prefix'
v0002 = '0002_test-minimal-threshold'
v0004 = '0004_test-minimal-ed25519'
v0017 = '0017_test-advanced-notarized-receipt-multiple-notaries'

all_vectors = {v0000, v0001, v0002, v0004, v0017}


@pytest.mark.parametrize('vectors_file', all_vectors)
def test_condition(vectors_file):
    vectors = _read_vectors(vectors_file)
    response = jsonRPC('makeCondition', vectors['json'])
    assert response == {
        'uri': vectors['conditionUri'],
        'bin': b16_to_b64(vectors['conditionBinary']),
    }


@pytest.mark.parametrize('vectors_file', all_vectors)
def test_verify_passes(vectors_file):
    vectors = _read_vectors(vectors_file)
    req = {
        'fulfillment': base64.b64encode(base64.b16decode(vectors['fulfillment'])),
        'message': '',
        'uri': vectors['conditionUri'],
    }
    assert jsonRPC('verifyFulfillment', req) == {'valid': True}


@pytest.mark.parametrize('vectors_file', [v0004, v0017])
def test_verify_fails(vectors_file):
    vectors = _read_vectors(vectors_file)
    req = {
        'fulfillment': base64.b64encode(base64.b16decode(vectors['fulfillment'])),
        'message': 'bla',
        'uri': vectors['conditionUri'],
    }
    assert jsonRPC('verifyFulfillment', req) == {'valid': False}


@pytest.mark.parametrize('vectors_file', all_vectors)
def test_decode_fulfillment(vectors_file):
    vectors = _read_vectors(vectors_file)
    response = jsonRPC('decodeFulfillment', {
        'fulfillment': base64.b64encode(base64.b16decode(vectors['fulfillment'])),
    })
    assert response == {
        'uri': vectors['conditionUri'],
        'bin': b16_to_b64(vectors['conditionBinary']),
    }


@pytest.mark.parametrize('vectors_file', all_vectors)
def test_decode_condition(vectors_file):
    vectors = _read_vectors(vectors_file)
    response = jsonRPC('decodeCondition', {
        'bin': b16_to_b64(vectors['conditionBinary']),
    })
    assert response['uri'] == vectors['conditionUri']


def decode_base64(data):
    """Decode base64, padding being optional.

    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.

    """
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data)
