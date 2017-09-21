import json
import ctypes
import base58
import base64
from ctypes import *


so = cdll.LoadLibrary('./cryptoconditions.so')
so.jsonRPC.restype = c_char_p


def _read_vectors(name):
    path = 'ext/crypto-conditions/test-vectors/valid/%s.json' % name
    return json.load(open(path))


def jsonRPC(method, params):
    return so.jsonRPC(json.dumps({
        'method': method,
        'params': params,
    }))


def test_ed25519():
    vectors = _read_vectors('0004_test-minimal-ed25519')
    pk = decode_base64(vectors['json']['publicKey'].encode())
    uri = jsonRPC('makeEd25519Condition', {
        'public_key': base58.b58encode(pk)
    })
    assert uri == vectors['conditionUri']


def decode_base64(data):
    """Decode base64, padding being optional.

    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.

    """
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data)
