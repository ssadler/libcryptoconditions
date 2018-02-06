import json
import base64
import ed25519
from test_vectors import jsonRPC


def test_sign_ed25519_pass():
    res = jsonRPC('signTreeEd25519', {
        'condition': {
            'type': 'ed25519-sha-256',
            'publicKey': "E0x0Ws4GhWhO_zBoUyaLbuqCz6hDdq11Ft1Dgbe9y9k",
        },
        'privateKey': '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        'message': '',
    })

    assert res == {
        "num_signed": 1,
        "condition": {
            "type": "ed25519-sha-256",
            "publicKey": "E0x0Ws4GhWhO_zBoUyaLbuqCz6hDdq11Ft1Dgbe9y9k",
            "signature": "jcuovSRpHwqiC781KzSM1Jd0Qtyfge0cMGttUdLOVdjJlSBFLTtgpinASOaJpd-VGjhSGWkp1hPWuMAAZq6pAg"
        }
    }


def test_sign_ed25519_fail():
    # privateKey doesnt match publicKey
    res = jsonRPC('signTreeEd25519', {
        'condition': {
            'type': 'ed25519-sha-256',
            'publicKey': "E0x0Ws4GhWhO_zBoUyaLbuqCz6hDdq11Ft1Dgbe9y9k",
        },
        'privateKey': '22qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        'message': '',
    })

    assert res == {
        "num_signed": 0,
        "condition": {
            "type": "ed25519-sha-256",
            "publicKey": "E0x0Ws4GhWhO_zBoUyaLbuqCz6hDdq11Ft1Dgbe9y9k",
        }
    }
