
build:
	gcc -fPIC -shared -g -o cryptoconditions.so -Iinclude/ -Isrc/models src/models/*.c include/*.c src/utils.c cryptoconditions.c -lsodium

asn1:
	rm -rf src/models
	mkdir -p src/models
	cd src/models && asn1c ../../ext/crypto-conditions/src/asn1/CryptoConditions.asn
	rm src/models/converter-sample.c

build-test:
	virtualenv .env
	.env/bin/pip install -r test-requirements.txt

test:
	pytest -s -x test.py
