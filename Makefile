
build:
	gcc -fPIC -shared -g -o cryptoconditions.so -Iinclude/ -Iinclude/models include/models/*.c include/*.c cryptoconditions.c -lsodium

asn1:
	rm -rf include/models
	mkdir -p include/models
	cd include/models && asn1c ../../ext/crypto-conditions/src/asn1/CryptoConditions.asn
	rm include/models/converter-sample.c

build-test:
	virtualenv .env
	.env/bin/pip install -r test-requirements.txt

test:
	pytest -s -x test.py
