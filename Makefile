
asn1:
	rm -rf include/
	mkdir include
	cd include && asn1c ../ext/crypto-conditions/src/asn1/CryptoConditions.asn
	rm include/converter-sample.c

build:
	gcc -o test -I include/ cryptoconditions.c include/*.c
