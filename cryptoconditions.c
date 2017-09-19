
#include "include/Fulfillment.h"
#include "include/Ed25519Sha512Fulfillment.h"
#include "include/OCTET_STRING.h"
#include "include/tweetnacl.h"


/*
 * This guy is for tweetnacl
 */
void randombytes(unsigned char *bytes, unsigned long long num) {
    bytes = malloc(num); // TODO
}

int makeEd25519Condition(Fulfillment_t *ffill, char *public_key) {
    Ed25519Sha512Fulfillment_t *ed25519 = malloc(sizeof(Ed25519Sha512Fulfillment_t));
    OCTET_STRING_t *pk = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, public_key, -1);
    if (pk == NULL) {
        return 1;
    }
    ed25519->publicKey = *pk;
    return 0;
}

