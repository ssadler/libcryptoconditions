
#include "include/Fulfillment.h"
#include "include/OCTET_STRING.h"



int makeEd25519Condition(Fulfillment_t *ffill, char *public_key) {
    OCTET_STRING_t *ospk = OCTET_STRING_new_fromBuf(NULL, public_key, -1);
    return 0;
}




int main(int argc, char *argv) {
    PreimageFulfillment_t pf;
    return 0;
}


