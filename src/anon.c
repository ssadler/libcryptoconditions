
#include "asn/Condition.h"
#include "asn/Fulfillment.h"
#include "asn/PrefixFingerprintContents.h"
#include "asn/OCTET_STRING.h"
#include "include/cJSON.h"
#include "cryptoconditions.h"


struct CCType cc_anonType;


static CC *mkAnon(Condition_t *asnCond) {
    CCType *realType = getTypeByAsnEnum(asnCond->present);
    if (!realType) {
        printf("Unknown ASN type: %i", asnCond->present);
        return 0;
    }
    CC *cond = calloc(1, sizeof(CC));
    cond->type = (CCType*) calloc(1, sizeof(CCType));
    *cond->type = cc_anonType;
    strcpy(cond->type->name, realType->name);
    cond->type->hasSubtypes = realType->hasSubtypes;
    cond->type->typeId = realType->typeId;
    cond->type->asnType = realType->asnType;
    CompoundSha256Condition_t *deets =& asnCond->choice.thresholdSha256;
    memcpy(cond->fingerprint, deets->fingerprint.buf, 32);
    cond->cost = deets->cost;
    if (realType->hasSubtypes) {
        cond->subtypes = fromAsnSubtypes(deets->subtypes);
    }
    return cond;
}


static int anonVerify(CC *cond, char *msg, size_t length) {
    return 0;
}


static char *anonFingerprint(CC *cond) {
    char *out = calloc(1, 32);
    memcpy(out, cond->fingerprint, 32);
    return out;
}


static unsigned long anonCost(CC *cond) {
    return cond->cost;
}


static uint32_t anonSubtypes(CC *cond) {
    return cond->subtypes;
}


static Fulfillment_t *anonFulfillment(CC *cond) {
    return NULL;
}


static void anonFree(CC *cond) {
    free(cond->type);
    free(cond);
}


static int anonIsFulfilled(CC *cond) {
    return 0;
}


struct CCType cc_anonType = { -1, "anon  (a buffer large enough to accomodate any type name)", Condition_PR_NOTHING, 0, NULL, &anonFingerprint, &anonCost, &anonSubtypes, NULL, NULL, NULL, &anonFulfillment, &anonIsFulfilled, &anonFree };
