
#include "asn/Condition.h"
#include "asn/Fulfillment.h"
#include "asn/PrefixFingerprintContents.h"
#include "asn/OCTET_STRING.h"
#include "include/cJSON.h"
#include "cryptoconditions.h"


struct CCType cc_anonType;


static void mkAnon(Condition_t *asnCond, CC *cond) {
    CCType *realType = getTypeByAsnEnum(asnCond->present);
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
}


static int anonVerify(CC *cond, char *msg, size_t length) {
    // TODO: log
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


static void anonFree(CC *cond) {
    free(cond->type);
    free(cond);
}


struct CCType cc_anonType = { -1, "anon  (a buffer large enough to accomodate any type name)", Condition_PR_NOTHING, 0, &anonVerify, &anonFingerprint, &anonCost, &anonSubtypes, NULL, NULL, &anonFree };
