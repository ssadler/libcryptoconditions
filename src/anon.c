
#include "asn/Condition.h"
#include "asn/Fulfillment.h"
#include "asn/PrefixFingerprintContents.h"
#include "asn/OCTET_STRING.h"
#include "include/cJSON.h"
#include "cryptoconditions.h"


void mkAnon(Condition_t *asnCond, CC *cond) {
    CCType realType =* getTypeByAsnEnum(asnCond->present);
    cond->type = (CCType*) malloc(sizeof(CCType));
    *cond->type = anonType;
    strcpy(cond->type->name, realType.name);
    cond->type->hasSubtypes = realType.hasSubtypes;
    cond->type->typeId = realType.typeId;
    cond->type->asnType = realType.asnType;
    SimpleSha256Condition_t *deets =& asnCond->choice.preimageSha256;
    memcpy(cond->fingerprint, deets->fingerprint.buf, 32);
    cond->cost = deets->cost;
    if (realType.hasSubtypes) {
        cond->subtypes = fromAsnSubtypes(((CompoundSha256Condition_t*) deets)->subtypes);
    }
}


int anonVerify(CC *cond, char *msg) {
    return 0;
}


char *anonFingerprint(CC *cond) {
    char *out = malloc(32);
    memcpy(out, cond->fingerprint, 32);
    return out;
}


unsigned long anonCost(CC *cond) {
    return cond->cost;
}


uint32_t anonSubtypes(CC *cond) {
    return cond->subtypes;
}


struct CCType anonType = { -1, "anon  (a buffer large enough to accomodate any type name)", Condition_PR_NOTHING, 0, &anonVerify, &anonFingerprint, &anonCost, &anonSubtypes, NULL, NULL };
