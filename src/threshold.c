
#include "asn/Condition.h"
#include "asn/Fulfillment.h"
#include "asn/ThresholdFingerprintContents.h"
#include "asn/OCTET_STRING.h"
#include "include/cJSON.h"
#include "cryptoconditions.h"



static uint32_t thresholdSubtypes(CC *cond) {
    uint32_t mask = 0;
    for (int i=0; i<cond->size; i++) {
        mask |= getSubtypes(cond->subconditions[i]);
    }
    mask &= ~(1 << cc_thresholdType.typeId);
    return mask;
}


static int cmpCost(const void *a, const void *b) {
    /* costs in descending order */
    return (int) ( *(unsigned long*)b - *(unsigned long*)a );
}


static unsigned long thresholdCost(CC *cond) {
    CC *sub;
    unsigned long *costs = malloc(cond->size * sizeof(unsigned long));
    for (int i=0; i<cond->size; i++) {
        sub = cond->subconditions[i];
        costs[i] = sub->type->getCost(sub);
    }
    qsort(costs, cond->size, sizeof(unsigned long), cmpCost);
    unsigned long cost = 0;
    for (int i=0; i<cond->threshold; i++) {
        cost += costs[i];
    }
    free(costs);
    return cost + 1024 * cond->size;
}


static int thresholdVerify(CC *cond, char *msg, size_t length) {
    int res;
    for (int i=0; i<cond->threshold; i++) {
        res = cc_verifyFulfillment(cond->subconditions[i], msg, length);
        if (!res) return 0;
    }
    return 1;
}


static int cmpConditions(const void *a, const void *b) {
    /* Compare conditions by their ASN binary representation */
    char bufa[BUF_SIZE], bufb[BUF_SIZE];
    asn_enc_rval_t r0 = der_encode_to_buffer(&asn_DEF_Condition, *(Condition_t**)a, bufa, BUF_SIZE);
    asn_enc_rval_t r1 = der_encode_to_buffer(&asn_DEF_Condition, *(Condition_t**)b, bufb, BUF_SIZE);
    int diff = r0.encoded - r1.encoded;
    return diff != 0 ? diff : strcmp(bufa, bufb);
}

//SAFE

static char *thresholdFingerprint(CC *cond) {
    Condition_t **subAsns = malloc(cond->size * sizeof(Condition_t*));

    /* Convert each CC into an ASN condition */
    Condition_t *asnCond;
    for (int i=0; i<cond->size; i++) {
        subAsns[i] = asnCondition(cond->subconditions[i]);
    }

    /* Sort conditions */
    qsort(subAsns, cond->size, sizeof(Condition_t*), cmpConditions);

    /* Create fingerprint */
    ThresholdFingerprintContents_t fp;
    fp.subconditions2.list.array = NULL;
    fp.subconditions2.list.free = 0;
    asn_set_empty(&fp.subconditions2.list);
    fp.threshold = cond->threshold;
    for (int i=0; i<cond->size; i++) {
        // TODO: Is there a bug here where the set is uninitialized?
        asn_set_add(&fp.subconditions2, subAsns[i]);
    }

    /* Encode and hash the result */
    char buf[BUF_SIZE];
    asn_enc_rval_t rc = der_encode_to_buffer(&asn_DEF_ThresholdFingerprintContents, &fp, buf, BUF_SIZE);
    assert(rc.encoded > 0);

    char *hash = malloc(32);
    crypto_hash_sha256(hash, buf, rc.encoded);

    //asn_DEF_OCTET_STRING.free_struct(&asn_DEF_OCTET_STRING, &(fp.publicKey), 0);
    free(subAsns);
    return hash;
}


static void thresholdFfillToCC(Fulfillment_t *ffill, CC *cond) {
    cond->type = &cc_thresholdType;
    ThresholdFulfillment_t *t = ffill->choice.thresholdSha256;
    cond->threshold = t->subfulfillments.list.count;
    cond->size = cond->threshold + t->subconditions.list.count;
    cond->subconditions = malloc(cond->size * sizeof(CC*));
    for (int i=0; i<cond->threshold; i++) {
        cond->subconditions[i] = malloc(sizeof(CC));
        ffillToCC(t->subfulfillments.list.array[i], cond->subconditions[i]);
    }
    for (int i=0; i<t->subconditions.list.count; i++) {
        cond->subconditions[i+cond->threshold] = malloc(sizeof(CC));
        mkAnon(t->subconditions.list.array[i], cond->subconditions[i+cond->threshold]);
    }
}



static CC *thresholdFromJSON(cJSON *params, char *err) {
    cJSON *threshold_item = cJSON_GetObjectItem(params, "threshold");
    if (!cJSON_IsNumber(threshold_item)) {
        strcpy(err, "threshold must be a number");
        return NULL;
    }

    cJSON *subfulfillments_item = cJSON_GetObjectItem(params, "subfulfillments");
    if (!cJSON_IsArray(subfulfillments_item)) {
        strcpy(err, "subfulfullments must be an array");
        return NULL;
    }

    CC *cond = malloc(sizeof(CC));
    cond->type = &cc_thresholdType;
    cond->threshold = (long)threshold_item->valuedouble;
    cond->size = cJSON_GetArraySize(subfulfillments_item);
    cond->subconditions = malloc(cond->size * sizeof(CC*));
    
    for (int i=0; i<cond->size; i++) {
        cond->subconditions[i] = conditionFromJSON(cJSON_GetArrayItem(subfulfillments_item, i), err);
        if (err[0] != '\0') break;
    }
    cJSON_free(threshold_item);
    cJSON_free(subfulfillments_item);
    if (err[0] != '\0') return NULL;
    return cond;
}


struct CCType cc_thresholdType = { 2, "threshold-sha-256", Condition_PR_thresholdSha256, 1, &thresholdVerify, &thresholdFingerprint, &thresholdCost, &thresholdSubtypes, &thresholdFromJSON, &thresholdFfillToCC };
