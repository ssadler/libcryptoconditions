
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


static int cmpCostDesc(const void *a, const void *b) {
    return (int) ( *(unsigned long*)b - *(unsigned long*)a );
}


static unsigned long thresholdCost(CC *cond) {
    CC *sub;
    unsigned long *costs = calloc(1, cond->size * sizeof(unsigned long));
    for (int i=0; i<cond->size; i++) {
        sub = cond->subconditions[i];
        costs[i] = sub->type->getCost(sub);
    }
    qsort(costs, cond->size, sizeof(unsigned long), cmpCostDesc);
    unsigned long cost = 0;
    for (int i=0; i<cond->threshold; i++) {
        cost += costs[i];
    }
    free(costs);
    return cost + 1024 * cond->size;
}


static int thresholdVerifyMessage(CC *cond, char *msg, size_t length) {
    int res;
    for (int i=0; i<cond->threshold; i++) {
        res = cc_verifyMessage(cond->subconditions[i], msg, length);
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

    /* Create fingerprint */
    ThresholdFingerprintContents_t *fp = calloc(1, sizeof(ThresholdFingerprintContents_t));
    fp->threshold = cond->threshold;
    for (int i=0; i<cond->size; i++) {
        asn_set_add(&fp->subconditions2, calloc(1, sizeof(Condition_t)));
        asnCondition(cond->subconditions[i], fp->subconditions2.list.array[i]);
    }

    /* Sort conditions */
    qsort(fp->subconditions2.list.array, cond->size, sizeof(Condition_t*), cmpConditions);

    /* Encode and hash the result */
    char buf[BUF_SIZE];
    asn_enc_rval_t rc = der_encode_to_buffer(&asn_DEF_ThresholdFingerprintContents, fp, buf, BUF_SIZE);

    /* Free everything */
    ASN_STRUCT_FREE(asn_DEF_ThresholdFingerprintContents, fp);
    
    /* Encode the output */
    assert(rc.encoded > 0);
    char *hash = calloc(1, 32);
    crypto_hash_sha256(hash, buf, rc.encoded);

    return hash;
}


static void thresholdFulfillmentToCC(Fulfillment_t *ffill, CC *cond) {
    cond->type = &cc_thresholdType;
    ThresholdFulfillment_t *t = ffill->choice.thresholdSha256;
    cond->threshold = t->subfulfillments.list.count;
    cond->size = cond->threshold + t->subconditions.list.count;
    cond->subconditions = calloc(cond->size, sizeof(CC*));
    for (int i=0; i<cond->threshold; i++) {
        cond->subconditions[i] = calloc(1, sizeof(CC));
        fulfillmentToCC(t->subfulfillments.list.array[i], cond->subconditions[i]);
    }
    for (int i=0; i<t->subconditions.list.count; i++) {
        cond->subconditions[i+cond->threshold] = calloc(1, sizeof(CC));
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

    CC *cond = calloc(1, sizeof(CC));
    cond->type = &cc_thresholdType;
    cond->threshold = (long) threshold_item->valuedouble;
    cond->size = cJSON_GetArraySize(subfulfillments_item);
    cond->subconditions = calloc(1, cond->size * sizeof(CC*));
    
    cJSON *sub;
    for (int i=0; i<cond->size; i++) {
        sub = cJSON_GetArrayItem(subfulfillments_item, i);
        cond->subconditions[i] = cc_conditionFromJSON(sub, err);
        if (err[0] != '\0') break;
    }

    if (err[0] != '\0') return NULL;
    return cond;
}


static void thresholdFree(CC *cond) {
    for (int i=0; i<cond->size; i++) {
        cc_free(cond->subconditions[i]);
    }
    free(cond->subconditions);
    free(cond);
}


struct CCType cc_thresholdType = { 2, "threshold-sha-256", Condition_PR_thresholdSha256, 1, &thresholdVerifyMessage, &thresholdFingerprint, &thresholdCost, &thresholdSubtypes, &thresholdFromJSON, &thresholdFulfillmentToCC, &thresholdFree };
