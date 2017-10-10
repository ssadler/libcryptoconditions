
#include "asn/Condition.h"
#include "asn/Fulfillment.h"
#include "asn/Ed25519FingerprintContents.h"
#include "asn/ThresholdFingerprintContents.h"
#include "asn/OCTET_STRING.h"
#include "include/cJSON.h"
#include "cryptoconditions.h"
#include "utils.h"
#include "strings.h"
#include <sodium.h>


#define streq(a, b) strcmp(a, b) == 0


// TODO: all der_encoding should use dynamically resizing buffer with realloc


char *ed25519Fingerprint(CC *cond) {
    Ed25519FingerprintContents_t fp;
    fp.publicKey =* OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, cond->publicKey, 32);
    char *out = malloc(100);
    char *hash = malloc(32);

    asn_enc_rval_t rc = der_encode_to_buffer(&asn_DEF_Ed25519FingerprintContents, &fp, out, 100);
    crypto_hash_sha256(hash, out, rc.encoded);
    //asn_DEF_OCTET_STRING.free_struct(&asn_DEF_OCTET_STRING, &(fp.publicKey), 0);
    free(out);
    return hash;
}


char *fingerprintTypes(int mask) {
    char *out = malloc(1000);
    int append = 0;
    for (int i=0; i<5; i++) {
        if (mask & 1 << i) {
            if (append) {
                strcat(out, ",");
                strcat(out, typeRegistry[i]->name);
            } else strcpy(out, typeRegistry[i]->name);
            append = 1;
        }
    }
    return out;
}


void conditionUriSubtypes(CC *cond, char *out);


char *conditionUri(CC *cond) {
    char *fp = cond->type.fingerprint(cond);
    size_t len;
    char *encoded = base64_encode(fp, 32, &len);
    int cost = cond->type.getCost(cond);

    char *out = malloc(1000);
    sprintf(out, "ni:///sha-256;%s?fpt=%s&cost=%i", encoded, cond->type.name, cost);
    
    if (NULL != cond->type.getSubtypes) {
        conditionUriSubtypes(cond, out);
    }

    free(fp);
    free(encoded);

    return out;
}


void conditionUriSubtypes(CC *cond, char *out) {
    strcat(out, "&subtypes=");

    uint32_t mask = cond->type.getSubtypes(cond);
    int pop = __builtin_popcount(mask);
    int pop2 = pop;
    char **subtypes = malloc(pop * sizeof(char*));
    for (int i=0; i<32; i++) {
        if (mask & (1<<i)) {
            subtypes[--pop2] = typeRegistry[i]->name;
        }
    }
    qsort(subtypes, pop, sizeof(char*), strcmp);
    for (int i=0; i<pop; i++) {
        strcat(out, subtypes[i]);
        if (pop - 1 != i) {
            strcat(out, ",");
        }
    }
}


/*
 * Subtype Mask
 */
uint32_t getSubtypes(CC *cond) {
    uint32_t mask = 1 << cond->type.typeId;
    if (NULL != cond->type.getSubtypes) {
        mask |= cond->type.getSubtypes(cond);
    }
    return mask;
}


ConditionTypes_t *asnSubtypes(uint32_t mask) {
    uint8_t buf[4] = {0,0,0,0};
    int maxId = 0;

    for (int i=0; i<32; i++) {
        if (mask & (1<<i)) {
            maxId = i;
            buf[i >> 3] |= 1 << (7 - i % 8);
        }
    }
    
    ConditionTypes_t *types = malloc(sizeof(ConditionTypes_t));
    types->size = 1 + (maxId >> 3);
    types->buf = malloc(types->size);
    memcpy(types->buf, &buf, types->size);
    types->bits_unused = 7 - maxId % 8;
    return types;
}


uint32_t thresholdSubtypes(CC *cond) {
    uint32_t mask = 0;
    for (int i=0; i<cond->size; i++) {
        mask |= getSubtypes(cond->subconditions[i]);
    }
    return mask & ~(1 << thresholdType.typeId);
}


cJSON *jsonCondition(CC *cond) {

    // todo: condition as binary function
    Condition_t *asn = cond->type.asAsn(cond);
    char buf[1000]; // todo: overflows?
    asn_enc_rval_t rc = der_encode_to_buffer(&asn_DEF_Condition, (void*)asn, buf, 1000);
    size_t olen;
    char *b64 = base64_encode(buf, rc.encoded, &olen);

    cJSON *root = cJSON_CreateObject();
    char *uri = conditionUri(cond);
    cJSON_AddItemToObject(root, "uri", cJSON_CreateString(uri));
    free(uri);
    cJSON_AddItemToObject(root, "bin", cJSON_CreateString(b64));
    free(b64);

    return root;
}


int ed25519Verify(CC *cond, char *msg) {
    int rc = crypto_sign_verify_detached(cond->signature, msg, strlen(msg), cond->publicKey);
    return rc == 0;
}


unsigned long ed25519Cost(CC *cond) {
    return 131072;
}


CC *ed25519Condition(cJSON *params, char *err) {
    cJSON *pk_item = cJSON_GetObjectItem(params, "publicKey");
    if (!cJSON_IsString(pk_item)) {
        strcpy(err, "publicKey must be a string");
        return NULL;
    }
    char *pk_b64 = pk_item->valuestring;
    size_t binsz;

    CC *cond = malloc(sizeof(CC));
    cond->type = ed25519Type;
    cond->publicKey = base64_decode(pk_b64, strlen(pk_b64), &binsz);
    cond->signature = NULL;
    return cond;
}


Condition_t *simpleAsnCondition(CC *cond) {
    SimpleSha256Condition_t simple;
    simple.cost = cond->type.getCost(cond);
    char *fp = cond->type.fingerprint(cond);
    simple.fingerprint =* OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, fp, 32);
    free(fp);
    Condition_t *condt = malloc(sizeof(Condition_t));
    condt->present = cond->type.asnType;
    condt->choice.preimageSha256 = simple;
    return condt;
}


CC *preimageCondition(cJSON *params, char *err) {
    cJSON *preimage_item = cJSON_GetObjectItem(params, "preimage");
    if (!cJSON_IsString(preimage_item)) {
        strcpy(err, "preimage must be a string");
        return NULL;
    }
    char *preimage_b64 = preimage_item->valuestring;

    CC *cond = malloc(sizeof(CC));
    cond->type = preimageType;
    cond->preimage = base64_decode(preimage_b64, strlen(preimage_b64), &cond->preimageLen);
    return cond;
}


int preimageVerify(CC *cond, char *msg) {
    return 1; // no message to verify
}


unsigned long preimageCost(CC *cond) {
    return (int) cond->preimageLen;
}


char *preimageFingerprint(CC *cond) {
    char *hash = malloc(32); // TODO: need to allocate here?
    crypto_hash_sha256(hash, cond->preimage, cond->preimageLen);
    return hash;
}


CC *makeCondition(cJSON *params, char *err);

CC *thresholdCondition(cJSON *params, char *err) {
    int e;
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
    cond->type = thresholdType;
    cond->threshold = (long)threshold_item->valuedouble;
    cond->size = cJSON_GetArraySize(subfulfillments_item);
    cond->subconditions = malloc(cond->size * sizeof(CC*));
    
    for (int i=0; i<cond->size; i++) {
        cond->subconditions[i] = makeCondition(cJSON_GetArrayItem(subfulfillments_item, i), err);
        if (err[0] != '\0') {
            return NULL;
        }
    }
    return cond;
}


int cmpCost(const void *a, const void *b) {
    return (int) ( *(unsigned long*)b - *(unsigned long*)a );
}


unsigned long thresholdCost(CC *cond) {
    CC *sub;
    unsigned long *costs = malloc(cond->size * sizeof(unsigned long));
    for (int i=0; i<cond->size; i++) {
        sub = cond->subconditions[i];
        costs[i] = sub->type.getCost(sub);
    }
    qsort(costs, cond->size, sizeof(unsigned long), cmpCost);
    unsigned long cost = 0;
    for (int i=0; i<cond->size; i++) {
        cost += costs[i];
    }
    cost += 1024;
    return cost * cond->size;
}


int thresholdVerify(CC *cond, char *msg) {
    return 1; // TODO
}


int cmpConditions(const void *a, const void *b) {
    char bufa[1000];
    char bufb[1000]; // todo: overflows?
    der_encode_to_buffer(&asn_DEF_Condition, (void*)a, bufa, 1000);
    der_encode_to_buffer(&asn_DEF_Condition, (void*)b, bufb, 1000);
    return strcmp(bufa, bufb);
}


char *thresholdFingerprint(CC *cond) {
    Condition_t **subAsns = malloc(cond->size * sizeof(Condition_t*));

    /* Convert each CC into an ASN condition */
    CC *subcond;
    for (int i=0; i<cond->size; i++) {
        subcond = cond->subconditions[i];
        subAsns[i] = subcond->type.asAsn(subcond);
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
    char *out = malloc(1024^2); // TODO: overflow?
    char *hash = malloc(32);
    asn_enc_rval_t rc = der_encode_to_buffer(&asn_DEF_ThresholdFingerprintContents, &fp, out, 1024^2);
    crypto_hash_sha256(hash, out, rc.encoded);
    //asn_DEF_OCTET_STRING.free_struct(&asn_DEF_OCTET_STRING, &(fp.publicKey), 0);
    free(out);
    return hash;
}


Condition_t *thresholdAsAsn(CC *cond) {
    CompoundSha256Condition_t comp;
    ConditionTypes_t *subtypes = asnSubtypes(thresholdSubtypes(cond));
    comp.subtypes =* subtypes; // TODO: memory leak?
    free(subtypes);

    char *fp = thresholdFingerprint(cond);
    comp.fingerprint =* OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, fp, 32);
    free(fp);

    comp.cost = thresholdCost(cond);

    Condition_t *condt = malloc(sizeof(Condition_t));
    condt->present = Condition_PR_thresholdSha256;
    condt->choice.thresholdSha256 = comp;
    return condt;
}


CC *makeCondition(cJSON *params, char *err) {
    CC *cond;
    if (cJSON_HasObjectItem(params, "publicKey")) {
        cond = ed25519Condition(params, err);
    } else if (cJSON_HasObjectItem(params, "preimage")) {
        cond = preimageCondition(params, err);
    } else if (cJSON_HasObjectItem(params, "threshold")) {
        cond = thresholdCondition(params, err);
    } else {
        strcpy(err, "cannot detect type of condition");
        return NULL;
    }
    return cond;
}


void ffill_to_cc(Fulfillment_t *ffill, CC *cond) {
    if (ffill->present == Fulfillment_PR_ed25519Sha256) {
        cond->type = ed25519Type;
        cond->publicKey = malloc(32);
        memcpy(cond->publicKey, ffill->choice.ed25519Sha256.publicKey.buf, 32);
        cond->signature = malloc(64);
        memcpy(cond->signature, ffill->choice.ed25519Sha256.signature.buf, 64);
    }
    else {
        // TODO
        fprintf(stderr, "Unknown fulfillment type\n");
    }
}


int readFulfillment(struct CC *cond, char *ffill_bin, size_t ffill_bin_len) {
    Fulfillment_t *ffill = 0;
    asn_dec_rval_t rval;
    rval = ber_decode(0, &asn_DEF_Fulfillment, (void **)&ffill, ffill_bin, ffill_bin_len);
    if (rval.code == RC_OK) {
        ffill_to_cc(ffill, cond);
    }
    asn_DEF_Fulfillment.free_struct(&asn_DEF_Fulfillment, ffill, 0);
    if (rval.code == RC_OK) return 0;
    return 1;
}


int verifyFulfillment(CC *cond, char *msg) {
    return cond->type.verify(cond, msg);
}


cJSON *jsonErr(char *err) {
    cJSON *out = cJSON_CreateObject();
    cJSON_AddItemToObject(out, "error", cJSON_CreateString(err));
    return out;
}


cJSON *jsonVerifyFulfillment(cJSON *params) {
    cJSON *uri_item = cJSON_GetObjectItem(params, "uri");
    if (!cJSON_IsString(uri_item)) {
        return jsonErr("uri must be a string");
    }

    cJSON *msg_item = cJSON_GetObjectItem(params, "message");
    if (!cJSON_IsString(msg_item)) {
        return jsonErr("message must be a string");
    }

    cJSON *ffill_b64_item = cJSON_GetObjectItem(params, "fulfillment");
    if (!cJSON_IsString(ffill_b64_item)) {
        return jsonErr("fulfillment must be a string");
    }

    size_t ffill_bin_len;
    char *ffill_bin = base64_decode(ffill_b64_item->valuestring,
            strlen(ffill_b64_item->valuestring), &ffill_bin_len);

    CC *cond = malloc(sizeof(CC));

    int rc = readFulfillment(cond, ffill_bin, ffill_bin_len);
    if (rc != 0) return jsonErr("Invalid fulfillment payload");

    cJSON *out = cJSON_CreateObject();
    int valid = verifyFulfillment(cond, msg_item->valuestring);
    cJSON_AddItemToObject(out, "valid", cJSON_CreateBool(valid));
    return out;
}


cJSON *decodeFulfillment(cJSON *params) {
    cJSON *ffill_b64_item = cJSON_GetObjectItem(params, "fulfillment");
    if (!cJSON_IsString(ffill_b64_item)) {
        return jsonErr("fulfillment must be a string");
    }

    size_t ffill_bin_len;
    char *ffill_bin = base64_decode(ffill_b64_item->valuestring,
            strlen(ffill_b64_item->valuestring), &ffill_bin_len);

    CC *cond = malloc(sizeof(CC));
    int rc = readFulfillment(cond, ffill_bin, ffill_bin_len);
    if (rc != 0) return jsonErr("Invalid fulfillment payload");

    return jsonCondition(cond);
}


void cc_free(CC *cond) {
    //TODO
    free(cond);
}


char *jsonRPC(char* input) {
    // TODO: Return proper errors
    // cJSON free structures? (everywhere)
    cJSON *root = cJSON_Parse(input);
    cJSON *method_item = cJSON_GetObjectItem(root, "method");
    if (!cJSON_IsString(method_item)) {
        return "malformed method";
    }
    char *method = method_item->valuestring;
    cJSON *params = cJSON_GetObjectItem(root, "params");
    if (!cJSON_IsObject(params)) {
        return "params is not an object";
    }

    cJSON *out;
    CC *cond;
    char *err = malloc(1000);
    err[0] = '\0';

    if (streq(method, "makeCondition")) {
        cond = makeCondition(params, err);
        if (cond == NULL) {
            dumpStr(err, 100);
            out = jsonErr(err);
        } else {
            out = jsonCondition(cond);
            cc_free(cond);
        }
    }

    else if (streq(method, "decodeFulfillment")) {
        out = decodeFulfillment(params);
    }

    else if (streq(method, "verifyFulfillment")) {
        out = jsonVerifyFulfillment(params);
    }

    else {
        out = jsonErr("invalid method");
    }    
    
    char *res = cJSON_Print(out);
    cJSON_Delete(out);
    return res;
}



void dumpCondition(CC *cond) {
    size_t olen;
    char *str;

    fprintf(stderr, "COND:");
    if (cond->type.typeId == ed25519Type.typeId) {
        str = base64_encode(cond->publicKey, 32, &olen);
        fprintf(stderr, "%s", str);
        free(str);
    } else {
    }
    fprintf(stderr, "\n");
}


