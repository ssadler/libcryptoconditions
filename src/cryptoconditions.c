
#include "asn/Condition.h"
#include "asn/Fulfillment.h"
#include "asn/Ed25519FingerprintContents.h"
#include "asn/PrefixFingerprintContents.h"
#include "asn/ThresholdFingerprintContents.h"
#include "asn/OCTET_STRING.h"
#include "include/cJSON.h"
#include "cryptoconditions.h"
#include "utils.h"
#include "strings.h"
#include <sodium.h>


#define streq(a, b) strcmp(a, b) == 0

#define BUF_SIZE 1024 * 1024


// TODO: all der_encoding should use dynamically resizing buffer with realloc


char *ed25519Fingerprint(CC *cond) {
    Ed25519FingerprintContents_t fp;
    //OCTET_STRING_fromBuf(&fp.publicKey, cond->publicKey, 32);
    fp.publicKey =* OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, cond->publicKey, 32);
    char out[BUF_SIZE];

    asn_enc_rval_t rc = der_encode_to_buffer(&asn_DEF_Ed25519FingerprintContents, &fp, out, BUF_SIZE);
    if (rc.encoded == -1) {
        return NULL; // TODO assert
    }
    char *hash = malloc(32);
    crypto_hash_sha256(hash, out, rc.encoded);
    //asn_DEF_OCTET_STRING.free_struct(&asn_DEF_OCTET_STRING, &(fp.publicKey), 0);
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


/*
 * Subtype Mask
 */
uint32_t getSubtypes(CC *cond) {
    uint32_t mask = 1 << cond->type->typeId;
    if (cond->type->hasSubtypes) {
        mask |= cond->type->getSubtypes(cond);
    }
    return mask;
}


ConditionTypes_t asnSubtypes(uint32_t mask) {
    ConditionTypes_t types;
    uint8_t buf[4] = {0,0,0,0};
    int maxId = 0;

    for (int i=0; i<32; i++) {
        if (mask & (1<<i)) {
            maxId = i;
            buf[i >> 3] |= 1 << (7 - i % 8);
        }
    }
    
    types.size = 1 + (maxId >> 3);
    types.buf = malloc(types.size);
    memcpy(types.buf, &buf, types.size);
    types.bits_unused = 7 - maxId % 8;
    return types;
}


uint32_t fromAsnSubtypes(ConditionTypes_t types) {
    uint32_t mask = 0;
    for (int i=0; i<types.size*8; i++) {
        if (types.buf[i >> 3] & (1 << (7 - i % 8))) {
            mask |= 1 << i;
        }
    }
    return mask;
}


/*
 * URI Generation
 */
void conditionUriSubtypes(CC *cond, char *out);


char *conditionUri(CC *cond) {
    char *fp = cond->type->fingerprint(cond);
    char *encoded = base64_encode(fp, 32);
    int cost = cond->type->getCost(cond);

    char *out = malloc(1000);
    sprintf(out, "ni:///sha-256;%s?fpt=%s&cost=%i", encoded, cond->type->name, cost);
    fprintf(stderr, "URI:%s\n", out);
    
    if (cond->type->hasSubtypes) {
        appendUriSubtypes(cond->type->getSubtypes(cond), out);
    }

    free(fp);
    free(encoded);

    return out;
}


void appendUriSubtypes(uint32_t mask, char *buf) {
    int append = 0;
    for (int i=0; i<32; i++) {
        if (mask & 1 << i) {
            if (append) {
                strcat(buf, ",");
                strcat(buf, typeRegistry[i]->name);
            } else {
                strcat(buf, "&subtypes=");
                strcat(buf, typeRegistry[i]->name);
            }
            append = 1;
        }
    }
}


uint32_t thresholdSubtypes(CC *cond) {
    uint32_t mask = 0;
    for (int i=0; i<cond->size; i++) {
        mask |= getSubtypes(cond->subconditions[i]);
    }
    mask &= ~(1 << thresholdType.typeId);
    return mask;
}


cJSON *jsonCondition(CC *cond) {
    Condition_t *asn = asnCondition(cond);
    char buf[1000]; // todo: overflows?
    asn_enc_rval_t rc = der_encode_to_buffer(&asn_DEF_Condition, asn, buf, 1000);
    if (rc.encoded == -1) {
        // TODO: assert
    }
    fprintf(stderr, "LEN:%u\n", rc.encoded);

    cJSON *root = cJSON_CreateObject();
    char *uri = conditionUri(cond);
    cJSON_AddItemToObject(root, "uri", cJSON_CreateString(uri));
    free(uri);
    char *b64 = base64_encode(buf, rc.encoded);
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


CC *ed25519FromJSON(cJSON *params, char *err) {
    cJSON *pk_item = cJSON_GetObjectItem(params, "publicKey");
    if (!cJSON_IsString(pk_item)) {
        strcpy(err, "publicKey must be a string");
        return NULL;
    }
    char *pk_b64 = pk_item->valuestring;
    size_t binsz;

    CC *cond = malloc(sizeof(CC));
    cond->type = &ed25519Type;
    cond->publicKey = base64_decode(pk_b64, strlen(pk_b64), &binsz);
    cond->signature = NULL;
    cJSON_free(pk_item);
    return cond;
}


Condition_t *asnCondition(CC *cond) {
    Condition_t *asn = malloc(sizeof(Condition_t));
    SimpleSha256Condition_t simple;
    CompoundSha256Condition_t compound;
    
    asn->present = cond->type->asnType;
    simple.cost = cond->type->getCost(cond);
    char *fp = cond->type->fingerprint(cond);
    //OCTET_STRING_fromBuf(&simple.fingerprint, fp, 32);
    simple.fingerprint =* OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, fp, 32);
    free(fp);
    // We don't know which of the union members to assign to here, so just
    // assign to any that has the correct size
    asn->choice.preimageSha256 = simple;
    if (cond->type->hasSubtypes) {
        compound.fingerprint = simple.fingerprint;
        compound.cost = simple.cost;
        compound.subtypes = asnSubtypes(cond->type->getSubtypes(cond));
        asn->choice.thresholdSha256 = compound;
    }
    return asn;
}


CC *preimageFromJSON(cJSON *params, char *err) {
    cJSON *preimage_item = cJSON_GetObjectItem(params, "preimage");
    if (!cJSON_IsString(preimage_item)) {
        strcpy(err, "preimage must be a string");
        return NULL;
    }
    char *preimage_b64 = preimage_item->valuestring;

    CC *cond = malloc(sizeof(CC));
    cond->type = &preimageType;
    cond->preimage = base64_decode(preimage_b64, strlen(preimage_b64), &cond->preimageLength);
    return cond;
}


int preimageVerify(CC *cond, char *msg) {
    return 1; // no message to verify
}


unsigned long preimageCost(CC *cond) {
    return (unsigned long) cond->preimageLength;
}


char *preimageFingerprint(CC *cond) {
    char *hash = malloc(32); // TODO: need to allocate here?
    crypto_hash_sha256(hash, cond->preimage, cond->preimageLength);
    return hash;
}


void preimageFfillToCC(Fulfillment_t *ffill, CC *cond) {
    cond->type = &preimageType;
    PreimageFulfillment_t p = ffill->choice.preimageSha256;
    cond->preimage = malloc(p.preimage.size);
    memcpy(cond->preimage, p.preimage.buf, p.preimage.size);
    cond->preimageLength = p.preimage.size;
}


/*
 * prefix type
 */

int prefixVerify(CC *cond, char *msg) {
    return 1; // TODO
}


char *prefixFingerprint(CC *cond) {
    PrefixFingerprintContents_t fp;
    Condition_t *asnCond = asnCondition(cond->subcondition);
    fp.subcondition = *asnCond;
    free(asnCond);
    fp.maxMessageLength = cond->maxMessageLength;
    //OCTET_STRING_fromBuf(&fp.prefix, cond->prefix, cond->prefixLength);
    fp.prefix =* OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, cond->prefix, cond->preimageLength);
    /* Encode and hash the result */
    char out[1000^2];
    char *hash = malloc(32);
    asn_enc_rval_t rc = der_encode_to_buffer(&asn_DEF_PrefixFingerprintContents, &fp, out, 1024^2);
    if (rc.encoded == -1) {
        //panic?
    }
    crypto_hash_sha256(hash, out, rc.encoded);
    //asn_DEF_OCTET_STRING.free_struct(&asn_DEF_OCTET_STRING, &(fp.publicKey), 0);
    return hash;
}


unsigned long prefixCost(CC *cond) {
    return 1024 + cond->prefixLength + cond->maxMessageLength +
        cond->subcondition->type->getCost(cond->subcondition);
}


void prefixFfillToCC(Fulfillment_t *ffill, CC *cond) {
    cond->type = &prefixType;
    PrefixFulfillment_t *p = ffill->choice.prefixSha256;
    cond->maxMessageLength = p->maxMessageLength;
    cond->prefix = malloc(p->prefix.size);
    memcpy(cond->prefix, p->prefix.buf, p->prefix.size);
    cond->prefixLength = p->prefix.size;
    cond->subcondition = malloc(sizeof(CC));
    ffillToCC(p->subfulfillment, cond->subcondition);
}


uint32_t prefixSubtypes(CC *cond) {
    return getSubtypes(cond->subcondition) & ~(1 << prefixType.typeId);
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


CC *conditionFromJSON(cJSON *params, char *err);


CC *prefixFromJSON(cJSON *params, char *err) {
    cJSON *mml_item = cJSON_GetObjectItem(params, "maxMessageLength");
    cJSON *prefix_item = cJSON_GetObjectItem(params, "prefix");
    cJSON *subcond_item = cJSON_GetObjectItem(params, "subfulfillment");

    if (!cJSON_IsNumber(mml_item)) {
        strcpy(err, "maxMessageLength must be a number");
        return NULL;
    }

    if (!cJSON_IsString(prefix_item)) {
        strcpy(err, "prefix must be a string");
        return NULL;
    }

    if (!cJSON_IsObject(subcond_item)) {
        strcpy(err, "subfulfillment must be an oject");
        return NULL;
    }

    CC *cond = malloc(sizeof(CC));
    cond->type = &prefixType;
    cond->maxMessageLength = (unsigned long) mml_item->valuedouble;
    CC *sub = conditionFromJSON(subcond_item, err);
    if (NULL == sub) {
        return NULL;
    }
    cond->subcondition = sub;

    cond->prefix = base64_decode(prefix_item->valuestring, // TODO: verify
            strlen(prefix_item->valuestring), &cond->prefixLength);
    cJSON_free(mml_item);
    cJSON_free(prefix_item);
    cJSON_free(subcond_item);
    return cond;
}


CC *thresholdFromJSON(cJSON *params, char *err) {
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
    cond->type = &thresholdType;
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


/*
 * Costs highest to lowest
 */
int cmpCost(const void *a, const void *b) {
    return (int) ( *(unsigned long*)b - *(unsigned long*)a );
}


/*
 * Cost of a threshold condition
 */
unsigned long thresholdCost(CC *cond) {
    // MEMSAFE
    CC *sub; // Each subcondition
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


int thresholdVerify(CC *cond, char *msg) {
    CC *sub;
    for (int i=0; i<cond->size; i++) {
        sub = cond->subconditions[i];
        if (!cond->type->verify(cond, msg)) {
            return 0;
        }
    }
    return 1;
}


int cmpConditions(const void *a, const void *b) {
    char bufa[1000], bufb[1000];
    asn_enc_rval_t r0 = der_encode_to_buffer(&asn_DEF_Condition, *(Condition_t**)a, bufa, 1000);
    asn_enc_rval_t r1 = der_encode_to_buffer(&asn_DEF_Condition, *(Condition_t**)b, bufb, 1000);
    int diff = r0.encoded - r1.encoded;
    return diff != 0 ? diff : strcmp(bufa, bufb);
}


char *thresholdFingerprint(CC *cond) {
    Condition_t **subAsns = malloc(cond->size * sizeof(Condition_t*));

    /* Convert each CC into an ASN condition */
    Condition_t *asnCond;
    for (int i=0; i<cond->size; i++) {
        subAsns[i] = asnCondition(cond->subconditions[i]);
    }

    /* Sort conditions */
    qsort(subAsns, cond->size, sizeof(Condition_t*), cmpConditions);

    char bufa[1000];
    asn_enc_rval_t r;
    for (int i=0; i<cond->size; i++) {
        r = der_encode_to_buffer(&asn_DEF_Condition, subAsns[i], bufa, 1000);
    }

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
    asn_enc_rval_t rc = der_encode_to_buffer(&asn_DEF_ThresholdFingerprintContents, &fp, out, 1024^2);
    if (rc.encoded == -1) {
        fprintf(stderr, "ohshit\n");
    }

    char *hash = malloc(32);
    crypto_hash_sha256(hash, out, rc.encoded);

    //asn_DEF_OCTET_STRING.free_struct(&asn_DEF_OCTET_STRING, &(fp.publicKey), 0);
    free(out);
    free(subAsns);
    return hash;
}


void thresholdFfillToCC(Fulfillment_t *ffill, CC *cond) {
    cond->type = &thresholdType;
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


CCType *getTypeByAsnEnum(Condition_PR present) {
    for (int i=0; i<typeRegistryLength; i++) {
        if (typeRegistry[i] != NULL && typeRegistry[i]->asnType == present) {
            return typeRegistry[i];
        }
    }
    return NULL;
}


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


CC *conditionFromJSON(cJSON *params, char *err) {
    CC *cond;
    if (!cJSON_IsObject(params)) {
        strcpy(err, "condition params must be an object");
        return NULL;
    }
    cJSON *type_item = cJSON_GetObjectItem(params, "type");
    if (!cJSON_IsString(type_item)) {
        strcpy(err, "\"type\" must be a string");
        return NULL;
    }
    for (int i=0; i<typeRegistryLength; i++) {
        if (typeRegistry[i] != NULL) {
            if (streq(type_item->valuestring, typeRegistry[i]->name)) {
                return typeRegistry[i]->fromJSON(params, err);
            }
        }
    }
    strcpy(err, "cannot detect type of condition");
    return NULL;
}


void ed25519FfillToCC(Fulfillment_t *ffill, CC *cond) {
    cond->type = &ed25519Type;
    cond->publicKey = malloc(32);
    memcpy(cond->publicKey, ffill->choice.ed25519Sha256.publicKey.buf, 32);
    cond->signature = malloc(64);
    memcpy(cond->signature, ffill->choice.ed25519Sha256.signature.buf, 64);
}


void ffillToCC(Fulfillment_t *ffill, CC *cond) {
    CCType *type = getTypeByAsnEnum(ffill->present);
    if (NULL == type) {
        fprintf(stderr, "Unknown fulfillment type\n");
        // TODO: panic?
    }
    type->ffillToCC(ffill, cond);
}


int readFulfillment(struct CC *cond, char *ffill_bin, size_t ffill_bin_len) {
    Fulfillment_t *ffill = 0;
    asn_dec_rval_t rval;
    rval = ber_decode(0, &asn_DEF_Fulfillment, (void **)&ffill, ffill_bin, ffill_bin_len);
    if (rval.code == RC_OK) {
        ffillToCC(ffill, cond);
    }
    asn_DEF_Fulfillment.free_struct(&asn_DEF_Fulfillment, ffill, 0);
    if (rval.code == RC_OK) return 0;
    return 1;
}


int verifyFulfillment(CC *cond, char *msg) {
    return cond->type->verify(cond, msg);
}


int readCondition(struct CC *cond, char *cond_bin, size_t length) {
    Condition_t *asnCond = 0;
    asn_dec_rval_t rval;
    rval = ber_decode(0, &asn_DEF_Condition, (void **)&asnCond, cond_bin, length);
    if (rval.code == RC_OK) {
        mkAnon(asnCond, cond);
    }
    asn_DEF_Fulfillment.free_struct(&asn_DEF_Condition, asnCond, 0);
    if (rval.code == RC_OK) return 0;
    return 1;
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


cJSON *decodeCondition(cJSON *params) {
    cJSON *conditionB64_item = cJSON_GetObjectItem(params, "bin");
    if (!cJSON_IsString(conditionB64_item)) {
        return jsonErr("bin must be condition binary base64");
    }

    size_t cond_bin_len;
    char *condition_bin = base64_decode(conditionB64_item->valuestring,
                                        strlen(conditionB64_item->valuestring), &cond_bin_len);
    CC *cond = malloc(sizeof(CC));
    int rc = readCondition(cond, condition_bin, cond_bin_len);
    if (rc != 0) return jsonErr("Invalid condition payload");

    return jsonCondition(cond);
}


void cc_free(CC *cond) {
    //TODO
    free(cond);
}


char *jsonRPC(char* input) {

    ConditionTypes_t typ = asnSubtypes(1<<1 | 1<<4);
    char ou[100];
    asn_enc_rval_t rc = der_encode_to_buffer(&asn_DEF_ConditionTypes, &typ, ou, 100);

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
        cond = conditionFromJSON(params, err);
        if (cond == NULL) {
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

    else if (streq(method, "decodeCondition")) {
        out = decodeCondition(params);
    }

    else {
        out = jsonErr("invalid method");
    }    
    
    char *res = cJSON_Print(out);
    cJSON_Delete(out);
    return res;
}



void dumpCondition(CC *cond) {
    char *str;

    fprintf(stderr, "COND:");
    if (cond->type->typeId == ed25519Type.typeId) {
        str = base64_encode(cond->publicKey, 32);
        fprintf(stderr, "%s", str);
        free(str);
    } else {
    }
    fprintf(stderr, "\n");
}
