
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
#include "src/threshold.c"
#include "src/ed25519.c"
#include "src/prefix.c"
#include "src/preimage.c"
#include "src/anon.c"
#include <sodium.h>


#define streq(a, b) strcmp(a, b) == 0


static struct CCType *typeRegistry[] = { &cc_preimageType, &cc_prefixType, &cc_thresholdType, NULL, &cc_ed25519Type };
static int typeRegistryLength = 5;


static void appendUriSubtypes(uint32_t mask, char *buf) {
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

char *cc_conditionUri(CC *cond) {
    char *fp = cond->type->fingerprint(cond);
    char *encoded = base64_encode(fp, 32);
    int cost = cond->type->getCost(cond);

    char *out = malloc(1000);
    sprintf(out, "ni:///sha-256;%s?fpt=%s&cost=%i", encoded, cond->type->name, cost);
    
    if (cond->type->hasSubtypes) {
        appendUriSubtypes(cond->type->getSubtypes(cond), out);
    }

    free(fp);
    free(encoded);

    return out;
}

static char *fingerprintTypes(int mask) {
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
static uint32_t getSubtypes(CC *cond) {
    uint32_t mask = 1 << cond->type->typeId;
    if (cond->type->hasSubtypes) {
        mask |= cond->type->getSubtypes(cond);
    }
    return mask;
}


static ConditionTypes_t asnSubtypes(uint32_t mask) {
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


static uint32_t fromAsnSubtypes(ConditionTypes_t types) {
    uint32_t mask = 0;
    for (int i=0; i<types.size*8; i++) {
        if (types.buf[i >> 3] & (1 << (7 - i % 8))) {
            mask |= 1 << i;
        }
    }
    return mask;
}


static cJSON *jsonCondition(CC *cond) {
    Condition_t *asn = asnCondition(cond);
    char buf[1000]; // todo: overflows?
    asn_enc_rval_t rc = der_encode_to_buffer(&asn_DEF_Condition, asn, buf, 1000);
    if (rc.encoded == -1) {
        // TODO: assert
    }

    cJSON *root = cJSON_CreateObject();
    char *uri = cc_conditionUri(cond);
    cJSON_AddItemToObject(root, "uri", cJSON_CreateString(uri));
    free(uri);
    char *b64 = base64_encode(buf, rc.encoded);
    cJSON_AddItemToObject(root, "bin", cJSON_CreateString(b64));
    free(b64);

    return root;
}


static Condition_t *asnCondition(CC *cond) {
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


CC *conditionFromJSON(cJSON *params, char *err);


CCType *getTypeByAsnEnum(Condition_PR present) {
    for (int i=0; i<typeRegistryLength; i++) {
        if (typeRegistry[i] != NULL && typeRegistry[i]->asnType == present) {
            return typeRegistry[i];
        }
    }
    return NULL;
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


void ffillToCC(Fulfillment_t *ffill, CC *cond) {
    CCType *type = getTypeByAsnEnum(ffill->present);
    if (NULL == type) {
        fprintf(stderr, "Unknown fulfillment type\n");
        // TODO: panic?
    }
    type->ffillToCC(ffill, cond);
}


int cc_readFulfillmentBinary(struct CC *cond, char *ffill_bin, size_t ffill_bin_len) {
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


int cc_verifyFulfillment(CC *cond, char *msg, size_t length) {
    return cond->type->verify(cond, msg, length);
}


int cc_readConditionBinary(struct CC *cond, char *cond_bin, size_t length) {
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


static cJSON *jsonErr(char *err) {
    cJSON *out = cJSON_CreateObject();
    cJSON_AddItemToObject(out, "error", cJSON_CreateString(err));
    return out;
}


static cJSON *jsonVerifyFulfillment(cJSON *params) {
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

    int rc = cc_readFulfillmentBinary(cond, ffill_bin, ffill_bin_len);
    if (rc != 0) return jsonErr("Invalid fulfillment payload");

    int valid = cc_verifyFulfillment(cond, msg_item->valuestring, strlen(msg_item->valuestring)); // TODO: b64 decode
    
    cJSON *out = cJSON_CreateObject();
    cJSON_AddItemToObject(out, "valid", cJSON_CreateBool(valid));
    return out;
}


static cJSON *decodeFulfillment(cJSON *params) {
    cJSON *ffill_b64_item = cJSON_GetObjectItem(params, "fulfillment");
    if (!cJSON_IsString(ffill_b64_item)) {
        return jsonErr("fulfillment must be a string");
    }

    size_t ffill_bin_len;
    char *ffill_bin = base64_decode(ffill_b64_item->valuestring,
            strlen(ffill_b64_item->valuestring), &ffill_bin_len);

    CC *cond = malloc(sizeof(CC));
    int rc = cc_readFulfillmentBinary(cond, ffill_bin, ffill_bin_len);
    if (rc != 0) return jsonErr("Invalid fulfillment payload");

    return jsonCondition(cond);
}


static cJSON *decodeCondition(cJSON *params) {
    cJSON *conditionB64_item = cJSON_GetObjectItem(params, "bin");
    if (!cJSON_IsString(conditionB64_item)) {
        return jsonErr("bin must be condition binary base64");
    }

    size_t cond_bin_len;
    char *condition_bin = base64_decode(conditionB64_item->valuestring,
                                        strlen(conditionB64_item->valuestring), &cond_bin_len);
    CC *cond = malloc(sizeof(CC));
    int rc = cc_readConditionBinary(cond, condition_bin, cond_bin_len);
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






