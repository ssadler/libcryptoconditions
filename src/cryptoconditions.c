
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
#include <malloc.h>
#include <sodium.h>


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


CCType *getTypeByAsnEnum(Condition_PR present) {
    for (int i=0; i<typeRegistryLength; i++) {
        if (typeRegistry[i] != NULL && typeRegistry[i]->asnType == present) {
            return typeRegistry[i];
        }
    }
    return NULL;
}


int jsonGet(cJSON *object, char *name, char *target) {
    cJSON *item = cJSON_GetObjectItem(object, name);
    if (!cJSON_IsString(item)) {
        return 1;
    } else if (strlen(item->valuestring) > malloc_usable_size(target)) {
        return 2;
    }
    strcpy(target, item->valuestring);
    return 0;
}


CC *cc_conditionFromJSON(cJSON *params, char *err) {
    CC *cond;
    if (!cJSON_IsObject(params)) {
        strcpy(err, "Condition params must be an object");
        return NULL;
    }
    char typeName[100];
    if (0 != jsonGet(params, "type", typeName)) {
        strcpy(err, "\"type\" not valid");
        return NULL;
    }
    for (int i=0; i<typeRegistryLength; i++) {
        if (typeRegistry[i] != NULL) {
            if (0 == strcmp(typeName, typeRegistry[i]->name)) {
                return typeRegistry[i]->fromJSON(params, err);
            }
        }
    }
    strcpy(err, "cannot detect type of condition");
    return NULL;
}


static cJSON *jsonMakeCondition(cJSON *params, char *err) {
    CC *cond = cc_conditionFromJSON(params, err);
    cJSON *out = NULL;
    if (cond != NULL) {
        out = jsonCondition(cond);
        cc_free(cond);
    }
    return out;
}


static void ffillToCC(Fulfillment_t *ffill, CC *cond) {
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


int cc_verifyMessage(CC *cond, char *msg, size_t length) {
    return cond->type->verifyMessage(cond, msg, length);
}


int cc_verify(CC *cond, char *msg, size_t length, char *uri) {
    char *targetUri = cc_conditionUri(cond);
    int pass = cc_verifyMessage(cond, msg, length) && 0 == strcmp(uri, targetUri);
    free(targetUri);
    return pass;
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


static cJSON *jsonVerifyFulfillment(cJSON *params, char *err) {
    cJSON *uri_item = cJSON_GetObjectItem(params, "uri");
    cJSON *msg_b64_item = cJSON_GetObjectItem(params, "message");
    cJSON *ffill_b64_item = cJSON_GetObjectItem(params, "fulfillment");

    if (!cJSON_IsString(uri_item)) {
        strcpy(err, "uri must be a string");
        return NULL;
    }

    if (!cJSON_IsString(msg_b64_item)) {
        strcpy(err, "message must be a string");
        return NULL;
    }

    if (!cJSON_IsString(ffill_b64_item)) {
        strcpy(err, "fulfillment must be a string");
        return NULL;
    }

    size_t ffill_bin_len;
    char *ffill_bin = base64_decode(ffill_b64_item->valuestring,
            strlen(ffill_b64_item->valuestring), &ffill_bin_len);

    size_t msg_len;
    char *msg = base64_decode(msg_b64_item->valuestring,
            strlen(msg_b64_item->valuestring), &msg_len);

    CC *cond = malloc(sizeof(CC));
    
    if (cc_readFulfillmentBinary(cond, ffill_bin, ffill_bin_len) != 0) {
        strcpy(err, "Invalid fulfillment payload");
        // TODO: free cond
        return NULL;
    }

    int valid = cc_verify(cond, msg, msg_len, uri_item->valuestring);
    cc_free(cond);
    cJSON *out = cJSON_CreateObject();
    cJSON_AddItemToObject(out, "valid", cJSON_CreateBool(valid));
    return out;
}


static cJSON *jsonDecodeFulfillment(cJSON *params, char *err) {
    cJSON *ffill_b64_item = cJSON_GetObjectItem(params, "fulfillment");
    if (!cJSON_IsString(ffill_b64_item)) {
        strcpy(err, "fulfillment must be a string");
        return NULL;
    }

    size_t ffill_bin_len;
    char *ffill_bin = base64_decode(ffill_b64_item->valuestring,
            strlen(ffill_b64_item->valuestring), &ffill_bin_len);

    CC *cond = malloc(sizeof(CC));
    if (cc_readFulfillmentBinary(cond, ffill_bin, ffill_bin_len) != 0) {
        strcpy(err, "Invalid fulfillment payload");
        return NULL;
    }

    return jsonCondition(cond);
}


static cJSON *jsonDecodeCondition(cJSON *params, char *err) {
    cJSON *conditionB64_item = cJSON_GetObjectItem(params, "bin");
    if (!cJSON_IsString(conditionB64_item)) {
        strcpy(err, "bin must be condition binary base64");
        return NULL;
    }

    size_t cond_bin_len;
    char *condition_bin = base64_decode(conditionB64_item->valuestring,
                                        strlen(conditionB64_item->valuestring), &cond_bin_len);
    CC cond;
    int rc = cc_readConditionBinary(&cond, condition_bin, cond_bin_len);

    if (rc != 0) {
        strcpy(err, "Invalid condition payload");
        return NULL;
    }

    return jsonCondition(&cond);
}


void cc_free(CC *cond) {
    cond->type->free(cond);
}


char *cc_jsonMethodNames[] = {
    "makeCondition",
    "decodeCondition",
    "decodeFulfillment",
    "verifyFulfillment"
};


cJSON *(*cc_jsonMethodImplementations[])(cJSON *params, char *err) = {
    &jsonMakeCondition,
    &jsonDecodeCondition,
    &jsonDecodeFulfillment,
    &jsonVerifyFulfillment
};


static cJSON* execJsonRPC(cJSON *root, char *err) {
    cJSON *method_item = cJSON_GetObjectItem(root, "method");

    if (!cJSON_IsString(method_item)) {
        return jsonErr("malformed method");
    }

    cJSON *params = cJSON_GetObjectItem(root, "params");
    if (!cJSON_IsObject(params)) {
        return jsonErr("params is not an object");
    }

    for (int i=0; i<4; i++) {
        if (0 == strcmp(cc_jsonMethodNames[i], method_item->valuestring)) {
            return cc_jsonMethodImplementations[i](params, err);
        }
    }

    return jsonErr("invalid method");
}


char *jsonRPC(char* input) {
    cJSON *root = cJSON_Parse(input);
    char err[1000] = "\0";
    cJSON *out = execJsonRPC(root, err);
    char *res;
    if (NULL == out) out = jsonErr(err);
    res = cJSON_Print(out);
    cJSON_Delete(out);
    cJSON_Delete(root);
    return res;
}
