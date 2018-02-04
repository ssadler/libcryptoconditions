
#include "asn/Condition.h"
#include "asn/Fulfillment.h"
#include "asn/AuxFulfillment.h"
#include "asn/AuxFingerprintContents.h"
#include "asn/OCTET_STRING.h"
#include "include/cJSON.h"
#include "cryptoconditions.h"



struct CCType cc_auxType;


static char *auxFingerprint(CC *cond) {
    AuxFingerprintContents_t *fp = calloc(1, sizeof(AuxFingerprintContents_t));
    OCTET_STRING_fromBuf(&fp->method, cond->method, 64);

    char out[BUF_SIZE];
    asn_enc_rval_t rc = der_encode_to_buffer(&asn_DEF_AuxFingerprintContents, fp, out, BUF_SIZE);
    ASN_STRUCT_FREE(asn_DEF_AuxFingerprintContents, fp);

    if (rc.encoded == -1) {
        return NULL; // TODO assert
    }
    char *hash = calloc(1, 32);
    crypto_hash_sha256(hash, out, rc.encoded);
    return hash;
}


static int auxVerifyMessage(CC *cond, char *msg, size_t length) {
    return 1; // no message to verify
}


static unsigned long auxCost(CC *cond) {
    return 131072;
}


int checkString(cJSON *value, char *key, char *err) {
    if (value == NULL) {
        sprintf(err, "%s is required", key);
        return 0;
    }
    if (!cJSON_IsString(value)) {
        sprintf(err, "%s must be a string", key);
        return 0;
    }
    return 1;
}

int checkDecodeBase64(cJSON *value, char *key, char *err, char **data, size_t *size) {
    if (!checkString(value, key, err)) {
        return 0;
    }

    *data = base64_decode(value->valuestring, size);
    if (!*data) {
        sprintf(err, "%s must be valid base64", key);
        return 0;
    }
    return 1;
}


static CC *auxFromJSON(cJSON *params, char *err) {
    size_t binsz;

    cJSON *method_item = cJSON_GetObjectItem(params, "method");
    if (!checkString(method_item, "method", err)) {
        return NULL;
    }

    if (strlen(method_item->valuestring) > 64) {
        strcpy(err, "method must be less than or equal to 64 bytes");
        return NULL;
    }

    char *conditionAux;
    size_t conditionAuxLength;
    cJSON *condition_item = cJSON_GetObjectItem(params, "condition");
    if (!checkDecodeBase64(condition_item, "condition", err, &conditionAux, &conditionAuxLength)) {
        return NULL;
    }

    char *fulfillmentAux;
    size_t fulfillmentAuxLength;
    cJSON *fulfillment_item = cJSON_GetObjectItem(params, "fulfillment");
    if (!checkDecodeBase64(fulfillment_item, "fulfillment", err, &fulfillmentAux, &fulfillmentAuxLength)) {
        return NULL;
    }

    CC *cond = calloc(1, sizeof(CC));
    strcpy(cond->method, method_item->valuestring);
    cond->conditionAux = conditionAux;
    cond->conditionAuxLength = conditionAuxLength;
    cond->fulfillmentAux = fulfillmentAux;
    cond->fulfillmentAuxLength = fulfillmentAuxLength;
    cond->type = &cc_auxType;
    return cond;
}


static void auxToJSON(CC *cond, cJSON *params) {

    // add method
    cJSON_AddItemToObject(params, "method", cJSON_CreateString(cond->method));

    // add condition
    char *b64 = base64_encode(cond->conditionAux, cond->conditionAuxLength);
    cJSON_AddItemToObject(params, "condition", cJSON_CreateString(b64));
    free(b64);

    // add fulfillment
    if (cond->fulfillmentAux) {
        b64 = base64_encode(cond->fulfillmentAux, cond->fulfillmentAuxLength);
        cJSON_AddItemToObject(params, "fulfillment", cJSON_CreateString(b64));
        free(b64);
    }
}


static void auxFromFulfillment(Fulfillment_t *ffill, CC *cond) {
    cond->type = &cc_auxType;

    AuxFulfillment_t *aux = &ffill->choice.auxSha256;

    memcpy(cond->method, aux->method.buf, aux->method.size);
    cond->method[aux->method.size] = NULL;

    OCTET_STRING_t octets = aux->conditionAux;
    cond->conditionAuxLength = octets.size;
    cond->conditionAux = malloc(octets.size);
    memcpy(cond->conditionAux, octets.buf, octets.size);

    octets = aux->fulfillmentAux;
    if (octets.size) {
        cond->fulfillmentAuxLength = octets.size;
        cond->fulfillmentAux = malloc(octets.size);
        memcpy(cond->fulfillmentAux, octets.buf, octets.size);
    }
}


static Fulfillment_t *auxToFulfillment(CC *cond) {
    if (!cond->fulfillmentAux) {
        return NULL;
    }
    Fulfillment_t *ffill = calloc(1, sizeof(Fulfillment_t));
    ffill->present = Fulfillment_PR_auxSha256;
    AuxFulfillment_t *aux = &ffill->choice.auxSha256;
    OCTET_STRING_fromBuf(&aux->method, cond->method, strlen(cond->method));
    OCTET_STRING_fromBuf(&aux->conditionAux, cond->conditionAux, cond->conditionAuxLength);
    OCTET_STRING_fromBuf(&aux->fulfillmentAux, cond->fulfillmentAux, cond->fulfillmentAuxLength);
    return ffill;
}


int auxIsFulfilled(CC *cond) {
    return cond->fulfillmentAux > 0;
}


static void auxFree(CC *cond) {
    free(cond->conditionAux);
    if (cond->fulfillmentAux) {
        free(cond->fulfillmentAux);
    }
    free(cond);
}


static uint32_t auxSubtypes(CC *cond) {
    return 0;
}


/*
 * The JSON api doesn't contain custom verifiers, so a stub method is provided suitable for testing
 */
int jsonVerifyAux(CC *cond, void *context) {
    if (strcmp(cond->method, "equals") == 0) {
        return memcmp(cond->conditionAux, cond->fulfillmentAux, cond->conditionAuxLength) == 0;
    }
    fprintf(stderr, "Cannot verify aux; user functions unknown\nHalting\n");
    return 0;
}


struct CCType cc_auxType = { 15, "aux-sha-256", Condition_PR_auxSha256, 0, &auxVerifyMessage, &auxFingerprint, &auxCost, &auxSubtypes, &auxFromJSON, &auxToJSON, &auxFromFulfillment, &auxToFulfillment, &auxIsFulfilled, &auxFree };
