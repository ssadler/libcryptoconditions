
#include "include/models/Condition.h"
#include "include/models/Ed25519Sha512Condition.h"
#include "include/models/OCTET_STRING.h"
#include "include/cJSON.h"
#include <sodium.h>



#define streq(a, b) strcmp(a, b) == 0

/*
 * This guy is for tweetnacl
 */
void randombytes(unsigned char *bytes, unsigned long long num) {
    bytes = malloc(num); // TODO
}


int makeEd25519Condition(Condition_t *cond, char *public_key) {
    SimpleSha256Condition *ed25519 = malloc(sizeof(Ed25519Sha512Condition_t));
    OCTET_STRING_t *pk = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, public_key, -1);
    if (pk == NULL) {
        return 1;
    }
    ed25519->publicKey = *pk;
    //fprintf(stderr, public_key);
    ffill->choice.ed25519Sha256 = *ed25519;
    ffill->present = Condition_PR_ed25519Sha256;
    return 0;
}


char *getFingerprint(Condition_t *ffill) {
    char *out = malloc(100);
    char *hash = malloc(32);
    der_encode_to_buffer(&asn_DEF_Ed25519Sha512Condition, &ffill->choice.ed25519Sha256, out, 100);
    //fprintf(stderr, "%zu\n", strlen(out));
    crypto_hash_sha256(hash, out, strlen(out));
    return hash; // LEAK
}

char *conditionUri(Condition_t *ffill) {
    char *out = malloc(1000);
    strcpy(out, "ni:///sha-256;");

    char *fp = getFingerprint(ffill);
    size_t len;
    char *encoded = base64_encode(fp, 32, &len);

    strcat(out, encoded);
    //strcpy(out, "?fpt=ed25519-sha-256&cost=131072");
    return out;

    //"ni:///sha-256;eZI5q6j8T_fqv7xMROaei9_tmTMk4S7WR5Kr4onPHV8?fpt=ed25519-sha-256&cost=131072"
}


char *jsonCondition(Condition_t *ffill) {
    return fulfillmentUri(ffill);
}


char *dispatchMakeEd25119Condition(cJSON *params) {
    cJSON *pk_item = cJSON_GetObjectItem(params, "public_key");
    if (!cJSON_IsString(pk_item)) {
        return "public_key must be a string";
    }
    char *pk_b64 = pk_item->valuestring;
    size_t binsz;
    char *pk_bin = base64_decode(pk_item->valuestring, strlen(pk_b64), &binsz);
    //fprintf(stderr, "%zu %zu\n", binsz, strlen(pk_bin));

    Condition_t *cond = malloc(sizeof(Condition_t));
    int out = makeEd25519Condition(ffill, pk_bin);
    if (0 == out) {
        return jsonCondition(ffill);
    }
    // TODO: shitty errors everywhere
    return "invalid address";
}


char *jsonRPC(char* input) {
    // TODO: Return proper errors
    // cJSON free structures? (everywhere)
    cJSON *root = cJSON_Parse(input);
    cJSON *method_item = cJSON_GetObjectItem(root, "method");
    if (!cJSON_IsString(method_item)) {
        return "";
    }
    char *method = method_item->valuestring;
    cJSON *params = cJSON_GetObjectItem(root, "params");
    if (!cJSON_IsObject(params)) {
        return "params is not an object";
    }

    if (streq(method, "makeEd25519Condition")) {
        return dispatchMakeEd25119Condition(params);
    }
        

    return "a"; // todo: memory leak?
}
