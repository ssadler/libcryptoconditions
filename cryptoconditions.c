
#include "include/models/Condition.h"
#include "include/models/Ed25519FingerprintContents.h"
#include "include/models/OCTET_STRING.h"
#include "include/cJSON.h"
#include "src/condition.c"
#include <sodium.h>



#define streq(a, b) strcmp(a, b) == 0

/*
 * This guy is for tweetnacl
 */
void randombytes(unsigned char *bytes, unsigned long long num) {
    bytes = malloc(num); // TODO
}

/*
int makeEd25519Condition_t(Condition *cond, char *public_key) {
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
*/


char *getFingerprint(CC *cond) {
    Ed25519FingerprintContents_t fp;
    fp.publicKey = *OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, cond->publicKey, 32);
    char *out = malloc(100);
    char *hash = malloc(32);

    der_encode_to_buffer(&asn_DEF_Ed25519FingerprintContents, &fp, out, 100);
    fprintf(stderr, "%i\n", strlen(out));
    for (int i=0; i<32; i++) fprintf(stderr, "0x%x,", cond->publicKey[i] & 0xff);
    crypto_hash_sha256(hash, out, strlen(out));
    return hash;
}


char *conditionUri(CC *cond) {
    char *out = malloc(1000);
    strcpy(out, "ni:///sha-256;");

    char *fp = getFingerprint(cond);
    size_t len;
    char *encoded = base64_encode(fp, 32, &len);

    strcat(out, encoded);
    strcat(out, "?fpt=ed25519-sha-256&cost=131072");
    return out;

    //"ni:///sha-256;eZI5q6j8T_fqv7xMROaei9_tmTMk4S7WR5Kr4onPHV8?fpt=ed25519-sha-256&cost=131072"
}


char *jsonCondition(CC *cond) {
    return conditionUri(cond);
}


char *makeEd25119Condition(cJSON *params) {
    cJSON *pk_item = cJSON_GetObjectItem(params, "public_key");
    if (!cJSON_IsString(pk_item)) {
        return "public_key must be a string";
    }
    char *pk_b64 = pk_item->valuestring;
    size_t binsz;

    CC *cond = malloc(sizeof(CC));
    cond->publicKey = base64_decode(pk_b64, strlen(pk_b64), &binsz);

    return jsonCondition(cond); // TODO: free(cond);
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
        return makeEd25119Condition(params);
    }
        

    return "a"; // todo: memory leak?
}
