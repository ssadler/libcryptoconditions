#define _GNU_SOURCE 1

#include <sys/syscall.h>
#include <unistd.h>

#include "asn/Condition.h"
#include "asn/Fulfillment.h"
#include "asn/Secp256k1Fulfillment.h"
#include "asn/Secp256k1FingerprintContents.h"
#include "asn/OCTET_STRING.h"
#include "include/cJSON.h"
#include "include/secp256k1/include/secp256k1.h"
#include "cryptoconditions.h"
#include "internal.h"


struct CCType cc_secp256k1Type;

static const size_t SECP256K1_PK_SIZE = 33;
static const size_t SECP256K1_SK_SIZE = 32;
static const size_t SECP256K1_SIG_SIZE = 64;


#define CTXOPEN(flags) secp256k1_context *ctx = makeSecp256k1Context(flags)
#define CTXCLOSE()     secp256k1_context_destroy(ctx)


secp256k1_context *makeSecp256k1Context(unsigned int flags)
{
    secp256k1_context *ctx = 0;
    unsigned char ent[32];
    int read = syscall(SYS_getrandom, ent, 32, 0);
    if (read != 32) {
        fprintf(stderr, "Could not read 32 bytes entropy from system\n");
        return NULL;
    }
    ctx = secp256k1_context_create(flags);
    if (!ctx) {
        fprintf(stderr, "Could not create secp256k1 context\n");
        return NULL;
    }
    if (flags & SECP256K1_FLAGS_BIT_CONTEXT_SIGN) {
        if (!secp256k1_context_randomize(ctx, ent)) {
            fprintf(stderr, "Could not randomize secp256k1 context\n");
            return NULL;
        }
    }
    return ctx;
}


static unsigned char *secp256k1Fingerprint(CC *cond) {
    char pubKey[SECP256K1_PK_SIZE];
    size_t ol = SECP256K1_PK_SIZE;
    Secp256k1FingerprintContents_t *fp = calloc(1, sizeof(Secp256k1FingerprintContents_t));
    CTXOPEN(SECP256K1_CONTEXT_NONE);
    secp256k1_ec_pubkey_serialize(ctx, pubKey, &ol, cond->secpPublicKey, SECP256K1_EC_COMPRESSED);
    CTXCLOSE();
    OCTET_STRING_fromBuf(&fp->publicKey, pubKey, SECP256K1_PK_SIZE);
    return hashFingerprintContents(&asn_DEF_Secp256k1FingerprintContents, fp);
}


int secp256k1Verify(CC *cond, CCVisitor visitor) {
    if (cond->type->typeId != cc_secp256k1Type.typeId) return 1;
    // TODO: test failure mode: empty sig / null pointer
    CTXOPEN(SECP256K1_CONTEXT_VERIFY);
    int rc = secp256k1_ecdsa_verify(ctx, cond->secpSignature, visitor.msg, cond->secpPublicKey);
    CTXCLOSE();
    return rc;
}


static int cc_secp256k1VerifyTreeMsg32(CC *cond, unsigned char *msg32) {
    int subtypes = getSubtypes(cond);
    if (subtypes & (1 << cc_prefixType.typeId) &&
        subtypes & (1 << cc_secp256k1Type.typeId)) {
        // No support for prefix currently, due to pending protocol decision on
        // how to combine message and prefix into 32 byte hash
        return 0;
    }
    CCVisitor visitor = {&secp256k1Verify, msg32, 0, NULL};
    int out = cc_visit(cond, visitor);
    return out;
}


/*
 * Signing data
 */
typedef struct CCSecp256k1SigningData {
    secp256k1_pubkey *pk;
    char *sk;
    int nSigned;
} CCSecp256k1SigningData;


/*
 * Visitor that signs an secp256k1 condition if it has a matching public key
 */
static int secp256k1Sign(CC *cond, CCVisitor visitor) {
    if (cond->type->typeId != cc_secp256k1Type.typeId) return 1;
    CCSecp256k1SigningData *signing = (CCSecp256k1SigningData*) visitor.context;
    if (0 != memcmp(cond->secpPublicKey, signing->pk, sizeof(secp256k1_pubkey))) return 1;
    if (!cond->secpSignature) cond->secpSignature = calloc(1, sizeof(secp256k1_ecdsa_signature));
    CTXOPEN(SECP256K1_CONTEXT_SIGN);
    int rc = secp256k1_ecdsa_sign(ctx, cond->secpSignature, visitor.msg, signing->sk, NULL, NULL);
    CTXCLOSE();
    if (rc) {
        signing->nSigned++;
        return 1;
    }
    return 0;
}


/*
 * Sign secp256k1 conditions in a tree
 */
static int cc_signTreeSecp256k1Msg32(struct CC *cond, unsigned char *privateKey, unsigned char *msg32) {
    if (getSubtypes(cond) & (1 << cc_preimageType.typeId)) {
        // No support for prefix currently, due to pending protocol decision on
        // how to combine message and prefix into 32 byte hash
        return 0;
    }
    secp256k1_pubkey *publicKey = calloc(1, sizeof(secp256k1_pubkey));
    CCSecp256k1SigningData signing = {publicKey, privateKey, 0};
    CCVisitor visitor = {&secp256k1Sign, msg32, 32, &signing};
    CTXOPEN(SECP256K1_CONTEXT_SIGN);
    int rc = secp256k1_ec_pubkey_create(ctx, publicKey, privateKey);
    CTXCLOSE();
    if (rc) cc_visit(cond, visitor);
    free(publicKey);
    return signing.nSigned;
}


static unsigned long secp256k1Cost(CC *cond) {
    return 131072;
}


static CC *cc_secp256k1Condition(const unsigned char *publicKey, const unsigned char *signature) {
    CC *cond = 0;
    secp256k1_pubkey *pk = calloc(1, sizeof(secp256k1_pubkey));
    secp256k1_ecdsa_signature *sig = 0;


    CTXOPEN(SECP256K1_CONTEXT_NONE);
    int rc = secp256k1_ec_pubkey_parse(ctx, pk, publicKey, SECP256K1_PK_SIZE);
    if (rc && signature) {
        sig = calloc(1, sizeof(secp256k1_ecdsa_signature));
        rc = secp256k1_ecdsa_signature_parse_compact(ctx, sig, signature);
    }
    CTXCLOSE();

    if (rc) {
        cond = calloc(1, sizeof(CC));
        cond->type = &cc_secp256k1Type;
        cond->secpPublicKey = pk;
        cond->secpSignature = sig;
    } else {
        free(pk);
        free(sig);
    }
    return cond;
}


static CC *secp256k1FromJSON(cJSON *params, unsigned char *err) {
    CC *cond = 0;
    unsigned char *pk = 0, *sig = 0;
    size_t pkSize, sigSize;

    if (!jsonGetBase64(params, "publicKey", err, &pk, &pkSize)) goto END;
    if (SECP256K1_PK_SIZE != pkSize) {
        strcpy(err, "publicKey has incorrect length");
        goto END;
    }

    if (!jsonGetBase64Optional(params, "signature", err, &sig, &sigSize)) goto END;
    if (sig && SECP256K1_SIG_SIZE != sigSize) {
        strcpy(err, "signature has incorrect length");
        goto END;
    }

    cond = cc_secp256k1Condition(pk, sig);
END:
    free(pk);
    free(sig);
    return cond;
}


void secp256k1Decode(CC *cond, unsigned char **pubKey, unsigned char **sig) {
    size_t ol = SECP256K1_PK_SIZE;
    *pubKey = malloc(ol), *sig = 0;
    CTXOPEN(SECP256K1_CONTEXT_NONE);
    secp256k1_ec_pubkey_serialize(ctx, *pubKey, &ol, cond->secpPublicKey, SECP256K1_EC_COMPRESSED);
    if (cond->secpSignature) {
        *sig = malloc(SECP256K1_SIG_SIZE);
        secp256k1_ecdsa_signature_serialize_compact(ctx, *sig, cond->secpSignature);
    }
    CTXCLOSE();
}


static void secp256k1ToJSON(CC *cond, cJSON *params) {
    unsigned char *pubKey, *sig;
    secp256k1Decode(cond, &pubKey, &sig);

    jsonAddBase64(params, "publicKey", pubKey, SECP256K1_PK_SIZE);
    free(pubKey);

    if (sig) {
        jsonAddBase64(params, "signature", sig, SECP256K1_SIG_SIZE);
        free(sig);
    }
}


static CC *secp256k1FromFulfillment(Fulfillment_t *ffill) {
    return cc_secp256k1Condition(ffill->choice.secp256k1Sha256.publicKey.buf,
                                 ffill->choice.secp256k1Sha256.signature.buf);
}


static Fulfillment_t *secp256k1ToFulfillment(CC *cond) {
    if (!cond->secpSignature) {
        return NULL;
    }

    Fulfillment_t *ffill = calloc(1, sizeof(Fulfillment_t));
    ffill->present = Fulfillment_PR_secp256k1Sha256;
    Secp256k1Fulfillment_t *sec = &ffill->choice.secp256k1Sha256;

    unsigned char *pubKey, *sig;
    secp256k1Decode(cond, &pubKey, &sig);
    OCTET_STRING_fromBuf(&sec->publicKey, pubKey, SECP256K1_PK_SIZE);
    OCTET_STRING_fromBuf(&sec->signature, sig, SECP256K1_SIG_SIZE);

    return ffill;
}


int secp256k1IsFulfilled(CC *cond) {
    return cond->secpSignature > 0;
}


static void secp256k1Free(CC *cond) {
    free(cond->secpPublicKey);
    if (cond->secpSignature) {
        free(cond->secpSignature);
    }
    free(cond);
}


static uint32_t secp256k1Subtypes(CC *cond) {
    return 0;
}


struct CCType cc_secp256k1Type = { 5, "secp256k1-sha-256", Condition_PR_secp256k1Sha256, 0, 0, &secp256k1Fingerprint, &secp256k1Cost, &secp256k1Subtypes, &secp256k1FromJSON, &secp256k1ToJSON, &secp256k1FromFulfillment, &secp256k1ToFulfillment, &secp256k1IsFulfilled, &secp256k1Free };
