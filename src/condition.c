#include <stdio.h>
#include <stddef.h>
#include "utils.h"


#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef struct ConditionType {
    int typeId;
} ConditionType;


struct ConditionType ed25519Type = { 4 };


/* Condition */
typedef struct CC {
	ConditionType type;
	union {
        struct { char *publicKey, *signature; };
	};
} CC;


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

void freeCondition(CC *cond);

#ifdef __cplusplus
}
#endif


