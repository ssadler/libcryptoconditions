#include <stdio.h>
#include <stddef.h>


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


int readFulfillment(CC *cond, char *ffill_bin, size_t ffill_bin_len);


void freeCondition(CC *cond);

#ifdef __cplusplus
}
#endif


