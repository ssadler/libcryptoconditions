#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef struct ConditionType {
    int typeId;
} ConditionType;

/* Condition */
typedef struct CC {
	ConditionType type;
	union {
        struct { char *publicKey, *signature; };
	};
} CC;


#ifdef __cplusplus
}
#endif


