#pragma once

#include "./misc.h"

/* An RC5 context needs to know how many rounds it has, and its subkeys. */
typedef struct {
        WORD *xk;
        int nr;
} rc5_ctx;

/* Function prototypes for dealing with RC5 basic operations. */
void rc5_init(rc5_ctx *, int);
void rc5_destroy(rc5_ctx *);
void rc5_key(rc5_ctx *, BYTE *, int);
void rc5_encrypt(rc5_ctx *, WORD *, int);
void rc5_decrypt(rc5_ctx *, WORD *, int);

