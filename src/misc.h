#pragma once

/* printf, putc, getc, files */ 
#include <stdio.h>
/* malloc */
#include <stdlib.h>
/* fixed size integers */
#include <stdint.h>
/* strlen() */
#include <string.h>

typedef unsigned char BYTE;
typedef uint64_t WORD;

extern const WORD WORD_SIZE;
extern const WORD WORD_SIZE_BITS;
extern const WORD DWORD_SIZE;

#define ROTL64(X,C) (((X)<<(C))|((X)>>(64-(C))))
#define ROTR64(X,C) (((X)>>(C))|((X)<<(64-(C))))

enum mode { ENCRYPTION, DECRYPTION, KEYGEN };

BYTE *keygen(WORD);
WORD pow_word(WORD, WORD);
WORD get_file_size(FILE*);
WORD align(WORD);
WORD pad(WORD);
WORD flush_data(FILE*, WORD*, WORD, enum mode);
