#include <stdio.h>
#include <stdlib.h>
#include "./misc.h"

const short WORD_SIZE = sizeof(WORD);
const short WORD_SIZE_BITS = 8*WORD_SIZE;
const short DWORD_SIZE = 2*WORD_SIZE;

BYTE *keygen(int length) {
  BYTE ch;
  BYTE *key = (BYTE*)calloc(length, sizeof(BYTE));
  int i = 0;
  FILE *rnd = fopen("/dev/random", "rb");
  if (rnd == NULL) {
    fprintf(stderr, "%s\n", "failed to open /dev/random, exit");
    exit;
  }
  while (i < length) {
    ch = fgetc(rnd);
    /* use only printable ascii characters */
    if (33 <= ch && ch <= 126) {
      key[i] = ch;
      ++i;
    }
  }

  return key;
}

WORD pow_word(WORD x, WORD power) {
  WORD result = 1;
  while (power > 0) {
    result *= x;
    --power;
  }
  return result;
}

WORD get_file_size(FILE *f) {
  fseek(f, 0L, SEEK_END);
  WORD fsize = ftell(f);
  fseek(f, 0L, SEEK_SET);

  return fsize;
}

WORD align(WORD x) {
  WORD res = (x + (WORD_SIZE - x % WORD_SIZE)) / WORD_SIZE;
  return res + res % 2;
}

int flush_data(FILE *f, WORD *data, WORD file_size, enum mode m) {
  WORD data_size, delta;
  if (m == ENCRYPTION) {
    data_size = align(file_size);
    file_size = WORD_SIZE * data_size;
  }
  else if (m == DECRYPTION) {
    data_size = file_size / 8;
    delta = data[data_size - 1] & 0xff;
    file_size = file_size - delta;
  }
  for (WORD i = 0, k = 0; i < data_size; ++i) {
    for (WORD j = 0; j < WORD_SIZE && k < file_size; ++j, ++k) {
      fputc((char)(data[i] / pow_word(DWORD_SIZE, DWORD_SIZE-2-2*j)), f);
    }
  }

  return 0;
}
