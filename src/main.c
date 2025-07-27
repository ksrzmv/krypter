#include "./rc5.h"
#include "./misc.h"
#include <unistd.h>

const short NR = 255;
const char  *ARG_PATTERN = "k:d";
const char  *OUT_STREAM = "/dev/stdout";

int main(int argc, char** argv){
  WORD data_size, file_size, ch, delta;
  WORD *data;
  BYTE *key;
  FILE *finput, *fout;
  enum mode m = ENCRYPTION;
  /* rc5 context */
  rc5_ctx c;
  int key_len;

  char arg;
  while ((arg = getopt(argc, argv, ARG_PATTERN)) != -1) {
    switch (arg) {
      case 'd':
        m = DECRYPTION;
        break;
      case 'k':
        m = KEYGEN;
        key_len = atoi(optarg);
        break;
      default:
        return 1;
    }
  }


  if (m == KEYGEN) {
    key = keygen(key_len);
    fprintf(stdout, "%s", key);
    free(key);
    return 0;
  }

  /* read key */
  key = (BYTE*)getpass("Enter key: ");
  key_len = strlen((const char*)key);


  finput = fopen(argv[argc-1], "rb");
  file_size = get_file_size(finput);

  /* get size of array of 8-byte blocks */
  if (m == ENCRYPTION) {
    data_size = align(file_size);
  }
  else if (m == DECRYPTION) {
    data_size = file_size / WORD_SIZE;
  }
  delta = data_size * WORD_SIZE - file_size;

  data = (WORD*)calloc(data_size, WORD_SIZE);
  if (data == NULL) {
    fprintf(stderr, "%s\n", "error while memory allocation, exit");
    return 1;
  }

  BYTE IS_EOF = 0;
  for (WORD i = 0; i < data_size; ++i) {
    for (WORD j = 0; j < WORD_SIZE; ++j) {
      if (IS_EOF == 0) {
        ch = fgetc(finput);
        if (ch == EOF) {
          IS_EOF = 1;
          break;
        }
      }
      if (m == ENCRYPTION) {
        if (IS_EOF == 1 && (i == data_size - 1) && (j == WORD_SIZE - 1)) {
          /* last byte of encrypted file is a size of padded data */
          ch = delta;
        }
        else if ((IS_EOF == 1) && (i < data_size - 1) && (j < WORD_SIZE - 1)) {
          /* add bunch of 0b10101010 to pad data with double 64-bit blocks */
          ch = 0xaa;
        }
      }
      
      data[i] += ch * pow_word(DWORD_SIZE, DWORD_SIZE-2-2*j);
    }
  }


  rc5_init(&c, NR); /* nr = number of rounds */
  rc5_key(&c, key, key_len); /* key_len = length of the key in bytes */

  int nb = data_size/2;

  switch(m) {
    case ENCRYPTION:
      rc5_encrypt(&c, data, nb);
      break;
    case DECRYPTION:
      rc5_decrypt(&c, data, nb);
      break;
  }

  fout = fopen(OUT_STREAM, "wb");
  flush_data(fout, data, file_size, m);
  fclose(fout);

  return 0;
}

