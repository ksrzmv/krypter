/* --------------------------------------------------------------------
* RC5 -- a block cipher designed by Ron Rivest.
* Implementation by John Kelsey, jmkelsey@delphi.com, March 1995.
* This implementation is in the public domain, but RC5 may be patented.
* Check with Rivest or RSA Data Security for details.
*
* This program implements RC5-64/r/b for user-specified r and b.
* (r = number of rounds, b = number of bytes in key)
-------------------------------------------------------------------- */

#include "rc5.h"

/* Function implementations for RC5. */

/* Scrub out all sensitive values. */
void rc5_destroy(rc5_ctx *c){
	for(int i = 0; i < 2*((c->nr) + 1); ++i) {
    c->xk[i] = 0;
  }
	free(c->xk);
}

/* Allocate memory for rc5 context's xk and such. */
void rc5_init(rc5_ctx *c, int rounds){
	c->nr = rounds;
	c->xk = (WORD *) malloc(WORD_SIZE*(2*(rounds+1)));
}

/*
**      rc5_encrypt(context,data_ptr,count_of_blocks_to_encrypt)
**      This function encrypts several blocks with RC5 in ECB mode.
**      *Which* version of RC5 (ie, how many rounds and how much key)
**      is set up in rc5_key() for this context.  Padding out short
**      blocks is the user's responsibility--this function is only
**      interested in how many 32-bit blocks you have.
**
**      RC5's round structure is very simple and should compile down to
**      something very efficient on 32-bit architectures.  On 16-bit
**      architectures like the 8086, RC5 (actually, RC5-32) may not be
**      quite so fast.
*/
void rc5_encrypt(rc5_ctx *c, WORD *data, int blocks){
  WORD *d, *sk;
  WORD h, i, rc;

	d = data;
  sk = (c->xk) + 2;
  for(h = 0; h < blocks; h++){
    d[0] += c->xk[0];
    d[1] += c->xk[1];

    for(i = 0; i < c->nr; ++i){
      d[0] ^= d[1];
      rc = d[1] & (WORD_SIZE_BITS-1);
      d[0] = ROTL64(d[0], rc);
      d[0] += sk[2*i];
			d[1] ^= d[0];
      rc = d[0] & (WORD_SIZE_BITS-1);
      d[1] = ROTL64(d[1], rc);
      d[1] += sk[2*i+1];
      /* use for debug */
      /* printf("Round %03d : %08lx %08lx  sk= %08lx %08lx\n",i/2, d[0],d[1],sk[i],sk[i+1]); */
    }
		d+=2;
  }
}

/*
**      rc5_decrypt(context,data_ptr,count_of_blocks_to_decrypt)
**      This function decrypts a bunch of blocks with RC5 in ECB mode.
**      Padding short blocks is the user's responsibility.
*/
void rc5_decrypt(rc5_ctx *c, WORD *data, int blocks){
	WORD *d, *sk;
  int h, i, rc;

	d = data;
  sk = (c->xk) + 2;
	for(h = 0; h < blocks; ++h){
    for(i = c->nr - 1; i >= 0; --i){
      /* used for debug */
      /* printf("Round %03d: %08lx %08lx  sk: %08lx %08lx\n", i,d[0],d[1],sk[i],sk[i+1]); */
      d[1] -= sk[2*i+1];
      rc = d[0] & (WORD_SIZE_BITS-1);
      d[1] = ROTR64(d[1],rc);
      d[1] ^= d[0];
      d[0] -= sk[2*i];
      rc = d[1] & (WORD_SIZE_BITS-1);
      d[0] = ROTR64(d[0],rc);
			d[0] ^= d[1];
    }

    d[0] -= c->xk[0];
    d[1] -= c->xk[1];
    /* printf("Block %03d: %08lx %08lx  c->xk: %08lx %08lx\n", h,d[0],d[1],c->xk[0],c->xk[1]); */
    d+=2;
	}
}

/*
**      rc5_key(context,key_pointer,key_len,rounds)
**      This implements the RC5 key scheduling algorithm for the
**      specified key length and number of rounds.  The key schedule
**      is fairly complex in C code, but conceptually, it boils down
**      to this:
**
**      1.  Pad the key out to the next 64-bit word.
**      2.  Initialize the expanded key array to a predefined
**          pseudorandom value.
**      3.  Initialize two chaining values, A and B, to 0.
**      4.  Make several passes through the expanded and padded key
**          arrays, adding A and B to the next expanded key entry and then
**          rotating it left 3 bits, and setting A to that entry, and
**          then adding A and B to next padded key entry, and rotating
**          it by (A + B) mod 64 bits, and setting B to that result.
**
*/
void rc5_key(rc5_ctx *c, BYTE *key, int keylen){
	WORD *pk, A, B;
	int xk_len, pk_len, i, num_steps,rc;
	BYTE *cp;

	xk_len = 2*(c->nr + 1);
	pk_len = keylen/WORD_SIZE;

	if((keylen % WORD_SIZE) != 0) {
    pk_len += 1;
  }

  /* Initialize pk (padded key). */
	pk = (WORD*)calloc(pk_len, WORD_SIZE);
	if(pk == NULL) {
		printf("An error occurred!\n");
		exit(-1);
	}

	cp = (BYTE*)pk;
	for(i = 0; i < keylen; ++i) {
    cp[i] = key[i];
  }

	/* Initialize xk (expanded key). */
  /* 
   * P64 = Odd((e - 2) * pow(2, w)) = 0xb7e151628aed2a6b
   * Q64 = Odd((phi - 1) * pow(2, w)) = 0x9e3779b97f4a7c15
   * where:
   *      e - base of ln (2.718281828459...)
   *      phi - golden ratio (1.618033988749...)
   *      w - word size (64 bits)
   */   
	c->xk[0] = 0xb7e151628aed2a6b; /* P64 */
	for(i = 1; i < xk_len; ++i) {
    c->xk[i] = c->xk[i-1] + 0x9e3779b97f4a7c15; /* Q64 */
  }

	/* TESTING */
	A = B = 0;
	for(i = 0; i < xk_len; ++i) {
		A = A + c->xk[i];
		B = B ^ c->xk[i];
	}

	/* Expand key into xk. */
	if(pk_len > xk_len) {
    num_steps = 3*pk_len;
  }
  else {
    num_steps = 3*xk_len;
  }

	A = B = 0;
	for(i = 0; i < num_steps; ++i){
		A = c->xk[i%xk_len] = ROTL64(c->xk[i%xk_len] + A + B, 3);
		rc = (A+B) & (WORD_SIZE_BITS-1);
		B = pk[i%pk_len] = ROTL64(pk[i%pk_len] + A + B, rc);
	}

	/* Clobber sensitive data before deallocating memory. */
	for(i = 0; i < pk_len; ++i) {
    pk[i] = 0;
  }

	free(pk);
}

