/** aes.h
 *
 * Abstract types for the AES family
 */

#ifndef _AES_H
#define _AES_H

#include <sys/types.h>

#define AES_128_ROUNDS 10
#define AES_192_ROUNDS 12
#define AES_256_ROUNDS 14

#if 0
typedef struct _aes_rkeys {
	unsigned int rounds;
	unsigned char *rkeys;	/* 16*rounds+1 */
}
#endif

#define PAD_ZERO 0
#define PAD_ALWAYS 1
#define PAD_ASNEEDED 2

/* Returned as negative vals from crypt fns */
#define ILLEGAL_PADDING 1
#define INCONSISTENT_PADDING 2

typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned long ulong;


#define STP_ECB 0
#define STP_CBC 1
#define STP_CTR 2

extern const char* stypes[]; // = { "ECB", "CBC", "CTR" };

typedef void (Crypt_IV_Prep_fn)(const uchar *nonce /*[16]*/, uchar *ctr /*[16]*/, unsigned long long ival);

typedef struct _stream_dsc {
	uint granul;	/* bytes */
	uchar seek_blk;
	uchar type;
	uchar needs_iv;
	Crypt_IV_Prep_fn *iv_prep;
} stream_dsc_t;

extern stream_dsc_t aes_stream_ecb, aes_stream_cbc, aes_stream_ctr;

/* Both Enc and Dec */
typedef void (Key_Setup_fn)(const uchar* usrkey, uchar* rkeys, uint rounds); 
typedef void (AES_Crypt_Blk_fn)(const uchar* rkeys, uint rounds, 
			    const uchar* input, uchar* output);
typedef void (AES_Crypt_CTR_Blk_fn)(const uchar* rkeys, uint rounds, 
			    const uchar* input, uchar* output, uchar* iv);
typedef int  (Crypt_IV_fn) (const uchar* rkeys, uint rounds,
			    uchar *iv /* [16] */, uint pad,
			    const uchar* input, uchar* output,
			    ssize_t len, ssize_t *olen);
typedef void (Key_Release_fn)(uchar* rkeys, uint rounds);
typedef int (Probe_fn)();
typedef void (Key_Recycle_fn)(uchar* rkeys);

typedef struct _ciph_desc {
	const char *name;
	uint keylen;	/* bits */
	uint rounds;
	uint blocksize;	/* blk cipher blksize, always 16 for AES */
	uint ctx_size;	/* Size for all round keys (and potentially addtl context in bytes) */
	stream_dsc_t *stream;
	Key_Setup_fn *enc_key_setup, *dec_key_setup;
	Crypt_IV_fn *encrypt, *decrypt;
	Key_Release_fn *release;
	Probe_fn *probe;
	Key_Recycle_fn *recycle;
} ciph_desc_t;


/* Generic functions */
int  AES_Gen_ECB_Enc(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     /* uchar *iv unused ,*/ uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen);
int  AES_Gen_ECB_Enc4(AES_Crypt_Blk_fn *cryptfn4,
		     AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     /* uchar *iv unused ,*/ uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen);
int  AES_Gen_ECB_Dec(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     /* char *iv unused ,*/ uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen);
int  AES_Gen_ECB_Dec4(AES_Crypt_Blk_fn *cryptfn4,
		     AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     /* char *iv unused ,*/ uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen);
int  AES_Gen_CBC_Enc(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     uchar *iv, uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen);
/* no CBC_Enc4 - we have data dependencies */
int  AES_Gen_CBC_Dec(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     uchar *iv, uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen);
int  AES_Gen_CBC_Dec4(AES_Crypt_Blk_fn *cryptfn4,
		     AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     uchar *iv, uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen);
int  AES_Gen_CTR_Crypt(AES_Crypt_Blk_fn *cryptfn,
			const uchar *rkeys, uint rounds,
			uchar *ctr, /* uint pad unused ,*/
			const uchar *input, uchar *output,
			ssize_t len/*, ssize_t *olen unused */);
int  AES_Gen_CTR_Crypt4(AES_Crypt_Blk_fn *cryptfn4,
			AES_Crypt_Blk_fn *cryptfn,
			const uchar *rkeys, uint rounds,
			uchar *ctr, /* uint pad unused ,*/
			const uchar *input, uchar *output,
			ssize_t len/*, ssize_t *olen unused */);
int  AES_Gen_CTR_Crypt_Opt(AES_Crypt_CTR_Blk_fn *cryptfn4c,
			AES_Crypt_CTR_Blk_fn *cryptfnc,
			const uchar *rkeys, uint rounds,
			uchar *ctr, /* uint pad unused ,*/
			const uchar *input, uchar *output,
			ssize_t len/*, ssize_t *olen unused */);

void AES_Gen_CTR_Prep(const uchar *nonce /*[16]*/, uchar *ctr/*[16]*/, unsigned long long ival);
void AES_Gen_Release(uchar *rkeys, uint rounds);
void fill_blk(const uchar *in, uchar bf[16], ssize_t len, uint pad);
int  dec_fix_olen_pad(ssize_t *olen, uint pad, const uchar *output);

ciph_desc_t *findalg(ciph_desc_t* list, const char* nm, const char probe);

#endif
