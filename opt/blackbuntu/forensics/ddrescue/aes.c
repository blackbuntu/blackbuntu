/** aes.c
 * Generic AES routines buidling CBC and CTR by calling a lowlevel AES_Blk routine
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 8/2014
 * License: GPL v2 or v3
 */

#include "aes.h"
#include "secmem.h"

#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>

const char* stypes[] = { "ECB", "CBC", "CTR" };

void xor16(const uchar x1[16], const uchar x2[16], uchar xout[16])
{
	uint i;
	for (i = 0; i < 16; i+=sizeof(ulong))
		*(ulong*)(xout+i) = *(ulong*)(x1+i) ^ *(ulong*)(x2+i);
}

void xor48(const uchar x1[48], const uchar x2[48], uchar xout[48])
{
	uint i;
	for (i = 0; i < 48; i+=sizeof(ulong))
		*(ulong*)(xout+i) = *(ulong*)(x1+i) ^ *(ulong*)(x2+i);
}

void xor64(const uchar x1[64], const uchar x2[64], uchar xout[64])
{
	uint i;
	for (i = 0; i < 64; i+=sizeof(ulong))
		*(ulong*)(xout+i) = *(ulong*)(x1+i) ^ *(ulong*)(x2+i);
}

/* PKCS padding */
void fill_blk(const uchar *in, uchar bf[16], ssize_t len, uint pad)
{
	uint i;
	uchar by = pad? 16-(len&0x0f) : 0;
	for (i = 0; i < len; ++i)
		bf[i] = in[i];
	for (; i < 16; ++i)
		bf[i] = by;
}

int  AES_Gen_ECB_Enc(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     /* uchar *iv,*/ uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen)
{
	*olen = len;
	while (len >= 16) {
		cryptfn(rkeys, rounds, input, output);
		len -= 16; input += 16; output += 16;
	}
	if (len || pad == PAD_ALWAYS) {
		uchar in[16];
		fill_blk(input, in, len, pad);
		cryptfn(rkeys, rounds, in, output);
		*olen += 16-(len&15);
	}
	return (pad == PAD_ALWAYS || (len&15))? 16-(len&15): 0;
}

int  AES_Gen_ECB_Enc4(AES_Crypt_Blk_fn *cryptfn4, AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     /* uchar *iv,*/ uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen)
{
	*olen = len;
	while (len >= 64) {
		cryptfn4(rkeys, rounds, input, output);
		len -= 64; input += 64; output += 64;
	}
	while (len >= 16) {
		cryptfn(rkeys, rounds, input, output);
		len -= 16; input += 16; output += 16;
	}
	if (len || pad == PAD_ALWAYS) {
		uchar in[16];
		fill_blk(input, in, len, pad);
		cryptfn(rkeys, rounds, in, output);
		*olen += 16-(len&15);
	}
	return (pad == PAD_ALWAYS || (len&15))? 16-(len&15): 0;
}

#include <stdio.h>
/** Decrypt padding:
 * We expect all blocks have been decoded fully and
 * the output pointer points to the first byte beyond
 * the output buffer (i.e. output[-1] is the last decoded byte).
 * *olen contains the input length -- which may not be a multiple
 * of the block size -- in the PAD_ZERO case, we'll leave it
 * untouched (and assume that caller knew the right length).
 * Otherwise we round olen up to the next multiple of the block
 * size and then look for padding bytes. With PAD_ALWAYS, there
 * MUST be padding (1 -- 16 bytes), with PAD_ASNEEDED there may
 * be padding (0 -- 15 bytes). Note that there is a risk for
 * misinterpretation with PAD_ASNEEDED (if the last byte of the
 * inupt happens to be a 0x01, or -- less likely -- the last two
 * bytes being 0x02 0x02 or ...).
 * Return value: 0 => Success
 * Negative: Error: -ILLEGAL_PADDING, -INCONSISTENT_PADDING
 * 	(no unpadding happens then)
 * Positive: Success, but a not insignificant chance for wrongly
 * 	unpadded data (1: 1/256 chance, 2: 1/256^2, ...)
 */
int dec_fix_olen_pad(ssize_t *olen, uint pad, const uchar *output)
{
	if (!pad)
		return 0;
	uchar last = output[-1];
	if (last > 0x10)
		return (pad == PAD_ASNEEDED? ILLEGAL_PADDING: -ILLEGAL_PADDING);
	uint i;
	for (i = 1; i < last; ++i) {
		if (*(output-1-i) != last) 
			return (pad == PAD_ASNEEDED? INCONSISTENT_PADDING: -INCONSISTENT_PADDING);
	}
	int err = 0;
	if (pad != PAD_ALWAYS) {
		if (last < 8)
			err = last;
	}
	if (*olen & 0x0f)
		*olen += 16-(*olen&0x0f);
	*olen -= last;
	return err;
}

int  AES_Gen_ECB_Dec(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     /* uchar* iv,*/ uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen)
{
	*olen = len;
	while (len > 0) {
		cryptfn(rkeys, rounds, input, output);
		len -= 16; input += 16; output += 16;
	}
	if (pad) 
		return dec_fix_olen_pad(olen, pad, output);
	else
		return 0;
}

int  AES_Gen_ECB_Dec4(AES_Crypt_Blk_fn *cryptfn4,
		     AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     /* uchar* iv,*/ uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen)
{
	*olen = len;
	while (len >= 64) {
		cryptfn4(rkeys, rounds, input, output);
		len -= 64; input += 64; output += 64;
	}
	while (len > 0) {
		cryptfn(rkeys, rounds, input, output);
		len -= 16; input += 16; output += 16;
	}
	if (pad) 
		return dec_fix_olen_pad(olen, pad, output);
	else
		return 0;
}


int  AES_Gen_CBC_Enc(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     uchar *iv, uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen)
{
	*olen = len;
	while (len >= 16) {
		xor16(iv, input, iv);
		cryptfn(rkeys, rounds, iv, iv);
		memcpy(output, iv, 16);
		len -= 16; input += 16; output += 16;
	}
	if (len || pad == PAD_ALWAYS) {
		uchar *in = crypto->blkbuf1;
		fill_blk(input, in, len, pad);
		xor16(iv, in, iv);
		cryptfn(rkeys, rounds, iv, output);
		//memcpy(iv, output, 16);
		*olen += 16-(len&15);
		//memset(in, 0, 16);
		//asm("":::"memory");
	}
	return (pad == PAD_ALWAYS || (len&15))? 16-(len&15): 0;
}

int  AES_Gen_CBC_Dec(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     uchar *iv, uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen)
{
	uchar *ebf = crypto->blkbuf1;
	*olen = len;
	while (len > 0) {
		cryptfn(rkeys, rounds, input, ebf);
		xor16(iv, ebf, output);
		memcpy(iv, input, 16);
		len -= 16; input += 16; output += 16;
	}
	//memset(ebf, 0, 16);
	//asm("":::"memory");
	if (pad)
		return dec_fix_olen_pad(olen, pad, output);
	else
		return 0;
}

int  AES_Gen_CBC_Dec4(AES_Crypt_Blk_fn *cryptfn4,
		     AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     uchar *iv, uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen)
{
	uchar *ebf = crypto->blkbuf2;
	*olen = len;
	while (len >= 64) {
		cryptfn4(rkeys, rounds, input, ebf);
		xor16(iv, ebf, output);
		xor48(input, ebf+16, output+16);
		memcpy(iv, input+48, 16);
		len -= 64; input += 64; output += 64;
	}
	while (len > 0) {
		cryptfn(rkeys, rounds, input, ebf);
		xor16(iv, ebf, output);
		memcpy(iv, input, 16);
		len -= 16; input += 16; output += 16;
	}
	//memset(ebf, 0, 64);
	//asm("":::"memory");
	if (pad)
		return dec_fix_olen_pad(olen, pad, output);
	else
		return 0;
}


/* Use 12 bits from nonce, initialize rest with counter */
void AES_Gen_CTR_Prep(const uchar *nonce /*[16]*/, uchar *ctr /*[16]*/, unsigned long long ival)
{
	memcpy(ctr, nonce, 16);
	unsigned int low  = (unsigned int)ival;
	*(uint*)(ctr+12)  = htonl(ntohl(*(uint*)(ctr+12))+low);
	unsigned int high = (unsigned int)(ival>>32);
	*(uint*)(ctr+8)   = htonl(ntohl(*(uint*)(ctr+8))+high);
}

/* Consider counter to be 8 bytes ... this avoids wrap around after 4G blocks (64GB) */
static inline 
void be_inc(uchar ctr[8])
{
	int i = 8;
	do {
		++ctr[--i];
	} while (i && !ctr[i]);
}

static inline 
void be_inc4(uchar ctr[8])
{
	int i;
	for (i = 7; i >= 0; --i) {
		uchar ov = ctr[i];
		ctr[i] = ov+4;
		if (ov < 0xfc)
			return;
	}
}

static inline 
void be4_inc4(uchar ctr[64])
{
	be_inc4(ctr+8);
	be_inc4(ctr+24);
	be_inc4(ctr+40);
	be_inc4(ctr+56);
}

int  AES_Gen_CTR_Crypt(AES_Crypt_Blk_fn *cryptfn,
			const uchar *rkeys, uint rounds,
			uchar *ctr, /* uint pad, */
			const uchar *input, uchar *output,
			ssize_t len/*, ssize_t *olen */)
{
	//assert(pad == 0);
	//*olen = len;
	uchar *eblk = crypto->blkbuf2;
	while (len >= 16) {
		cryptfn(rkeys, rounds, ctr, eblk);
		be_inc(ctr+8);	
		xor16(eblk, input, output);
		len -= 16;
		input += 16; output += 16;
	}
	if (len) {
		uchar *in = crypto->blkbuf1;
		fill_blk(input, in, len, 0 /*pad*/);
		cryptfn(rkeys, rounds, ctr, eblk);
		//be_inc(ctr+8);	
		xor16(eblk, in, in);
		memcpy(output, in, len&15);
		//memset(in, 0, 16);
	}
	//memset(eblk, 0, 16);
	//asm("":::"memory");
	return 0;
}

int  AES_Gen_CTR_Crypt_Opt(AES_Crypt_CTR_Blk_fn *cryptfn4c,
			AES_Crypt_CTR_Blk_fn *cryptfnc,
			const uchar *rkeys, uint rounds,
			uchar *ctr, /* uint pad, */
			const uchar *input, uchar *output,
			ssize_t len/*, ssize_t *olen */)
{
	//assert(pad == 0);
	//*olen = len;
	while (len >= 64) {
		cryptfn4c(rkeys, rounds, input, output, ctr);
		len -= 64;
		input += 64; output += 64;
	}
	while (len >= 16) {
		cryptfnc(rkeys, rounds, input, output, ctr);
		len -= 16;
		input += 16; output += 16;
	}
	if (len) {
		uchar *in = crypto->blkbuf1;
		uchar *eblk = crypto->blkbuf2;
		// Do we really need to uncount the last incomplete block?
		/* FIXME: This is inconsistent, but irrelevant for now */
		//uchar octr[16];
		//memcpy(octr, ctr, 16);
		fill_blk(input, in, len, 0 /*pad*/);
		cryptfnc(rkeys, rounds, in, eblk, ctr);
		memcpy(output, eblk, len&15);
		//memset(in, 0, 16);
		//memcpy(ctr, octr, 16);
		//memset(eblk, 0, 16);
		//asm("":::"memory");
	}
	return 0;
}

int  AES_Gen_CTR_Crypt4(AES_Crypt_Blk_fn *cryptfn4,
			AES_Crypt_Blk_fn *cryptfn,
			const uchar *rkeys, uint rounds,
			uchar *ctr, /* uint pad, */
			const uchar *input, uchar *output,
			ssize_t len/*, ssize_t *olen */)
{
	//assert(pad == 0);
	//*olen = len;
	uchar *eblk = crypto->blkbuf2;
	uchar cblk[64];
#if 0
	if (len >= 64) {
		memcpy(cblk, ctr, 16);
		be_inc(ctr+8);
		memcpy(cblk+16, ctr, 16);
		be_inc(ctr+8);
		memcpy(cblk+32, ctr, 16);
		be_inc(ctr+8);
		memcpy(cblk+48, ctr, 16);
	} 
	while (len >= 128) {
		cryptfn4(rkeys, rounds, cblk, eblk);
		be4_inc4(cblk);
		xor64(eblk, input, output);
		len -= 64;
		input += 64; output += 64;
	}
	if (len >= 64) {
		cryptfn4(rkeys, rounds, cblk, eblk);
		be_inc4(cblk+8);
		xor64(eblk, input, output);
		memcpy(ctr+8, cblk+8, 8);
		len -= 64;
		input += 64; output += 64;
	}
#else
	if (len >= 64) {
		memcpy(cblk, ctr, 8);
		memcpy(cblk+16, ctr, 8);
		memcpy(cblk+32, ctr, 8);
		memcpy(cblk+48, ctr, 8);
	}
	while (len >= 64) {
		memcpy(cblk+ 8, ctr+8, 8);
		be_inc(ctr+8);
		memcpy(cblk+24, ctr+8, 8);
		be_inc(ctr+8);
		memcpy(cblk+40, ctr+8, 8);
		be_inc(ctr+8);
		memcpy(cblk+56, ctr+8, 8);
		cryptfn4(rkeys, rounds, cblk, eblk);
		be_inc(ctr+8);
		xor64(eblk, input, output);
		len -= 64;
		input += 64; output += 64;
	}
#endif	
	while (len >= 16) {
		cryptfn(rkeys, rounds, ctr, eblk);
		be_inc(ctr+8);	
		xor16(eblk, input, output);
		len -= 16;
		input += 16; output += 16;
	}
	if (len) {
		uchar *in = crypto->blkbuf1;
		fill_blk(input, in, len, 0 /*pad*/);
		cryptfn(rkeys, rounds, ctr, eblk);
		//be_inc(ctr+8);	
		xor16(eblk, in, in);
		memcpy(output, in, len&15);
	}
	//memset(eblk, 0, 16);
	//asm("":::"memory");
	return 0;
}

void AES_Gen_Release(uchar *rkeys, uint rounds)
{
	memset(rkeys, 0, 16*(rounds+1));
	asm("":::"memory");
}

ciph_desc_t *findalg(ciph_desc_t* list, const char* nm, const char probe)
{
	ciph_desc_t* alg = list;
	while (alg->name) {
		if (!strcmp(alg->name, nm)) {
			if (!probe || !alg->probe)
				return alg;
			return (alg->probe()? NULL: alg);
		}
		alg += 1;
	}
	return NULL;
}

stream_dsc_t aes_stream_ecb = { 16, 1, STP_ECB, 0, NULL };
stream_dsc_t aes_stream_cbc = { 16, 0, STP_CBC, 1, NULL };
stream_dsc_t aes_stream_ctr = {  1, 1, STP_CTR, 1, AES_Gen_CTR_Prep };



