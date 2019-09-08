#ifndef _AES_C_H
#define _AES_C_H

#include "aes.h"

#define DECL_KEYSETUP(MODE, BITS)	\
void AES_C_KeySetup_##BITS##_##MODE(const uchar *usrkey, uchar *rkeys, uint rounds)
DECL_KEYSETUP(Enc, 128);
DECL_KEYSETUP(Dec, 128);
DECL_KEYSETUP(Enc, 192);
DECL_KEYSETUP(Dec, 192);
DECL_KEYSETUP(Enc, 256);
DECL_KEYSETUP(Dec, 256);
#undef DECL_KEYSETUP
#define DECL_KEYSETUP2(MODE, BITS)	\
void AES_C_KeySetupX2_##BITS##_##MODE(const uchar *usrkey, uchar *rkeys, uint rounds)
DECL_KEYSETUP2(Enc, 128);
DECL_KEYSETUP2(Dec, 128);
DECL_KEYSETUP2(Enc, 192);
DECL_KEYSETUP2(Dec, 192);
DECL_KEYSETUP2(Enc, 256);
DECL_KEYSETUP2(Dec, 256);
#undef DECL_KEYSETUP2

void AES_C_Encrypt_Blk(const uchar* rkeys, uint rounds, const uchar in[16], uchar out[16]);
void AES_C_Decrypt_Blk(const uchar* rkeys, uint rounds, const uchar in[16], uchar out[16]);
int  AES_C_ECB_Encrypt(const uchar* rkeys, uint rounds, uchar *iv,  uint pad, const uchar *in, uchar *out, ssize_t len, ssize_t *olen);
int  AES_C_ECB_Decrypt(const uchar* rkeys, uint rounds, uchar *iv,  uint pad, const uchar *in, uchar *out, ssize_t len, ssize_t *olen);
int  AES_C_CBC_Encrypt(const uchar* rkeys, uint rounds, uchar *iv,  uint pad, const uchar *in, uchar *out, ssize_t len, ssize_t *olen);
int  AES_C_CBC_Decrypt(const uchar* rkeys, uint rounds, uchar *iv,  uint pad, const uchar *in, uchar *out, ssize_t len, ssize_t *olen);
int  AES_C_CTR_Crypt  (const uchar* rkeys, uint rounds, uchar *ctr, uint pad, const uchar *in, uchar *out, ssize_t len, ssize_t *olen);

void AES_C_Encrypt_BlkX2(const uchar* rkeys, uint rounds, const uchar in[16], uchar out[16]);
void AES_C_Decrypt_BlkX2(const uchar* rkeys, uint rounds, const uchar in[16], uchar out[16]);
int  AES_C_ECB_EncryptX2(const uchar* rkeys, uint rounds, uchar *iv,  uint pad, const uchar *in, uchar *out, ssize_t len, ssize_t *olen);
int  AES_C_ECB_DecryptX2(const uchar* rkeys, uint rounds, uchar *iv,  uint pad, const uchar *in, uchar *out, ssize_t len, ssize_t *olen);
int  AES_C_CBC_EncryptX2(const uchar* rkeys, uint rounds, uchar *iv,  uint pad, const uchar *in, uchar *out, ssize_t len, ssize_t *olen);
int  AES_C_CBC_DecryptX2(const uchar* rkeys, uint rounds, uchar *iv,  uint pad, const uchar *in, uchar *out, ssize_t len, ssize_t *olen);
int  AES_C_CTR_CryptX2  (const uchar* rkeys, uint rounds, uchar *ctr, uint pad, const uchar *in, uchar *out, ssize_t len, ssize_t *olen);

extern ciph_desc_t AES_C_Methods[];

#endif
