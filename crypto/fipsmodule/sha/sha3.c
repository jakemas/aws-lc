/*
 * Copyright 2017-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal.h"
#include <string.h>


uint8_t *SHA3_224(const uint8_t *data, size_t len,
                  uint8_t out[SHA3_224_DIGEST_LENGTH]) {
  FIPS_service_indicator_lock_state();
  KECCAK1600_CTX ctx;
  int ok = (SHA3_Init(&ctx, SHA3_PAD_CHAR, SHA3_224_DIGEST_BITLENGTH) && 
            SHA3_Update(&ctx, data, len) &&
            SHA3_Final(out, &ctx));

  OPENSSL_cleanse(&ctx, sizeof(ctx));
  FIPS_service_indicator_unlock_state();
  if (ok == 0) {
    return NULL;
  }
  FIPS_service_indicator_update_state();
  return out;
}

uint8_t *SHA3_256(const uint8_t *data, size_t len,
                  uint8_t out[SHA3_256_DIGEST_LENGTH]) {
  FIPS_service_indicator_lock_state();
  KECCAK1600_CTX ctx;
  int ok = (SHA3_Init(&ctx, SHA3_PAD_CHAR, SHA3_256_DIGEST_BITLENGTH) && 
            SHA3_Update(&ctx, data, len) &&
            SHA3_Final(out, &ctx));

  OPENSSL_cleanse(&ctx, sizeof(ctx));
  FIPS_service_indicator_unlock_state();
  if (ok == 0) {
    return NULL;
  }
  FIPS_service_indicator_update_state();
  return out;
}

uint8_t *SHA3_384(const uint8_t *data, size_t len,
                  uint8_t out[SHA3_384_DIGEST_LENGTH]) {
  FIPS_service_indicator_lock_state();
  KECCAK1600_CTX ctx;
  int ok = (SHA3_Init(&ctx, SHA3_PAD_CHAR, SHA3_384_DIGEST_BITLENGTH) && 
            SHA3_Update(&ctx, data, len) &&
            SHA3_Final(out, &ctx));

  OPENSSL_cleanse(&ctx, sizeof(ctx));
  FIPS_service_indicator_unlock_state();
  if (ok == 0) {
    return NULL;
  }
  FIPS_service_indicator_update_state();
  return out;
}

uint8_t *SHA3_512(const uint8_t *data, size_t len,
                  uint8_t out[SHA3_512_DIGEST_LENGTH]) {
  FIPS_service_indicator_lock_state();
  KECCAK1600_CTX ctx;
  int ok = (SHA3_Init(&ctx, SHA3_PAD_CHAR, SHA3_512_DIGEST_BITLENGTH) && 
            SHA3_Update(&ctx, data, len) &&
            SHA3_Final(out, &ctx));

  OPENSSL_cleanse(&ctx, sizeof(ctx));
  FIPS_service_indicator_unlock_state();
  if (ok == 0) {
    return NULL;
  }
  FIPS_service_indicator_update_state();
  return out;
}

uint8_t *SHAKE128(const uint8_t *data, const size_t in_len, uint8_t *out, size_t out_len) {
  FIPS_service_indicator_lock_state();
  KECCAK1600_CTX ctx;
  int ok = (SHAKE_Init(&ctx, SHAKE128_BLOCKSIZE) &&
            SHA3_Update(&ctx, data, in_len) &&
            SHAKE_Final(out, &ctx, out_len));

  OPENSSL_cleanse(&ctx, sizeof(ctx));
  FIPS_service_indicator_unlock_state();
  if (ok == 0) {
    return NULL;
  }
  FIPS_service_indicator_update_state();
  return out;
}

uint8_t *SHAKE256(const uint8_t *data, const size_t in_len, uint8_t *out, size_t out_len) {
  FIPS_service_indicator_lock_state();
  KECCAK1600_CTX ctx;
  int ok = (SHAKE_Init(&ctx, SHAKE256_BLOCKSIZE) &&
            SHA3_Update(&ctx, data, in_len) &&
            SHAKE_Final(out, &ctx, out_len));
  OPENSSL_cleanse(&ctx, sizeof(ctx));
  FIPS_service_indicator_unlock_state();
  if (ok == 0) {
    return NULL;
  }
  FIPS_service_indicator_update_state();
  return out;
}

int SHAKE_Init(KECCAK1600_CTX *ctx, size_t block_size) {
  // The SHAKE block size depends on the security level of the algorithm only
  // It is independent of the output size
  ctx->block_size = block_size;
  return SHA3_Init(ctx, SHAKE_PAD_CHAR, 0);
}


int SHAKE_Final(uint8_t *md, KECCAK1600_CTX *ctx, size_t len) {
  ctx->md_size = len;
  return SHA3_Final(md, ctx);
}

void SHA3_Reset(KECCAK1600_CTX *ctx) {
  memset(ctx->A, 0, sizeof(ctx->A));
  ctx->buf_load = 0;
  ctx->xof_state = XOF_STATE_INIT;
}

int SHA3_Init(KECCAK1600_CTX *ctx, uint8_t pad, size_t bit_len) {
  size_t block_size;

  // The block size is computed differently depending on which algorithm
  // is calling |SHA3_Init|:
  //   - for SHA3 we compute it by calling SHA3_BLOCKSIZE(bit_len)
  //     because the block size depends on the digest bit-length,
  //   - for SHAKE we take the block size from the context.
  // We use the given padding character to differentiate between SHA3 and SHAKE.
  if (pad == SHA3_PAD_CHAR) {
    block_size = SHA3_BLOCKSIZE(bit_len);
  } else if (pad == SHAKE_PAD_CHAR) {
    block_size = ctx->block_size;
  } else {
    return 0;
  }
  
  if (block_size <= sizeof(ctx->buf)) {
    SHA3_Reset(ctx);
    ctx->block_size = block_size;
    ctx->md_size = bit_len / 8;
    ctx->pad = pad;
    return 1;
  }
  return 0;
}

int SHA3_Update(KECCAK1600_CTX *ctx, const void *data, size_t len) {
  const unsigned char *inp = data;
  size_t bsz = ctx->block_size;
  size_t num, rem;

  if (len == 0)
    return 1;

  if (ctx->xof_state == XOF_STATE_SQUEEZE
      || ctx->xof_state == XOF_STATE_FINAL)
    return 0;

  if ((num = ctx->buf_load) != 0) {      /* process intermediate buffer? */
    rem = bsz - num;

    if (len < rem) {
      memcpy(ctx->buf + num, inp, len);
      ctx->buf_load += len;
      return 1;
    }
    /*
     * We have enough data to fill or overflow the intermediate
     * buffer. So we append |rem| bytes and process the block,
     * leaving the rest for later processing...
     */
    memcpy(ctx->buf + num, inp, rem);
    inp += rem, len -= rem;
    (void)SHA3_Absorb(ctx->A, ctx->buf, bsz, bsz);
    ctx->buf_load = 0;
    /* ctx->buf is processed, ctx->num is guaranteed to be zero */
  }

  if (len >= bsz)
    rem = SHA3_Absorb(ctx->A, inp, len, bsz);
  else
    rem = len;

  if (rem) {
    memcpy(ctx->buf, inp + len - rem, rem);
    ctx->buf_load = rem;
  }

  return 1;
}

/*
 * SHA3_Final is a single shot method
 * (Use SHA3_Squeeze for multiple calls).
 * outlen is the variable size output.
 */
int SHA3_Final(uint8_t *md, KECCAK1600_CTX *ctx) {
  size_t block_size = ctx->block_size;
  size_t num = ctx->buf_load;

  if (ctx->md_size == 0) {
    return 1;
  }

  if (ctx->xof_state == XOF_STATE_SQUEEZE
        || ctx->xof_state == XOF_STATE_FINAL)
    return 0;

   // Pad the data with 10*1. Note that |num| can be |block_size - 1|
   // in which case both byte operations below are performed on
   // the same byte.
  memset(ctx->buf + num, 0, block_size - num);
  ctx->buf[num] = ctx->pad;
  ctx->buf[block_size - 1] |= 0x80;

  if (SHA3_Absorb(ctx->A, ctx->buf, block_size, block_size) != 0) {
    return 0;
  }

  ctx->xof_state = XOF_STATE_FINAL;
  SHA3_Squeeze(ctx->A, md, ctx->md_size, block_size, 0);

  FIPS_service_indicator_update_state();

  return 1;
}

/*
 * This method can be called multiple times.
 * Rather than heavily modifying assembler for SHA3_squeeze(),
 * we instead just use the limitations of the existing function.
 * i.e. Only request multiples of the ctx->block_size when calling
 * SHA3_squeeze(). For output length requests smaller than the
 * ctx->block_size just request a single ctx->block_size bytes and
 * buffer the results. The next request will use the buffer first
 * to grab output bytes.
 */

// we can rename this function -- right now it's named as it is in OpenSSL to
// make it clear it is the same code.
int ossl_sha3_squeeze(KECCAK1600_CTX *ctx, unsigned char *out, size_t outlen)
{
    size_t bsz = ctx->block_size;
    size_t num = ctx->buf_load;
    size_t len;
    int next = 1;

    if (outlen == 0)
        return 1;

    if (ctx->xof_state == XOF_STATE_FINAL)
        return 0;

    /*
     * On the first squeeze call, finish the absorb process,
     * by adding the trailing padding and then doing
     * a final absorb.
     */
    if (ctx->xof_state != XOF_STATE_SQUEEZE) {
        /*
         * Pad the data with 10*1. Note that |num| can be |bsz - 1|
         * in which case both byte operations below are performed on
         * same byte...
         */
        memset(ctx->buf + num, 0, bsz - num);
        ctx->buf[num] = ctx->pad;
        ctx->buf[bsz - 1] |= 0x80;
        (void)SHA3_Absorb(ctx->A, ctx->buf, bsz, bsz);
        ctx->xof_state = XOF_STATE_SQUEEZE;
        num = ctx->buf_load = 0;
        next = 0;
    }

    /*
     * Step 1. Consume any bytes left over from a previous squeeze
     * (See Step 4 below).
     */
    if (num != 0) {
        if (outlen > ctx->buf_load)
            len = ctx->buf_load;
        else
            len = outlen;
        memcpy(out, ctx->buf + bsz - ctx->buf_load, len);
        out += len;
        outlen -= len;
        ctx->buf_load -= len;
    }
    if (outlen == 0)
        return 1;

    /* Step 2. Copy full sized squeezed blocks to the output buffer directly */
    if (outlen >= bsz) {
        len = bsz * (outlen / bsz);
        SHA3_Squeeze(ctx->A, out, len, bsz, next);
        next = 1;
        out += len;
        outlen -= len;
    }
    if (outlen > 0) {
        /* Step 3. Squeeze one more block into a buffer */
        SHA3_Squeeze(ctx->A, ctx->buf, bsz, bsz, next);
        memcpy(out, ctx->buf, outlen);
        /* Step 4. Remember the leftover part of the squeezed block */
        ctx->buf_load = bsz - outlen;
    }

    return 1;
}
