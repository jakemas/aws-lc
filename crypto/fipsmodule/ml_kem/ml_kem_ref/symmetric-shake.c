#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "symmetric.h"

/*************************************************
* Name:        kyber_shake128_absorb
*
* Description: Absorb step of the SHAKE128 specialized for the Kyber context.
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
*              - const uint8_t *seed: pointer to KYBER_SYMBYTES input to be absorbed into state
*              - uint8_t i: additional byte of input
*              - uint8_t j: additional byte of input
**************************************************/
void kyber_shake128_absorb(KECCAK1600_CTX *ctx,
                           const uint8_t seed[KYBER_SYMBYTES], uint8_t x,
                           uint8_t y) {
  uint8_t extseed[KYBER_SYMBYTES + 2];

  memcpy(extseed, seed, KYBER_SYMBYTES);
  extseed[KYBER_SYMBYTES + 0] = x;
  extseed[KYBER_SYMBYTES + 1] = y;

  //shake128_absorb_once(ctx, extseed, sizeof(extseed));
  SHAKE_Init(ctx, SHAKE128_RATE);
  SHA3_Update(ctx, extseed, sizeof(extseed));
}

/*************************************************
* Name:        kyber_shake256_prf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: number of requested output bytes
*              - const uint8_t *key: pointer to the key (of length KYBER_SYMBYTES)
*              - uint8_t nonce: single-byte nonce (public PRF input)
**************************************************/
void kyber_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce)
{
  uint8_t extkey[KYBER_SYMBYTES+1];

  memcpy(extkey, key, KYBER_SYMBYTES);
  extkey[KYBER_SYMBYTES] = nonce;

  SHAKE256(extkey, sizeof(extkey),out,outlen);
  //shake256(out, outlen, extkey, sizeof(extkey));
}

/*************************************************
* Name:        kyber_shake256_prf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: number of requested output bytes
*              - const uint8_t *key: pointer to the key (of length KYBER_SYMBYTES)
*              - uint8_t nonce: single-byte nonce (public PRF input)
**************************************************/
void kyber_shake256_rkprf(ml_kem_params *params, uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t *input)
{
  //keccak_state s;

  //shake256_init(&s);
  //shake256_absorb(&s, key, KYBER_SYMBYTES);
  //shake256_absorb(&s, input, params->ciphertext_bytes);
  //shake256_finalize(&s);
  //shake256_squeeze(out, KYBER_SSBYTES, &s);

  KECCAK1600_CTX ctx;
  SHAKE_Init(&ctx,SHAKE256_RATE);
  SHA3_Update(&ctx,key,KYBER_SYMBYTES);
  SHA3_Update(&ctx,input,KYBER_CIPHERTEXTBYTES_MAX);
  SHAKE_Final(out,&ctx,KYBER_SSBYTES);
}

// this function is a little pointless, we could instead define:
// #define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) ossl_sha3_squeeze(ctx, out, nblocks * SHAKE128_RATE);
// in symmetric.h
void shake128_squeezeblocks(uint8_t *out, size_t nblocks, KECCAK1600_CTX *ctx)
{
  ossl_sha3_squeeze(ctx,out,nblocks*SHAKE128_RATE);
}
