// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <openssl/base.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>

#include "../crypto/evp_extra/internal.h"
#include "../fipsmodule/evp/internal.h"
#include "../internal.h"
#include "sig_dilithium.h"

TEST(Dilithium3Test, KeyGeneration) {
  EVP_PKEY_CTX *dilithium_pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DILITHIUM3, nullptr);
  ASSERT_NE(dilithium_pkey_ctx, nullptr);

  EVP_PKEY *dilithium_pkey = EVP_PKEY_new();
  ASSERT_NE(dilithium_pkey, nullptr);

  EXPECT_TRUE(EVP_PKEY_keygen_init(dilithium_pkey_ctx));
  EXPECT_TRUE(EVP_PKEY_keygen(dilithium_pkey_ctx, &dilithium_pkey));
  ASSERT_NE(dilithium_pkey->pkey.ptr, nullptr);

  const DILITHIUM3_KEY *dilithium3Key = (DILITHIUM3_KEY *)(dilithium_pkey->pkey.ptr);
  EXPECT_TRUE(dilithium3Key->has_private);

  uint8_t *buf = nullptr;
  size_t buf_size;
  EXPECT_TRUE(EVP_PKEY_get_raw_public_key(dilithium_pkey, buf, &buf_size));
  EXPECT_EQ((size_t)DILITHIUM3_PUBLIC_KEY_BYTES, buf_size);

  buf = (uint8_t *)OPENSSL_malloc(buf_size);
  ASSERT_NE(buf, nullptr);
  EXPECT_TRUE(EVP_PKEY_get_raw_public_key(dilithium_pkey, buf, &buf_size));

  buf_size = 0;
  EXPECT_FALSE(EVP_PKEY_get_raw_public_key(dilithium_pkey, buf, &buf_size));

  uint32_t err = ERR_get_error();
  EXPECT_EQ(ERR_LIB_EVP, ERR_GET_LIB(err));
  EXPECT_EQ(EVP_R_BUFFER_TOO_SMALL, ERR_GET_REASON(err));
  OPENSSL_free(buf);
  buf = nullptr;

  EXPECT_TRUE(EVP_PKEY_get_raw_private_key(dilithium_pkey, buf, &buf_size));
  EXPECT_EQ((size_t)DILITHIUM3_PRIVATE_KEY_BYTES, buf_size);

  buf = (uint8_t *)OPENSSL_malloc(buf_size);
  ASSERT_NE(buf, nullptr);
  EXPECT_TRUE(EVP_PKEY_get_raw_private_key(dilithium_pkey, buf, &buf_size));

  buf_size = 0;
  EXPECT_FALSE(EVP_PKEY_get_raw_private_key(dilithium_pkey, buf, &buf_size));
  err = ERR_get_error();
  EXPECT_EQ(ERR_LIB_EVP, ERR_GET_LIB(err));
  EXPECT_EQ(EVP_R_BUFFER_TOO_SMALL, ERR_GET_REASON(err));
  OPENSSL_free(buf);

  EVP_PKEY_CTX_free(dilithium_pkey_ctx);
}

TEST(Dilithium3Test, KeyComparison) {
  EVP_PKEY_CTX *dilithium_pkey_ctx1 = EVP_PKEY_CTX_new_id(EVP_PKEY_DILITHIUM3, nullptr);
  ASSERT_NE(dilithium_pkey_ctx1, nullptr);

  EVP_PKEY *dilithium_pkey1 = EVP_PKEY_new();
  ASSERT_NE(dilithium_pkey1, nullptr);

  EXPECT_TRUE(EVP_PKEY_keygen_init(dilithium_pkey_ctx1));
  EXPECT_TRUE(EVP_PKEY_keygen(dilithium_pkey_ctx1, &dilithium_pkey1));
  ASSERT_NE(dilithium_pkey1->pkey.ptr, nullptr);

  EVP_PKEY_CTX *dilithium_pkey_ctx2 = EVP_PKEY_CTX_new_id(EVP_PKEY_DILITHIUM3, nullptr);
  ASSERT_NE(dilithium_pkey_ctx2, nullptr);

  EVP_PKEY *dilithium_pkey2 = EVP_PKEY_new();
  ASSERT_NE(dilithium_pkey2, nullptr);

  EXPECT_TRUE(EVP_PKEY_keygen_init(dilithium_pkey_ctx2));
  EXPECT_TRUE(EVP_PKEY_keygen(dilithium_pkey_ctx2, &dilithium_pkey2));
  ASSERT_NE(dilithium_pkey2->pkey.ptr, nullptr);

  EXPECT_EQ(0, EVP_PKEY_cmp(dilithium_pkey1, dilithium_pkey2));
  EXPECT_EQ(1, EVP_PKEY_cmp(dilithium_pkey1, dilithium_pkey1));
  EXPECT_EQ(1, EVP_PKEY_cmp(dilithium_pkey2, dilithium_pkey2));

  EVP_PKEY_CTX_free(dilithium_pkey_ctx1);
  EVP_PKEY_CTX_free(dilithium_pkey_ctx2);
}

TEST(Dilithium3Test, NewKeyFromBytes) {
  // Source key
  EVP_PKEY_CTX *dilithium_pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DILITHIUM3, nullptr);
  ASSERT_NE(dilithium_pkey_ctx, nullptr);

  EVP_PKEY *dilithium_pkey = EVP_PKEY_new();
  ASSERT_NE(dilithium_pkey, nullptr);

  EXPECT_TRUE(EVP_PKEY_keygen_init(dilithium_pkey_ctx));
  EXPECT_TRUE(EVP_PKEY_keygen(dilithium_pkey_ctx, &dilithium_pkey));
  ASSERT_NE(dilithium_pkey->pkey.ptr, nullptr);
  const DILITHIUM3_KEY *dilithium3Key = (DILITHIUM3_KEY *)(dilithium_pkey->pkey.ptr);

  // New raw public key
  EVP_PKEY *new_public = EVP_PKEY_new_raw_public_key(EVP_PKEY_DILITHIUM3,
                                                     NULL,
                                                     dilithium3Key->pub,
                                                     DILITHIUM3_PUBLIC_KEY_BYTES);
  ASSERT_NE(new_public, nullptr);

  uint8_t *buf = nullptr;
  size_t buf_size;
  EXPECT_FALSE(EVP_PKEY_get_raw_private_key(new_public, buf, &buf_size));
  uint32_t err = ERR_get_error();
  EXPECT_EQ(ERR_LIB_EVP, ERR_GET_LIB(err));
  EXPECT_EQ(EVP_R_NOT_A_PRIVATE_KEY, ERR_GET_REASON(err));

  // EVP_PKEY_cmp just compares the public keys so this should return 1
  EXPECT_EQ(1, EVP_PKEY_cmp(dilithium_pkey, new_public));

  // New raw private key
  EVP_PKEY *new_private = EVP_PKEY_new_raw_private_key(EVP_PKEY_DILITHIUM3,
                                                       NULL,
                                                       dilithium3Key->priv,
                                                       DILITHIUM3_PRIVATE_KEY_BYTES);
  ASSERT_NE(new_private, nullptr);
  const DILITHIUM3_KEY *newDilithium3Key = (DILITHIUM3_KEY *)(new_private->pkey.ptr);
  EXPECT_EQ(0, OPENSSL_memcmp(dilithium3Key->priv, newDilithium3Key->priv,
                              DILITHIUM3_PRIVATE_KEY_BYTES));

  EVP_PKEY_CTX_free(dilithium_pkey_ctx);
  EVP_PKEY_free(new_public);
  EVP_PKEY_free(new_private);
}

TEST(Dilithium3Test, KeySize) {
  EVP_PKEY_CTX *dilithium_pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DILITHIUM3, nullptr);
  ASSERT_NE(dilithium_pkey_ctx, nullptr);

  EVP_PKEY *dilithium_pkey = EVP_PKEY_new();
  ASSERT_NE(dilithium_pkey, nullptr);

  EXPECT_TRUE(EVP_PKEY_keygen_init(dilithium_pkey_ctx));
  EXPECT_TRUE(EVP_PKEY_keygen(dilithium_pkey_ctx, &dilithium_pkey));

  EXPECT_EQ(DILITHIUM3_PUBLIC_KEY_BYTES + DILITHIUM3_PRIVATE_KEY_BYTES, EVP_PKEY_size(dilithium_pkey));
  EXPECT_EQ(8*(DILITHIUM3_PUBLIC_KEY_BYTES + DILITHIUM3_PRIVATE_KEY_BYTES), EVP_PKEY_bits(dilithium_pkey));

  EVP_PKEY_CTX_free(dilithium_pkey_ctx);
}