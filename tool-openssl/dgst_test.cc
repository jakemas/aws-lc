// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <gtest/gtest.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include "../crypto/test/test_util.h"
#include "test_util.h"

// -------------------- MD5 OpenSSL Comparison Test ---------------------------

// Comparison tests cannot run without set up of environment variables:
// AWSLC_TOOL_PATH and OPENSSL_TOOL_PATH.

class DgstComparisonTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Skip gtests if env variables not set
    awslc_executable_path = getenv("AWSLC_TOOL_PATH");
    openssl_executable_path = getenv("OPENSSL_TOOL_PATH");
    if (awslc_executable_path == nullptr ||
        openssl_executable_path == nullptr) {
      GTEST_SKIP() << "Skipping test: AWSLC_TOOL_PATH and/or OPENSSL_TOOL_PATH "
                      "environment variables are not set";
    }
    ASSERT_GT(createTempFILEpath(in_path), 0u);
    ASSERT_GT(createTempFILEpath(out_path_awslc), 0u);
    ASSERT_GT(createTempFILEpath(out_path_openssl), 0u);
  }
  void TearDown() override {
    if (awslc_executable_path != nullptr &&
        openssl_executable_path != nullptr) {
      //      RemoveFile(in_path);
      RemoveFile(out_path_awslc);
      RemoveFile(out_path_openssl);
    }
  }
  char in_path[PATH_MAX];
  char out_path_awslc[PATH_MAX];
  char out_path_openssl[PATH_MAX];
  const char *awslc_executable_path;
  const char *openssl_executable_path;
  std::string awslc_output_str;
  std::string openssl_output_str;
};

// OpenSSL versions 3.1.0 and later change from "(stdin)= " to "MD5(stdin) ="
std::string GetHash(const std::string &str) {
  size_t pos = str.find('=');
  if (pos == std::string::npos) {
    return "";
  }

  // Extract the hash part after the equals sign
  std::string hash = str.substr(pos + 1);

  // Trim leading and trailing whitespace
  size_t start = hash.find_first_not_of(" \t\n\r");
  if (start == std::string::npos) {
    return "";
  }

  size_t end = hash.find_last_not_of(" \t\n\r");
  return hash.substr(start, end - start + 1);
}

// Test against OpenSSL output for "-hmac"
TEST_F(DgstComparisonTest, HMAC_default_files) {
  std::string input_file = std::string(in_path);
  std::ofstream ofs(input_file);
  ofs << "AWS_LC_TEST_STRING_INPUT";
  ofs.close();

  // Run -hmac against a single file.
  std::string awslc_command = std::string(awslc_executable_path) +
                              " dgst -hmac test_key_string " + input_file +
                              " > " + out_path_awslc;
  std::string openssl_command = std::string(openssl_executable_path) +
                                " dgst -hmac test_key_string " + input_file +
                                " > " + out_path_openssl;

  RunCommandsAndCompareOutput(awslc_command, openssl_command, out_path_awslc,
                              out_path_openssl, awslc_output_str,
                              openssl_output_str);

  std::string awslc_hash = GetHash(awslc_output_str);
  std::string openssl_hash = GetHash(openssl_output_str);

  EXPECT_EQ(awslc_hash, openssl_hash);

  // Run -hmac again against multiple files.
  char in_path2[PATH_MAX];
  ASSERT_GT(createTempFILEpath(in_path2), 0u);
  std::string input_file2 = std::string(in_path2);
  ofs.open(input_file2);
  ofs << "AWS_LC_TEST_STRING_INPUT_2";
  ofs.close();

  awslc_command = std::string(awslc_executable_path) +
                  " dgst -hmac alternative_key_string " + input_file + " " +
                  input_file2 + " > " + out_path_awslc;
  openssl_command = std::string(openssl_executable_path) +
                    " dgst -hmac alternative_key_string " + input_file + " " +
                    input_file2 + +" > " + out_path_openssl;

  RunCommandsAndCompareOutput(awslc_command, openssl_command, out_path_awslc,
                              out_path_openssl, awslc_output_str,
                              openssl_output_str);

  awslc_hash = GetHash(awslc_output_str);
  openssl_hash = GetHash(openssl_output_str);

  EXPECT_EQ(awslc_hash, openssl_hash);

  // Run -hmac with empty key
  awslc_command = std::string(awslc_executable_path) +
                  " dgst -hmac \"\" "
                  " " +
                  input_file + " " + input_file2 + " > " + out_path_awslc;
  openssl_command = std::string(openssl_executable_path) + " dgst -hmac \"\" " +
                    input_file + " " + input_file2 + +" > " + out_path_openssl;

  RunCommandsAndCompareOutput(awslc_command, openssl_command, out_path_awslc,
                              out_path_openssl, awslc_output_str,
                              openssl_output_str);

  awslc_hash = GetHash(awslc_output_str);
  openssl_hash = GetHash(openssl_output_str);

  EXPECT_EQ(awslc_hash, openssl_hash);

  RemoveFile(input_file.c_str());
  RemoveFile(input_file2.c_str());
}


TEST_F(DgstComparisonTest, HMAC_default_stdin) {
  std::string tool_command = "echo hmac_this_string | " +
                             std::string(awslc_executable_path) +
                             " dgst -hmac key > " + out_path_awslc;
  std::string openssl_command = "echo hmac_this_string | " +
                                std::string(openssl_executable_path) +
                                " dgst -hmac key > " + out_path_openssl;

  RunCommandsAndCompareOutput(tool_command, openssl_command, out_path_awslc,
                              out_path_openssl, awslc_output_str,
                              openssl_output_str);

  std::string tool_hash = GetHash(awslc_output_str);
  std::string openssl_hash = GetHash(openssl_output_str);

  EXPECT_EQ(tool_hash, openssl_hash);
}

TEST_F(DgstComparisonTest, MD5_files) {
  std::string input_file = std::string(in_path);
  std::ofstream ofs(input_file);
  ofs << "AWS_LC_TEST_STRING_INPUT";
  ofs.close();

  // Input file as pipe (stdin)
  std::string tool_command = std::string(awslc_executable_path) + " md5 < " +
                             input_file + " > " + out_path_awslc;
  std::string openssl_command = std::string(openssl_executable_path) +
                                " md5 < " + input_file + " > " +
                                out_path_openssl;

  RunCommandsAndCompareOutput(tool_command, openssl_command, out_path_awslc,
                              out_path_openssl, awslc_output_str,
                              openssl_output_str);

  std::string tool_hash = GetHash(awslc_output_str);
  std::string openssl_hash = GetHash(openssl_output_str);

  EXPECT_EQ(tool_hash, openssl_hash);

  // Input file as regular command line option.
  tool_command = std::string(awslc_executable_path) + " md5 " + input_file +
                 " > " + out_path_awslc;
  openssl_command = std::string(openssl_executable_path) + " md5 " +
                    input_file + " > " + out_path_openssl;

  RunCommandsAndCompareOutput(tool_command, openssl_command, out_path_awslc,
                              out_path_openssl, awslc_output_str,
                              openssl_output_str);

  tool_hash = GetHash(awslc_output_str);
  openssl_hash = GetHash(openssl_output_str);

  EXPECT_EQ(tool_hash, openssl_hash);

  RemoveFile(input_file.c_str());
}

// Test against OpenSSL output with stdin.
class DgstVerifyTest : public ::testing::Test {
 protected:
  void SetUp() override {
    awslc_executable_path = getenv("AWSLC_TOOL_PATH");
    if (awslc_executable_path == nullptr) {
      GTEST_SKIP() << "Skipping test: AWSLC_TOOL_PATH environment variable is not set";
    }

    // Create temporary paths for test files
    ASSERT_GT(createTempFILEpath(pubkey_path), 0u);
    ASSERT_GT(createTempFILEpath(signature_path), 0u);
    ASSERT_GT(createTempFILEpath(invalid_signature_path), 0u);
    ASSERT_GT(createTempFILEpath(message_path), 0u);
    ASSERT_GT(createTempFILEpath(out_path), 0u);
    ASSERT_GT(createTempFILEpath(out_path_awslc), 0u);
    ASSERT_GT(createTempFILEpath(malformed_key_path), 0u);
    ASSERT_GT(createTempFILEpath(empty_key_path), 0u);
    ASSERT_GT(createTempFILEpath(corrupted_pem_path), 0u);

    // Generate ECDSA P-256 key pair
    bssl::UniquePtr<EC_KEY> ec_key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    ASSERT_TRUE(ec_key);
    ASSERT_TRUE(EC_KEY_generate_key(ec_key.get()));

    pkey.reset(EVP_PKEY_new());
    ASSERT_TRUE(EVP_PKEY_assign_EC_KEY(pkey.get(), ec_key.release()));

    // Export public key in DER format (default)
    bssl::UniquePtr<BIO> bio(BIO_new_file(pubkey_path, "w"));
    ASSERT_TRUE(bio);
    ASSERT_TRUE(i2d_PUBKEY_bio(bio.get(), pkey.get()));

    // Also export public key in PEM format
    ASSERT_GT(createTempFILEpath(pubkey_pem_path), 0u);
    bssl::UniquePtr<BIO> bio_pem(BIO_new_file(pubkey_pem_path, "w"));
    ASSERT_TRUE(bio_pem);
    ASSERT_TRUE(PEM_write_bio_PUBKEY(bio_pem.get(), pkey.get()));

    // Create test message
    std::string test_message = "test message for signature verification";
    std::ofstream msg_file(message_path);
    msg_file << test_message;
    msg_file.close();

    // Sign the test message
    bssl::ScopedEVP_MD_CTX md_ctx;
    ASSERT_TRUE(EVP_DigestSignInit(md_ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()));
    ASSERT_TRUE(EVP_DigestSignUpdate(md_ctx.get(), test_message.data(), test_message.size()));

    size_t sig_len;
    ASSERT_TRUE(EVP_DigestSignFinal(md_ctx.get(), nullptr, &sig_len));
    std::vector<uint8_t> sig(sig_len);
    ASSERT_TRUE(EVP_DigestSignFinal(md_ctx.get(), sig.data(), &sig_len));

    // Write signature to file
    std::ofstream sig_file(signature_path, std::ios::binary);
    sig_file.write(reinterpret_cast<const char*>(sig.data()), sig_len);
    sig_file.close();

    // Create invalid signature by modifying a byte
    sig[0] ^= 0x42;
    std::ofstream invalid_sig_file(invalid_signature_path, std::ios::binary);
    invalid_sig_file.write(reinterpret_cast<const char*>(sig.data()), sig_len);
    invalid_sig_file.close();

    // Create malformed key file
    std::ofstream malformed_key(malformed_key_path);
    malformed_key << "This is not a valid key file";
    malformed_key.close();

    // Create empty key file
    std::ofstream empty_key(empty_key_path);
    empty_key.close();

    // Create corrupted PEM file
    std::ofstream corrupted_pem(corrupted_pem_path);
    corrupted_pem << "-----BEGIN PUBLIC KEY-----\n";
    corrupted_pem << "Not a valid base64 content!!!\n";
    corrupted_pem << "-----END PUBLIC KEY-----\n";
    corrupted_pem.close();
  }

  void TearDown() override {
    if (awslc_executable_path != nullptr) {
      RemoveFile(pubkey_path);
      RemoveFile(pubkey_pem_path);
      RemoveFile(signature_path);
      RemoveFile(invalid_signature_path);
      RemoveFile(message_path);
      RemoveFile(malformed_key_path);
      RemoveFile(empty_key_path);
      RemoveFile(corrupted_pem_path);
    }
  }

  char pubkey_path[PATH_MAX];      // DER format (default)
  char pubkey_pem_path[PATH_MAX];  // PEM format
  char signature_path[PATH_MAX];
  char invalid_signature_path[PATH_MAX];
  char message_path[PATH_MAX];
  char out_path[PATH_MAX];
  char out_path_awslc[PATH_MAX];
  char malformed_key_path[PATH_MAX];
  char empty_key_path[PATH_MAX];
  char corrupted_pem_path[PATH_MAX];
  const char *awslc_executable_path;
  bssl::UniquePtr<EVP_PKEY> pkey;
  std::string awslc_output_str;
  std::string openssl_output_str;
};

TEST_F(DgstVerifyTest, VerifyValidSignature) {
  // Test verification with valid signature
  std::string verify_command = "cat " + std::string(message_path) + " | " +
                              std::string(awslc_executable_path) +
                              " dgst -verify " + std::string(pubkey_path) +
                              " -signature " + std::string(signature_path) +
                              " > " + std::string(out_path);

  // Create an empty file for comparison
  std::ofstream empty_file(out_path_awslc);
  empty_file << "Verified OK\n";
  empty_file.close();

  RunCommandsAndCompareOutput(verify_command, "", out_path, out_path_awslc,
                            awslc_output_str, openssl_output_str);
}

TEST_F(DgstVerifyTest, VerifyValidSignatureWithDER) {
  // Test verification with valid signature using DER format key
  std::string verify_command = "cat " + std::string(message_path) + " | " +
                              std::string(awslc_executable_path) +
                              " dgst -verify " + std::string(pubkey_path) +
                              " -keyform DER" +
                              " -signature " + std::string(signature_path) +
                              " > " + std::string(out_path);

  // Create an empty file for comparison
  std::ofstream empty_file(out_path_awslc);
  empty_file << "Verified OK\n";
  empty_file.close();

  RunCommandsAndCompareOutput(verify_command, "", out_path, out_path_awslc,
                            awslc_output_str, openssl_output_str);
}

TEST_F(DgstVerifyTest, VerifyValidSignatureWithPEM) {
  // Test verification with valid signature using PEM format key
  std::string verify_command = "cat " + std::string(message_path) + " | " +
                              std::string(awslc_executable_path) +
                              " dgst -verify " + std::string(pubkey_pem_path) +
                              " -keyform PEM" +
                              " -signature " + std::string(signature_path) +
                              " > " + std::string(out_path);

  // Create an empty file for comparison
  std::ofstream empty_file(out_path_awslc);
  empty_file << "Verified OK\n";
  empty_file.close();

  RunCommandsAndCompareOutput(verify_command, "", out_path, out_path_awslc,
                            awslc_output_str, openssl_output_str);
}

TEST_F(DgstVerifyTest, VerifyWithDifferentDigestAlgorithm) {
  // Test verification with different digest algorithm
  std::string verify_command = "cat " + std::string(message_path) + " | " +
                              std::string(awslc_executable_path) +
                              " dgst -sha512 -verify " + std::string(pubkey_path) +
                              " -signature " + std::string(signature_path);

  // This should fail because the signature was created with SHA-256
  std::string output;
  int result = RunCommand(verify_command, &output);
  EXPECT_NE(0, result);  // Non-zero exit code indicates failure
  EXPECT_TRUE(output.find("Verification Failure") != std::string::npos);
}

TEST_F(DgstVerifyTest, VerifyInvalidSignature) {
  // Test verification with invalid signature
  std::string verify_command = "cat " + std::string(message_path) + " | " +
                              std::string(awslc_executable_path) +
                              " dgst -verify " + std::string(pubkey_path) +
                              " -signature " + std::string(invalid_signature_path);

  // For invalid signatures, we expect the command to fail with exit code 1
  std::string output;
  int result = RunCommand(verify_command, &output);
  EXPECT_NE(0, result);  // Non-zero exit code indicates failure
  EXPECT_TRUE(output.find("Verification Failure") != std::string::npos);
}

TEST_F(DgstVerifyTest, VerifyWithMalformedKey) {
  // Test verification with malformed key file
  std::string verify_command = "cat " + std::string(message_path) + " | " +
                              std::string(awslc_executable_path) +
                              " dgst -verify " + std::string(malformed_key_path) +
                              " -signature " + std::string(signature_path);

  std::string output;
  int result = RunCommand(verify_command, &output);
  EXPECT_NE(0, result);
  EXPECT_TRUE(output.find("Failed to read public key") != std::string::npos);
}

TEST_F(DgstVerifyTest, VerifyWithEmptyKey) {
  // Test verification with empty key file
  std::string verify_command = "cat " + std::string(message_path) + " | " +
                              std::string(awslc_executable_path) +
                              " dgst -verify " + std::string(empty_key_path) +
                              " -signature " + std::string(signature_path);

  std::string output;
  int result = RunCommand(verify_command, &output);
  EXPECT_NE(0, result);
  EXPECT_TRUE(output.find("Failed to read public key") != std::string::npos);
}

TEST_F(DgstVerifyTest, VerifyWithCorruptedPEM) {
  // Test verification with corrupted PEM file
  std::string verify_command = "cat " + std::string(message_path) + " | " +
                              std::string(awslc_executable_path) +
                              " dgst -verify " + std::string(corrupted_pem_path) +
                              " -keyform PEM" +
                              " -signature " + std::string(signature_path);

  std::string output;
  int result = RunCommand(verify_command, &output);
  EXPECT_NE(0, result);
  EXPECT_TRUE(output.find("Failed to read public key") != std::string::npos);
}

TEST_F(DgstVerifyTest, VerifyWithWrongKeyFormat) {
  // Test verification with wrong key format specified (PEM for DER file)
  std::string verify_command = "cat " + std::string(message_path) + " | " +
                              std::string(awslc_executable_path) +
                              " dgst -verify " + std::string(pubkey_path) +
                              " -keyform PEM" +  // Wrong format for DER file
                              " -signature " + std::string(signature_path);

  std::string output;
  int result = RunCommand(verify_command, &output);
  EXPECT_NE(0, result);
  EXPECT_TRUE(output.find("Failed to read public key") != std::string::npos);
}

TEST_F(DgstVerifyTest, VerifyWithMissingKeyFile) {
  // Test verification with non-existent key file
  std::string verify_command = "cat " + std::string(message_path) + " | " +
                              std::string(awslc_executable_path) +
                              " dgst -verify nonexistent.key" +
                              " -signature " + std::string(signature_path);

  std::string output;
  int result = RunCommand(verify_command, &output);
  EXPECT_NE(0, result);
  EXPECT_TRUE(output.find("Failed to open public key file") != std::string::npos);
}

TEST_F(DgstVerifyTest, VerifyWithMissingSignatureFile) {
  // Test verification with non-existent signature file
  std::string verify_command = "cat " + std::string(message_path) + " | " +
                              std::string(awslc_executable_path) +
                              " dgst -verify " + std::string(pubkey_path) +
                              " -signature nonexistent.sig";

  std::string output;
  int result = RunCommand(verify_command, &output);
  EXPECT_NE(0, result);
  EXPECT_TRUE(output.find("Failed to open signature file") != std::string::npos);
}

TEST_F(DgstComparisonTest, MD5_stdin) {
  std::string tool_command = "echo hash_this_string | " +
                             std::string(awslc_executable_path) + " md5 > " +
                             out_path_awslc;
  std::string openssl_command = "echo hash_this_string | " +
                                std::string(openssl_executable_path) +
                                " md5 > " + out_path_openssl;

  RunCommandsAndCompareOutput(tool_command, openssl_command, out_path_awslc,
                              out_path_openssl, awslc_output_str,
                              openssl_output_str);

  std::string tool_hash = GetHash(awslc_output_str);
  std::string openssl_hash = GetHash(openssl_output_str);

  EXPECT_EQ(tool_hash, openssl_hash);
}

// Test default digest algorithm (SHA-256)
TEST_F(DgstComparisonTest, DefaultDigestAlgorithm) {
  std::string input_file = std::string(in_path);
  std::ofstream ofs(input_file);
  ofs << "AWS_LC_TEST_STRING_FOR_DIGEST_ALGORITHMS";
  ofs.close();

  // Test SHA-256 (default)
  std::string awslc_command = std::string(awslc_executable_path) +
                              " dgst " + input_file +
                              " > " + out_path_awslc;
  std::string openssl_command = std::string(openssl_executable_path) +
                                " dgst " + input_file +
                                " > " + out_path_openssl;

  RunCommandsAndCompareOutput(awslc_command, openssl_command, out_path_awslc,
                              out_path_openssl, awslc_output_str,
                              openssl_output_str);

  std::string awslc_hash = GetHash(awslc_output_str);
  std::string openssl_hash = GetHash(openssl_output_str);

  EXPECT_EQ(awslc_hash, openssl_hash);

  RemoveFile(input_file.c_str());
}

// Test direct digest algorithm options
TEST_F(DgstComparisonTest, DirectDigestAlgorithms) {
  std::string input_file = std::string(in_path);
  std::ofstream ofs(input_file);
  ofs << "AWS_LC_TEST_STRING_FOR_DIRECT_DIGEST_ALGORITHMS";
  ofs.close();

  // Test all supported hash algorithms with direct options
  struct HashAlgorithm {
    const char* name;
    const char* option;
  };

  HashAlgorithm algorithms[] = {
    {"SHA-1", "-sha1"},
    {"SHA-224", "-sha224"},
    {"SHA-256", "-sha256"},
    {"SHA-384", "-sha384"},
    {"SHA-512", "-sha512"},
    {"SHA3-224", "-sha3-224"},
    {"SHA3-256", "-sha3-256"},
    {"SHA3-384", "-sha3-384"},
    {"SHA3-512", "-sha3-512"}
    // SHAKE algorithms are tested separately with -xoflen
  };

  for (const auto& algo : algorithms) {
    std::string awslc_command = std::string(awslc_executable_path) +
                                " dgst " + algo.option + " " + input_file +
                                " > " + out_path_awslc;
    std::string openssl_command = std::string(openssl_executable_path) +
                                  " dgst " + algo.option + " " + input_file +
                                  " > " + out_path_openssl;

    RunCommandsAndCompareOutput(awslc_command, openssl_command, out_path_awslc,
                                out_path_openssl, awslc_output_str,
                                openssl_output_str);

    std::string awslc_hash = GetHash(awslc_output_str);
    std::string openssl_hash = GetHash(openssl_output_str);

    EXPECT_EQ(awslc_hash, openssl_hash) << "Hash mismatch for " << algo.name;
  }

  RemoveFile(input_file.c_str());
}

// Test SHAKE algorithms with explicit output lengths
TEST_F(DgstComparisonTest, ShakeWithExplicitLength) {
  std::string input_file = std::string(in_path);
  std::ofstream ofs(input_file);
  ofs << "AWS_LC_TEST_STRING_FOR_SHAKE_EXPLICIT_LENGTH";
  ofs.close();

  // Test SHAKE128 with explicit output length (16 bytes)
  std::string awslc_command = std::string(awslc_executable_path) +
                              " dgst -shake128 -xoflen 16 " + input_file +
                              " > " + out_path_awslc;
  std::string openssl_command = std::string(openssl_executable_path) +
                                " dgst -shake128 -xoflen 16 " + input_file +
                                " > " + out_path_openssl;

  RunCommandsAndCompareOutput(awslc_command, openssl_command, out_path_awslc,
                              out_path_openssl, awslc_output_str,
                              openssl_output_str);

  std::string awslc_hash = GetHash(awslc_output_str);
  std::string openssl_hash = GetHash(openssl_output_str);

  EXPECT_EQ(awslc_hash, openssl_hash);
  EXPECT_EQ(awslc_hash.length(), 32UL) << "SHAKE128 output length should be 16 bytes (32 hex chars)";

  // Test SHAKE256 with explicit output length (32 bytes)
  awslc_command = std::string(awslc_executable_path) +
                  " dgst -shake256 -xoflen 32 " + input_file +
                  " > " + out_path_awslc;
  openssl_command = std::string(openssl_executable_path) +
                    " dgst -shake256 -xoflen 32 " + input_file +
                    " > " + out_path_openssl;

  RunCommandsAndCompareOutput(awslc_command, openssl_command, out_path_awslc,
                              out_path_openssl, awslc_output_str,
                              openssl_output_str);

  awslc_hash = GetHash(awslc_output_str);
  openssl_hash = GetHash(openssl_output_str);

  EXPECT_EQ(awslc_hash, openssl_hash);
  EXPECT_EQ(awslc_hash.length(), 64UL) << "SHAKE256 output length should be 32 bytes (64 hex chars)";

  RemoveFile(input_file.c_str());
}


// Test HMAC with direct digest algorithm options
TEST_F(DgstComparisonTest, HMAC_with_direct_digest) {
  std::string input_file = std::string(in_path);
  std::ofstream ofs(input_file);
  ofs << "AWS_LC_TEST_STRING_FOR_HMAC_WITH_DIRECT_DIGEST";
  ofs.close();

  // Test HMAC with SHA-512 using direct option
  std::string awslc_command = std::string(awslc_executable_path) +
                              " dgst -hmac test_key -sha512 " + input_file +
                              " > " + out_path_awslc;
  std::string openssl_command = std::string(openssl_executable_path) +
                                " dgst -hmac test_key -sha512 " + input_file +
                                " > " + out_path_openssl;

  RunCommandsAndCompareOutput(awslc_command, openssl_command, out_path_awslc,
                              out_path_openssl, awslc_output_str,
                              openssl_output_str);

  std::string awslc_hash = GetHash(awslc_output_str);
  std::string openssl_hash = GetHash(openssl_output_str);

  EXPECT_EQ(awslc_hash, openssl_hash);

  RemoveFile(input_file.c_str());
}

// Test invalid digest algorithm
TEST_F(DgstComparisonTest, InvalidDigestAlgorithm) {
  std::string input_file = std::string(in_path);
  std::ofstream ofs(input_file);
  ofs << "AWS_LC_TEST_STRING_FOR_INVALID_DIGEST";
  ofs.close();

  // Test with invalid direct digest algorithm option
  std::string command = std::string(awslc_executable_path) +
                        " dgst -invalid_algorithm " + input_file;

  std::string output;
  int result = RunCommand(command, &output);
  EXPECT_NE(0, result);  // Non-zero exit code indicates failure
  EXPECT_TRUE(output.find("Unknown option") != std::string::npos);

  RemoveFile(input_file.c_str());
}

// Test list option
TEST_F(DgstComparisonTest, ListDigestAlgorithms) {
  // Test the -list option
  std::string command = std::string(awslc_executable_path) + " dgst -list";

  std::string output;
  int result = RunCommand(command, &output);
  EXPECT_EQ(0, result);  // Zero exit code indicates success
  EXPECT_TRUE(output.find("Supported digests:") != std::string::npos);

  // Check that all supported algorithms are listed
  EXPECT_TRUE(output.find("sha1") != std::string::npos);
  EXPECT_TRUE(output.find("sha224") != std::string::npos);
  EXPECT_TRUE(output.find("sha256") != std::string::npos);
  EXPECT_TRUE(output.find("sha384") != std::string::npos);
  EXPECT_TRUE(output.find("sha512") != std::string::npos);
  EXPECT_TRUE(output.find("sha3-224") != std::string::npos);
  EXPECT_TRUE(output.find("sha3-256") != std::string::npos);
  EXPECT_TRUE(output.find("sha3-384") != std::string::npos);
  EXPECT_TRUE(output.find("sha3-512") != std::string::npos);
  EXPECT_TRUE(output.find("shake128") != std::string::npos);
  EXPECT_TRUE(output.find("shake256") != std::string::npos);
}

// Test binary output option
TEST_F(DgstComparisonTest, BinaryOutput) {
  std::string input_file = std::string(in_path);
  std::ofstream ofs(input_file);
  ofs << "AWS_LC_TEST_STRING_FOR_BINARY_OUTPUT";
  ofs.close();

  // Test SHA-256 with binary output
  std::string awslc_command = std::string(awslc_executable_path) +
                              " dgst -sha256 -binary " + input_file +
                              " > " + out_path_awslc;
  std::string openssl_command = std::string(openssl_executable_path) +
                                " dgst -sha256 -binary " + input_file +
                                " > " + out_path_openssl;

  // Execute both commands
  system(awslc_command.c_str());
  system(openssl_command.c_str());

  // Compare binary outputs directly
  std::ifstream awslc_file(out_path_awslc, std::ios::binary);
  std::ifstream openssl_file(out_path_openssl, std::ios::binary);

  std::vector<char> awslc_data((std::istreambuf_iterator<char>(awslc_file)), std::istreambuf_iterator<char>());
  std::vector<char> openssl_data((std::istreambuf_iterator<char>(openssl_file)), std::istreambuf_iterator<char>());

  EXPECT_EQ(awslc_data.size(), openssl_data.size());
  EXPECT_EQ(awslc_data, openssl_data);

  // Test HMAC with binary output
  awslc_command = std::string(awslc_executable_path) +
                  " dgst -hmac test_key -sha256 -binary " + input_file +
                  " > " + out_path_awslc;
  openssl_command = std::string(openssl_executable_path) +
                    " dgst -hmac test_key -sha256 -binary " + input_file +
                    " > " + out_path_openssl;

  // Execute both commands
  system(awslc_command.c_str());
  system(openssl_command.c_str());

  // Compare binary outputs directly
  awslc_file = std::ifstream(out_path_awslc, std::ios::binary);
  openssl_file = std::ifstream(out_path_openssl, std::ios::binary);

  awslc_data = std::vector<char>((std::istreambuf_iterator<char>(awslc_file)), std::istreambuf_iterator<char>());
  openssl_data = std::vector<char>((std::istreambuf_iterator<char>(openssl_file)), std::istreambuf_iterator<char>());

  EXPECT_EQ(awslc_data.size(), openssl_data.size());
  EXPECT_EQ(awslc_data, openssl_data);

  RemoveFile(input_file.c_str());
}

// Test binary output with stdin
TEST_F(DgstComparisonTest, BinaryOutputStdin) {
  // Test SHA-256 with binary output from stdin
  std::string awslc_command = "echo -n binary_test_string | " +
                              std::string(awslc_executable_path) +
                              " dgst -sha256 -binary > " + out_path_awslc;
  std::string openssl_command = "echo -n binary_test_string | " +
                                std::string(openssl_executable_path) +
                                " dgst -sha256 -binary > " + out_path_openssl;

  // Execute both commands
  system(awslc_command.c_str());
  system(openssl_command.c_str());

  // Compare binary outputs directly
  std::ifstream awslc_file(out_path_awslc, std::ios::binary);
  std::ifstream openssl_file(out_path_openssl, std::ios::binary);

  std::vector<char> awslc_data((std::istreambuf_iterator<char>(awslc_file)), std::istreambuf_iterator<char>());
  std::vector<char> openssl_data((std::istreambuf_iterator<char>(openssl_file)), std::istreambuf_iterator<char>());

  EXPECT_EQ(awslc_data.size(), openssl_data.size());
  EXPECT_EQ(awslc_data, openssl_data);
}

// Test binary output with XOF algorithms
TEST_F(DgstComparisonTest, BinaryOutputXOF) {
  std::string input_file = std::string(in_path);
  std::ofstream ofs(input_file);
  ofs << "AWS_LC_TEST_STRING_FOR_BINARY_XOF_OUTPUT";
  ofs.close();

  // Test SHAKE256 with binary output and custom length
  std::string awslc_command = std::string(awslc_executable_path) +
                              " dgst -shake256 -xoflen 64 -binary " + input_file +
                              " > " + out_path_awslc;
  std::string openssl_command = std::string(openssl_executable_path) +
                                " dgst -shake256 -xoflen 64 -binary " + input_file +
                                " > " + out_path_openssl;

  // Execute both commands
  system(awslc_command.c_str());
  system(openssl_command.c_str());

  // Compare binary outputs directly
  std::ifstream awslc_file(out_path_awslc, std::ios::binary);
  std::ifstream openssl_file(out_path_openssl, std::ios::binary);

  std::vector<char> awslc_data((std::istreambuf_iterator<char>(awslc_file)), std::istreambuf_iterator<char>());
  std::vector<char> openssl_data((std::istreambuf_iterator<char>(openssl_file)), std::istreambuf_iterator<char>());

  EXPECT_EQ(awslc_data.size(), 64UL);  // Should be exactly 64 bytes
  EXPECT_EQ(awslc_data, openssl_data);

  RemoveFile(input_file.c_str());
}

// Test XOF algorithms with -xoflen option
TEST_F(DgstComparisonTest, XOF_with_xoflen) {
  std::string input_file = std::string(in_path);
  std::ofstream ofs(input_file);
  ofs << "AWS_LC_TEST_STRING_FOR_XOF_ALGORITHMS";
  ofs.close();

  // Test SHAKE128 with -xoflen 32 (default is 16)
  std::string awslc_command = std::string(awslc_executable_path) +
                              " dgst -shake128 -xoflen 32 " + input_file +
                              " > " + out_path_awslc;
  std::string openssl_command = std::string(openssl_executable_path) +
                                " dgst -shake128 -xoflen 32 " + input_file +
                                " > " + out_path_openssl;

  RunCommandsAndCompareOutput(awslc_command, openssl_command, out_path_awslc,
                              out_path_openssl, awslc_output_str,
                              openssl_output_str);

  std::string awslc_hash = GetHash(awslc_output_str);
  std::string openssl_hash = GetHash(openssl_output_str);

  EXPECT_EQ(awslc_hash, openssl_hash);
  // Verify the output length is 32 bytes (64 hex characters)
  EXPECT_EQ(awslc_hash.length(), 64UL);

  // Test SHAKE256 with -xoflen 64 (default is 32)
  awslc_command = std::string(awslc_executable_path) +
                  " dgst -shake256 -xoflen 64 " + input_file +
                  " > " + out_path_awslc;
  openssl_command = std::string(openssl_executable_path) +
                    " dgst -shake256 -xoflen 64 " + input_file +
                    " > " + out_path_openssl;

  RunCommandsAndCompareOutput(awslc_command, openssl_command, out_path_awslc,
                              out_path_openssl, awslc_output_str,
                              openssl_output_str);

  awslc_hash = GetHash(awslc_output_str);
  openssl_hash = GetHash(openssl_output_str);

  EXPECT_EQ(awslc_hash, openssl_hash);
  // Verify the output length is 64 bytes (128 hex characters)
  EXPECT_EQ(awslc_hash.length(), 128UL);

  RemoveFile(input_file.c_str());
}

// Test XOF algorithms with stdin and -xoflen option
TEST_F(DgstComparisonTest, XOF_with_xoflen_stdin) {
  // Test SHAKE128 with -xoflen 32 using stdin
  std::string awslc_command = "echo xof_test_string | " +
                              std::string(awslc_executable_path) +
                              " dgst -shake128 -xoflen 32 > " + out_path_awslc;
  std::string openssl_command = "echo xof_test_string | " +
                                std::string(openssl_executable_path) +
                                " dgst -shake128 -xoflen 32 > " + out_path_openssl;

  RunCommandsAndCompareOutput(awslc_command, openssl_command, out_path_awslc,
                              out_path_openssl, awslc_output_str,
                              openssl_output_str);

  std::string awslc_hash = GetHash(awslc_output_str);
  std::string openssl_hash = GetHash(openssl_output_str);

  EXPECT_EQ(awslc_hash, openssl_hash);
  // Verify the output length is 32 bytes (64 hex characters)
  EXPECT_EQ(awslc_hash.length(), 64UL);

  // Test SHAKE256 with -xoflen 64 using stdin
  awslc_command = "echo xof_test_string | " +
                  std::string(awslc_executable_path) +
                  " dgst -shake256 -xoflen 64 > " + out_path_awslc;
  openssl_command = "echo xof_test_string | " +
                    std::string(openssl_executable_path) +
                    " dgst -shake256 -xoflen 64 > " + out_path_openssl;

  RunCommandsAndCompareOutput(awslc_command, openssl_command, out_path_awslc,
                              out_path_openssl, awslc_output_str,
                              openssl_output_str);

  awslc_hash = GetHash(awslc_output_str);
  openssl_hash = GetHash(openssl_output_str);

  EXPECT_EQ(awslc_hash, openssl_hash);
  // Verify the output length is 64 bytes (128 hex characters)
  EXPECT_EQ(awslc_hash.length(), 128UL);
}

// Test invalid -xoflen values
TEST_F(DgstComparisonTest, InvalidXoflen) {
  std::string input_file = std::string(in_path);
  std::ofstream ofs(input_file);
  ofs << "AWS_LC_TEST_STRING_FOR_INVALID_XOFLEN";
  ofs.close();

  // Test with invalid -xoflen value (non-numeric)
  std::string command = std::string(awslc_executable_path) +
                        " dgst -shake128 -xoflen invalid " + input_file;

  std::string output;
  int result = RunCommand(command, &output);
  EXPECT_NE(0, result);  // Non-zero exit code indicates failure
  EXPECT_TRUE(output.find("Invalid XOF output length") != std::string::npos);

  // Test with -xoflen 0 (should fail)
  command = std::string(awslc_executable_path) +
            " dgst -shake128 -xoflen 0 " + input_file;

  output.clear();
  result = RunCommand(command, &output);
  EXPECT_NE(0, result);  // Non-zero exit code indicates failure
  EXPECT_TRUE(output.find("XOF output length must be greater than 0") != std::string::npos);

  RemoveFile(input_file.c_str());
}

// Test -xoflen with non-XOF algorithms (should work but ignore the length)
TEST_F(DgstComparisonTest, XoflenWithNonXOF) {
  std::string input_file = std::string(in_path);
  std::ofstream ofs(input_file);
  ofs << "AWS_LC_TEST_STRING_FOR_XOFLEN_WITH_NON_XOF";
  ofs.close();

  // Test SHA-256 with -xoflen (should be ignored)
  std::string awslc_command = std::string(awslc_executable_path) +
                              " dgst -sha256 -xoflen 64 " + input_file +
                              " > " + out_path_awslc;
  std::string openssl_command = std::string(openssl_executable_path) +
                                " dgst -sha256 " + input_file +
                                " > " + out_path_openssl;

  RunCommandsAndCompareOutput(awslc_command, openssl_command, out_path_awslc,
                              out_path_openssl, awslc_output_str,
                              openssl_output_str);

  std::string awslc_hash = GetHash(awslc_output_str);
  std::string openssl_hash = GetHash(openssl_output_str);

  EXPECT_EQ(awslc_hash, openssl_hash);
  // SHA-256 output should still be 32 bytes (64 hex characters)
  EXPECT_EQ(awslc_hash.length(), 64UL);

  RemoveFile(input_file.c_str());
}
