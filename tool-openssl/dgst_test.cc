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
  return str.substr(pos + 1);
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
