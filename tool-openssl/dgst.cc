// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <fcntl.h>
#include <string.h>
#include <iostream>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include "internal.h"

namespace bssl {

class ScopedEVP_PKEY_CTX {
 public:
  ScopedEVP_PKEY_CTX() = default;
  ScopedEVP_PKEY_CTX(EVP_PKEY_CTX *ctx) : ctx_(ctx) {}
  ~ScopedEVP_PKEY_CTX() { EVP_PKEY_CTX_free(ctx_); }

  EVP_PKEY_CTX *get() { return ctx_; }
  EVP_PKEY_CTX **ptr() { return &ctx_; }

  void reset(EVP_PKEY_CTX *ctx = nullptr) {
    if (ctx_) {
      EVP_PKEY_CTX_free(ctx_);
    }
    ctx_ = ctx;
  }

  explicit operator bool() const { return ctx_ != nullptr; }

 private:
  EVP_PKEY_CTX *ctx_ = nullptr;
};

}  // namespace bssl

// Helper function to get EVP_MD from digest name
static const EVP_MD* GetDigestFromName(const std::string &digest_name) {
  if (digest_name == "sha1") {
    return EVP_sha1();
  } else if (digest_name == "sha224") {
    return EVP_sha224();
  } else if (digest_name == "sha256") {
    return EVP_sha256();
  } else if (digest_name == "sha384") {
    return EVP_sha384();
  } else if (digest_name == "sha512") {
    return EVP_sha512();
  } else if (digest_name == "sha3-224") {
    return EVP_sha3_224();
  } else if (digest_name == "sha3-256") {
    return EVP_sha3_256();
  } else if (digest_name == "sha3-384") {
    return EVP_sha3_384();
  } else if (digest_name == "sha3-512") {
    return EVP_sha3_512();
  } else if (digest_name == "shake128") {
    return EVP_shake128();
  } else if (digest_name == "shake256") {
    return EVP_shake256();
  }
  return nullptr;
}

// Get list of supported digest algorithms
static void PrintSupportedDigests() {
  fprintf(stdout, "Supported digests:\n");
  fprintf(stdout, "  sha1\n");
  fprintf(stdout, "  sha224\n");
  fprintf(stdout, "  sha256\n");
  fprintf(stdout, "  sha384\n");
  fprintf(stdout, "  sha512\n");
  fprintf(stdout, "  sha3-224\n");
  fprintf(stdout, "  sha3-256\n");
  fprintf(stdout, "  sha3-384\n");
  fprintf(stdout, "  sha3-512\n");
  fprintf(stdout, "  shake128\n");
  fprintf(stdout, "  shake256\n");
}

// MD5 command currently only supports stdin
static const argument_t kArguments[] = {
    {"-help", kBooleanArgument, "Display option summary"},
    {"-hmac", kOptionalArgument,
     "Create a hashed MAC with the corresponding key"},
    {"-verify", kRequiredArgument, "Verify signature using public key file"},
    {"-signature", kRequiredArgument, "Signature file to verify"},
    {"-keyform", kOptionalArgument, "Key format (DER/PEM), defaults to DER"},
    {"-digest", kRequiredArgument, "Specify message digest algorithm"},
    {"-list", kBooleanArgument, "List supported message digest algorithms"},
    {"-xoflen", kRequiredArgument, "Set output length for XOF algorithms (shake128, shake256)"},
    {"-binary", kBooleanArgument, "Output the digest or signature in binary form"},
    {"-sha1", kBooleanArgument, "Use SHA-1 digest algorithm"},
    {"-sha224", kBooleanArgument, "Use SHA-224 digest algorithm"},
    {"-sha256", kBooleanArgument, "Use SHA-256 digest algorithm"},
    {"-sha384", kBooleanArgument, "Use SHA-384 digest algorithm"},
    {"-sha512", kBooleanArgument, "Use SHA-512 digest algorithm"},
    {"-sha3-224", kBooleanArgument, "Use SHA3-224 digest algorithm"},
    {"-sha3-256", kBooleanArgument, "Use SHA3-256 digest algorithm"},
    {"-sha3-384", kBooleanArgument, "Use SHA3-384 digest algorithm"},
    {"-sha3-512", kBooleanArgument, "Use SHA3-512 digest algorithm"},
    {"-shake128", kBooleanArgument, "Use SHAKE-128 digest algorithm"},
    {"-shake256", kBooleanArgument, "Use SHAKE-256 digest algorithm"},
    {"", kOptionalArgument, ""}};

static bool read_signature_file(const std::string &filename, std::vector<uint8_t> *out) {
  ScopedFD fd(OpenFD(filename.c_str(), O_RDONLY | O_BINARY));
  if (fd.get() < 0) {
    fprintf(stderr, "Failed to open signature file %s: %s\n", filename.c_str(),
            strerror(errno));
    return false;
  }

  static const size_t kBufSize = 1024;
  std::unique_ptr<uint8_t[]> buf(new uint8_t[kBufSize]);

  for (;;) {
    size_t n;
    if (!ReadFromFD(fd.get(), &n, buf.get(), kBufSize)) {
      fprintf(stderr, "Failed to read from %s: %s\n", filename.c_str(),
              strerror(errno));
      return false;
    }

    if (n == 0) {
      break;
    }

    out->insert(out->end(), buf.get(), buf.get() + n);
  }

  return true;
}

static bool read_public_key(const std::string &filename, bool is_der,
                          bssl::UniquePtr<EVP_PKEY> *out) {
  ScopedFD fd(OpenFD(filename.c_str(), O_RDONLY | O_BINARY));
  if (fd.get() < 0) {
    fprintf(stderr, "Failed to open public key file %s: %s\n", filename.c_str(),
            strerror(errno));
    return false;
  }

  bssl::UniquePtr<BIO> bio(BIO_new_fd(fd.get(), BIO_NOCLOSE));
  if (!bio) {
    fprintf(stderr, "Failed to create BIO\n");
    return false;
  }

  EVP_PKEY *pkey = nullptr;
  if (is_der) {
    pkey = d2i_PUBKEY_bio(bio.get(), nullptr);
  } else {
    pkey = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
  }

  if (!pkey) {
    fprintf(stderr, "Failed to read public key\n");
    return false;
  }

  *out = bssl::UniquePtr<EVP_PKEY>(pkey);
  return true;
}

static bool verify_signature(EVP_PKEY *pkey, const EVP_MD *digest,
                           const uint8_t *msg, size_t msg_len,
                           const uint8_t *sig, size_t sig_len) {
  if (EVP_PKEY_id(pkey) == EVP_PKEY_PQDSA) {
    // For ML-DSA in pure mode, we use EVP_DigestVerify
    bssl::ScopedEVP_MD_CTX md_ctx;
    if (!EVP_DigestVerifyInit(md_ctx.get(), nullptr, nullptr, nullptr, pkey)) {
      fprintf(stderr, "Failed to initialize verification\n");
      return false;
    }

    // Verify the signature
    int verify_result = EVP_DigestVerify(md_ctx.get(), sig, sig_len, msg, msg_len);
    if (verify_result != 1) {
      fprintf(stderr, "Verification Failure\n");
      return false;
    }
    fprintf(stdout, "Verified OK\n");
    return true;
  } else {
    // Standard digest-based verification for other key types
    bssl::ScopedEVP_MD_CTX md_ctx;
    EVP_PKEY_CTX *pkey_ctx = nullptr;
    if (!EVP_DigestVerifyInit(md_ctx.get(), &pkey_ctx, digest, nullptr, pkey)) {
      fprintf(stderr, "Failed to initialize verification\n");
      return false;
    }

    if (!EVP_DigestVerifyUpdate(md_ctx.get(), msg, msg_len)) {
      fprintf(stderr, "Failed to update verification\n");
      return false;
    }

    int verify_result = EVP_DigestVerifyFinal(md_ctx.get(), sig, sig_len);
    if (verify_result != 1) {
      fprintf(stderr, "Verification Failure\n");
    } else {
      fprintf(stdout, "Verified OK\n");
    }
    return verify_result == 1;
  }
}

static bool dgst_file_op(const std::string &filename, const int fd,
                         const EVP_MD *digest, size_t xof_len = 0,
                         bool binary_output = false) {
  // Set default XOF lengths if not specified
  if (xof_len == 0) {
    if (EVP_MD_type(digest) == NID_shake128) {
      xof_len = 16;  // Default for SHAKE128 is 16 bytes (128 bits)
    } else if (EVP_MD_type(digest) == NID_shake256) {
      xof_len = 32;  // Default for SHAKE256 is 32 bytes (256 bits)
    }
  }
  static const size_t kBufSize = 8192;
  std::unique_ptr<uint8_t[]> buf(new uint8_t[kBufSize]);

  bssl::ScopedEVP_MD_CTX ctx;
  if (!EVP_DigestInit_ex(ctx.get(), digest, nullptr)) {
    fprintf(stderr, "Failed to initialize EVP_MD_CTX.\n");
    return false;
  }

  for (;;) {
    size_t n;
    if (!ReadFromFD(fd, &n, buf.get(), kBufSize)) {
      fprintf(stderr, "Failed to read from %s: %s\n", filename.c_str(),
              strerror(errno));
      return false;
    }

    if (n == 0) {
      break;
    }

    if (!EVP_DigestUpdate(ctx.get(), buf.get(), n)) {
      fprintf(stderr, "Failed to update hash.\n");
      return false;
    }
  }

  // Check if this is an XOF algorithm (SHAKE128 or SHAKE256) and xof_len is specified
  bool is_xof = (EVP_MD_flags(digest) & EVP_MD_FLAG_XOF) != 0;

  uint8_t hash[EVP_MAX_MD_SIZE];
  unsigned hash_len;

  if (is_xof && xof_len > 0) {
    // For XOF algorithms with specified length, use EVP_DigestFinalXOF
    if (!EVP_DigestFinalXOF(ctx.get(), hash, xof_len)) {
      fprintf(stderr, "Failed to finish XOF hash.\n");
      return false;
    }
    hash_len = xof_len;
  } else {
    // For regular algorithms or XOF without specified length, use EVP_DigestFinal_ex
    if (!EVP_DigestFinal_ex(ctx.get(), hash, &hash_len)) {
      fprintf(stderr, "Failed to finish hash.\n");
      return false;
    }
  }

  // Handle binary output
  if (binary_output) {
    // Write binary hash directly to stdout
    fwrite(hash, 1, hash_len, stdout);
  } else {
    // Print digest output in hex format. OpenSSL outputs the digest name with files, but not with stdin.
    if (fd != 0) {
      fprintf(stdout, "%s(%s)= ", EVP_MD_get0_name(digest), filename.c_str());
    } else {
      fprintf(stdout, "(%s)= ", filename.c_str());
    }
    for (size_t i = 0; i < hash_len; i++) {
      fprintf(stdout, "%02x", hash[i]);
    }
    fprintf(stdout, "\n");
  }
  return true;
}

static bool hmac_file_op(const std::string &filename, const int fd,
                         const EVP_MD *digest, const char *hmac_key,
                         const size_t hmac_key_len, bool binary_output = false) {
  static const size_t kBufSize = 8192;
  std::unique_ptr<uint8_t[]> buf(new uint8_t[kBufSize]);

  // Use HMAC_* for all algorithms
  // Note: SHA-3 algorithms are not currently supported for HMAC
  int md_type = EVP_MD_type(digest);
  if (md_type == NID_sha3_224 || md_type == NID_sha3_256 ||
      md_type == NID_sha3_384 || md_type == NID_sha3_512 ||
      md_type == NID_shake128 || md_type == NID_shake256) {
    fprintf(stderr, "HMAC is not supported with SHA-3 or SHAKE algorithms.\n");
    return false;
  }

  // Use HMAC_* for supported algorithms
    bssl::ScopedHMAC_CTX ctx;
    if (!HMAC_Init_ex(ctx.get(), hmac_key, hmac_key_len, digest, nullptr)) {
      fprintf(stderr, "Failed to initialize HMAC_Init_ex.\n");
      return false;
    }

    // Update |buf| from file continuously.
    for (;;) {
      size_t n;
      if (!ReadFromFD(fd, &n, buf.get(), kBufSize)) {
        fprintf(stderr, "Failed to read from %s: %s\n", filename.c_str(),
                strerror(errno));
        return false;
      }

      if (n == 0) {
        break;
      }

      if (!HMAC_Update(ctx.get(), buf.get(), n)) {
        fprintf(stderr, "Failed to update HMAC.\n");
        return false;
      }
    }

    const unsigned expected_mac_len = EVP_MD_size(digest);
    std::unique_ptr<uint8_t[]> mac(new uint8_t[expected_mac_len]);
    unsigned mac_len;
    if (!HMAC_Final(ctx.get(), mac.get(), &mac_len)) {
      fprintf(stderr, "Failed to finalize HMAC.\n");
      return false;
    }

    // Handle binary output
    if (binary_output) {
      // Write binary MAC directly to stdout
      fwrite(mac.get(), 1, mac_len, stdout);
    } else {
      // Print HMAC output in hex format. OpenSSL outputs the digest name with files, but not with stdin.
      if (fd != 0) {
        fprintf(stdout, "HMAC-%s(%s)= ", EVP_MD_get0_name(digest),
                filename.c_str());
      } else {
        fprintf(stdout, "(%s)= ", filename.c_str());
      }
      for (size_t i = 0; i < expected_mac_len; i++) {
        fprintf(stdout, "%02x", mac[i]);
      }
      fprintf(stdout, "\n");
    }
    return true;
}

static bool dgst_tool_op(const args_list_t &args, const EVP_MD *digest) {
  std::string verify_key_file;
  std::string signature_file;
  bool is_der = true;  // Default to DER format
  bool binary_output = false;  // Default to hex output
  std::vector<std::string> file_inputs;
  size_t xof_len = 0;  // Output length for XOF algorithms, 0 means use default

  // Default is SHA-256 if no digest is specified
  if (digest == nullptr) {
    digest = EVP_sha256();
  }

  // HMAC keys can be empty, but C++ std::string has no way to differentiate
  // between null and empty.
  const char *hmac_key = nullptr;
  size_t hmac_key_len = 0;

  bool verify_mode = false;

  auto it = args.begin();
  while (it != args.end()) {
    const std::string &arg = *it;
    if (!arg.empty() && arg[0] != '-') {
      // Any input without a '-' prefix is parsed as a file. This
      // also marks the end of any option input.
      while (it != args.end()) {
        if (!(*it).empty()) {
          file_inputs.push_back(*it);
        }
        it++;
      }
      break;
    }

    if (!arg.empty() && arg[0] == '-') {
      const std::string option = arg.substr(1);
      if (option == "help") {
        PrintUsage(kArguments);
        return false;
      } else if (option == "hmac") {
        // Read next argument as key string.
        it++;
        // HMAC allows for empty keys.
        if (it != args.end()) {
          hmac_key = (*it).c_str();
          hmac_key_len = (*it).length();
        } else {
          fprintf(stderr,
                  "dgst: Option -hmac needs a value\n"
                  "dgst: Use -help for summary.\n");
          return false;
        }
      } else if (option == "verify") {
        // Read next argument as public key file
        it++;
        if (it == args.end()) {
          fprintf(stderr,
                  "dgst: Option -verify needs a value\n"
                  "dgst: Use -help for summary.\n");
          return false;
        }
        verify_key_file = *it;
        verify_mode = true;
      } else if (option == "signature") {
        // Read next argument as signature file
        it++;
        if (it == args.end()) {
          fprintf(stderr,
                  "dgst: Option -signature needs a value\n"
                  "dgst: Use -help for summary.\n");
          return false;
        }
        signature_file = *it;
      } else if (option == "keyform") {
        // Read next argument as key format
        it++;
        if (it == args.end()) {
          fprintf(stderr,
                  "dgst: Option -keyform needs a value\n"
                  "dgst: Use -help for summary.\n");
          return false;
        }
        if (*it == "PEM") {
          is_der = false;
        } else if (*it == "DER") {
          is_der = true;
        } else {
          fprintf(stderr, "Invalid key format. Use PEM or DER.\n");
          return false;
        }
      } else if (option == "digest") {
        // Read next argument as digest algorithm
        it++;
        if (it == args.end()) {
          fprintf(stderr,
                  "dgst: Option -digest needs a value\n"
                  "dgst: Use -help for summary.\n");
          return false;
        }

        const std::string &digest_name = *it;
        digest = GetDigestFromName(digest_name);
        if (digest == nullptr) {
          fprintf(stderr, "Unknown digest algorithm: %s\n", digest_name.c_str());
          return false;
        }
      } else if (option == "xoflen") {
        // Read next argument as XOF output length
        it++;
        if (it == args.end()) {
          fprintf(stderr,
                  "dgst: Option -xoflen needs a value\n"
                  "dgst: Use -help for summary.\n");
          return false;
        }

        // Parse xof_len without using exceptions
        char *endptr;
        unsigned long value = strtoul(it->c_str(), &endptr, 10);

        // Check for conversion errors
        if (*endptr != '\0' || endptr == it->c_str()) {
          fprintf(stderr, "Invalid XOF output length: %s\n", it->c_str());
          return false;
        }

        if (value == 0) {
          fprintf(stderr, "XOF output length must be greater than 0\n");
          return false;
        }

        xof_len = value;
      }
      // List supported digest algorithms
      else if (option == "list") {
        PrintSupportedDigests();
        return true;
      }
      else if (option == "binary") {
        binary_output = true;
      }
      // Direct digest algorithm options
      else if (option == "sha1" || option == "sha224" || option == "sha256" ||
               option == "sha384" || option == "sha512" || option == "sha3-224" ||
               option == "sha3-256" || option == "sha3-384" || option == "sha3-512" ||
               option == "shake128" || option == "shake256") {
        digest = GetDigestFromName(option);
      } else {
        fprintf(stderr, "Unknown option '%s'.\n", option.c_str());
        return false;
      }
    } else {
      // Empty input. OpenSSL continues processing the next file even when
      // provided an invalid file.
      fprintf(stderr, "Failed to read from empty input.");
    }

    // Increment while loop.
    it++;
  }

  if (verify_mode) {
    if (signature_file.empty()) {
      fprintf(stderr, "Signature file (-signature) required for verification\n");
      return false;
    }

    // Read the public key
    bssl::UniquePtr<EVP_PKEY> pkey;
    if (!read_public_key(verify_key_file, is_der, &pkey)) {
      return false;
    }

    // Read the signature
    std::vector<uint8_t> signature;
    if (!read_signature_file(signature_file, &signature)) {
      return false;
    }

    // Use stdin if no files are provided
    if (file_inputs.empty()) {
      std::string file_name = "stdin";
      int fd = 0;

      // Read the message to verify
      std::vector<uint8_t> message;
      static const size_t kBufSize = 8192;
      std::unique_ptr<uint8_t[]> buf(new uint8_t[kBufSize]);

      for (;;) {
        size_t n;
        if (!ReadFromFD(fd, &n, buf.get(), kBufSize)) {
          fprintf(stderr, "Failed to read from stdin\n");
          return false;
        }

        if (n == 0) {
          break;
        }

        message.insert(message.end(), buf.get(), buf.get() + n);
      }

      return verify_signature(pkey.get(), digest, message.data(), message.size(),
                            signature.data(), signature.size());
    }

    // Verify each input file
    for (const auto &file_name : file_inputs) {
      std::vector<uint8_t> message;
      ScopedFD fd(OpenFD(file_name.c_str(), O_RDONLY | O_BINARY));
      if (fd.get() < 0) {
        fprintf(stderr, "Failed to open %s: %s\n", file_name.c_str(),
                strerror(errno));
        return false;
      }

      static const size_t kBufSize = 8192;
      std::unique_ptr<uint8_t[]> buf(new uint8_t[kBufSize]);

      for (;;) {
        size_t n;
        if (!ReadFromFD(fd.get(), &n, buf.get(), kBufSize)) {
          fprintf(stderr, "Failed to read from %s: %s\n", file_name.c_str(),
                  strerror(errno));
          return false;
        }

        if (n == 0) {
          break;
        }

        message.insert(message.end(), buf.get(), buf.get() + n);
      }

      if (!verify_signature(pkey.get(), digest, message.data(), message.size(),
                          signature.data(), signature.size())) {
        return false;
      }
    }

    return true;
  }

  // Regular digest mode
  // Use stdin if no files are provided.
  if (file_inputs.empty()) {
    // 0 denotes stdin.
    std::string file_name = "stdin";
    int fd = 0;
    if (hmac_key) {
      if (!hmac_file_op(file_name, fd, digest, hmac_key, hmac_key_len, binary_output)) {
        return false;
      }
    } else {
      if (!dgst_file_op(file_name, fd, digest, xof_len, binary_output)) {
        return false;
      }
    }
    return true;
  }

  // Do the dgst operation on all file inputs.
  for (const auto &file_name : file_inputs) {
    ScopedFD scoped_fd = OpenFD(file_name.c_str(), O_RDONLY | O_BINARY);
    int fd = scoped_fd.get();
    if (hmac_key) {
      if (!hmac_file_op(file_name, fd, digest, hmac_key, hmac_key_len, binary_output)) {
        return false;
      }
    } else {
      if (!dgst_file_op(file_name, fd, digest, xof_len, binary_output)) {
        return false;
      }
    }
  }

  return true;
}

bool dgstTool(const args_list_t &args) { return dgst_tool_op(args, nullptr); }
bool md5Tool(const args_list_t &args) { return dgst_tool_op(args, EVP_md5()); }
