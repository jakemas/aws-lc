# OpenSSL Tools for AWS-LC
*Files expected to change*

Current status:
* Contains implementation for OpenSSL x509, rsa, md5, and dgst tools
  * x509 options: -in -out, -req, -signkey, -modulus, -days, -dates,
    -checkend, -noout (x509.cc)
  * rsa options: -in, -out, -noout, -modulus (rsa.cc)
  * md5 options: N/A (md5.cc)
  * dgst options: (dgst.cc)
    * -help: Display option summary
    * -hmac <key>: Create a hashed MAC with the corresponding key
    * -verify <filename>: Verify signature using public key file
    * -signature <filename>: Signature file to verify
    * -keyform <format>: Key format (DER/PEM), defaults to DER
    * -digest <algorithm>: Specify message digest algorithm
    * -list: List supported message digest algorithms
    * -xoflen <length>: Set output length for XOF algorithms (shake128, shake256)
    * -binary: Output the digest or signature in binary form
    * Direct digest algorithm options: -sha1, -sha224, -sha256, -sha384, -sha512, -sha3-224, -sha3-256, -sha3-384, -sha3-512, -shake128, -shake256
* Unit, integration, and OpenSSL comparison tests (x509_test.cc, rsa_test.cc, md5_test.cc, dgst_test.cc)
  * OpenSSL comparison tests require environment variables for both AWS-LC ("AWSLC_TOOL_PATH") and OpenSSL ("OPENSSL_TOOL_PATH") tools

## Digest Tool (dgst)

The AWS-LC digest tool provides message digest and signature verification capabilities compatible with OpenSSL's dgst command. It supports:

1. **Message Digest Operations**
   * Calculate message digests using various algorithms (SHA-1, SHA-2, SHA-3, SHAKE)
   * Process input from both files and stdin
   * Output in hex or binary format

2. **HMAC Functionality**
   * Create HMACs with provided keys
   * Support for standard digest algorithms (SHA-1, SHA-2)
   * SHA-3 and SHAKE algorithms are not currently supported for HMAC

3. **Signature Verification**
   * Verify signatures using public keys
   * Support for different key formats (DER/PEM)
   * Compatible with multiple signature algorithms:
     * RSA
     * ECDSA
     * DSA
     * EdDSA (Ed25519, Ed448)
     * ML-DSA (post-quantum digital signature algorithm)

4. **XOF Support**
   * Customizable output length for SHAKE128 and SHAKE256 algorithms
   * Default output lengths: 16 bytes for SHAKE128, 32 bytes for SHAKE256

### Algorithm Support Table

| Algorithm | Message Digest | HMAC | Signature Verification |
|-----------|:--------------:|:----:|:----------------------:|
| SHA-1     | ✓              | ✓    | ✓                      |
| SHA-224   | ✓              | ✓    | ✓                      |
| SHA-256   | ✓              | ✓    | ✓                      |
| SHA-384   | ✓              | ✓    | ✓                      |
| SHA-512   | ✓              | ✓    | ✓                      |
| SHA3-224  | ✓              | ✗    | ✓                      |
| SHA3-256  | ✓              | ✗    | ✓                      |
| SHA3-384  | ✓              | ✗    | ✓                      |
| SHA3-512  | ✓              | ✗    | ✓                      |
| SHAKE128  | ✓              | ✗    | ✗                      |
| SHAKE256  | ✓              | ✗    | ✗                      |

### Example Usage

Calculate a SHA-256 digest:
```
echo "message" | openssl-tool dgst -sha256
```

Create an HMAC with SHA-512:
```
echo "message" | openssl-tool dgst -hmac "key" -sha512
```

Verify a signature:
```
echo "message" | openssl-tool dgst -verify public_key.der -signature signature.bin
```

Use SHAKE256 with custom output length:
```
echo "message" | openssl-tool dgst -shake256 -xoflen 64
```

Output digest in binary form:
```
echo "message" | openssl-tool dgst -sha256 -binary > digest.bin
```
