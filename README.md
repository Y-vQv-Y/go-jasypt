# go-jasypt

> Go implementation of [Jasypt](http://www.jasypt.org/) (Java Simplified Encryption) — fully compatible with Java jasypt 1.9.3.

**go-jasypt** is a Go library and CLI tool for Password-Based Encryption (PBE) that can encrypt and decrypt data interchangeably with the Java jasypt library. Go-encrypted data can be decrypted by Java jasypt, and vice versa.

---

## ✅ Cross-Language Compatibility Verified

| Direction | Algorithm | Encoding | Status |
|-----------|-----------|----------|--------|
| Java → Go | `PBEWithMD5AndDES` | Base64 | ✅ |
| Go → Java | `PBEWithMD5AndDES` | Base64 | ✅ |
| Java → Go | `PBEWITHHMACSHA512ANDAES_256` | Base64 | ✅ |
| Go → Java | `PBEWITHHMACSHA512ANDAES_256` | Base64 | ✅ |
| Java → Go | `PBEWITHHMACSHA512ANDAES_256` | Hex | ✅ |
| Go → Java | `PBEWITHHMACSHA512ANDAES_256` | Hex | ✅ |

---

## Installation

### CLI Binary

```bash
# Build from source
git clone https://github.com/go-jasypt/jasypt.git
cd jasypt
go build -o jasypt-go ./cmd/jasypt
```

### Go Library

```bash
go get github.com/go-jasypt/jasypt
```

**Requirements:** Go 1.21+ (only standard library + `golang.org/x/crypto` + `golang.org/x/text`)

---

## Quick Start

### CLI Usage

```bash
# Encrypt (matching Java jasypt CLI parameter names)
jasypt-go encrypt input="Hello World" password="mySecretKey"

# Decrypt
jasypt-go decrypt input="encryptedBase64String" password="mySecretKey"

# Strong encryption with AES-256 + Random IV
jasypt-go encrypt input="Sensitive Data" password="mySecretKey" \
    algorithm=PBEWITHHMACSHA512ANDAES_256 \
    keyObtentionIterations=1000 \
    ivGeneratorClassName=RandomIvGenerator \
    saltGeneratorClassName=RandomSaltGenerator

# Hexadecimal output
jasypt-go encrypt input="Hello" password="secret" stringOutputType=hexadecimal
```

### Go API

```go
package main

import (
    "fmt"
    "github.com/go-jasypt/jasypt/iv"
    "github.com/go-jasypt/jasypt/pbe"
    "github.com/go-jasypt/jasypt/salt"
)

func main() {
    // --- Simplest way (PBEWithMD5AndDES) ---
    config := pbe.DefaultConfig()
    config.Password = "mySecretKey"

    enc, _ := pbe.NewStringEncryptor(config)
    encrypted, _ := enc.Encrypt("Hello World")
    decrypted, _ := enc.Decrypt(encrypted)

    fmt.Println(encrypted) // Base64 string
    fmt.Println(decrypted) // "Hello World"

    // --- Advanced: AES-256 with random IV ---
    config2 := &pbe.Config{
        Algorithm:              "PBEWITHHMACSHA512ANDAES_256",
        Password:               "PILLAR-PLUS-SECRET",
        KeyObtentionIterations: 1000,
        SaltGenerator:          salt.NewRandomGenerator(),
        IvGenerator:            iv.NewRandomGenerator(),
        StringOutputType:       "base64",
    }

    enc2, _ := pbe.NewStringEncryptor(config2)
    result, _ := enc2.Encrypt("Sensitive Data")
    original, _ := enc2.Decrypt(result)
    fmt.Println(original) // "Sensitive Data"
}
```

### Using Convenience Encryptors (like jasypt's `util.text`)

```go
import "github.com/go-jasypt/jasypt/text"

// BasicTextEncryptor — PBEWithMD5AndDES
basic := text.NewBasicTextEncryptor()
basic.SetPassword("password")
encrypted, _ := basic.Encrypt("hello")
decrypted, _ := basic.Decrypt(encrypted)
```

---

## CLI Arguments

All argument names match the Java jasypt CLI (`org.jasypt.intf.cli`).

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `input` | ✅ Yes | — | Message to encrypt/decrypt |
| `password` | ✅ Yes | — | Encryption password |
| `algorithm` | No | `PBEWithMD5AndDES` | PBE algorithm name |
| `keyObtentionIterations` | No | `1000` | Key derivation iterations |
| `saltGeneratorClassName` | No | `RandomSaltGenerator` | `RandomSaltGenerator`, `FixedSaltGenerator`, `ZeroSaltGenerator` |
| `ivGeneratorClassName` | No | `NoIvGenerator` | `RandomIvGenerator`, `NoIvGenerator`, `FixedIvGenerator` |
| `stringOutputType` | No | `base64` | `base64` or `hexadecimal` |
| `providerName` | No | — | Ignored (for Java CLI compatibility) |
| `providerClassName` | No | — | Ignored (for Java CLI compatibility) |
| `verbose` | No | `true` | Verbose output |

---

## Supported Algorithms

| Algorithm | Key Derivation | Key Length | Block Size | Provider |
|-----------|---------------|------------|------------|----------|
| `PBEWithMD5AndDES` | PBKDF1 (MD5) | 8 bytes | 8 bytes | JVM Built-in |
| `PBEWithSHA1AndDESede` | PKCS#12 (SHA-1) | 24 bytes | 8 bytes | JVM Built-in |
| `PBEWITHHMACSHA512ANDAES_256` | PBKDF2 (HMAC-SHA-512) | 32 bytes | 16 bytes | BouncyCastle |

> **Note:** Algorithm names are case-insensitive. `PBEWITHHMACSHA512ANDAES_256` requires BouncyCastle on the Java side but works directly in Go.

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│                    CLI / API                      │
│  ┌─────────────────┐  ┌────────────────────────┐ │
│  │ BasicTextEncryptor│  │  StringEncryptor       │ │
│  │ (convenience)    │  │  (UTF-8 ↔ Base64/Hex)  │ │
│  └────────┬────────┘  └───────────┬────────────┘ │
│           │                       │               │
│  ┌────────┴───────────────────────┴────────────┐ │
│  │            ByteEncryptor                     │ │
│  │  · CBC Cipher (DES / AES)                   │ │
│  │  · PKCS#7 Padding                           │ │
│  │  · Key Derivation (PBKDF1 / PBKDF2)         │ │
│  │  · Output: [salt][iv][ciphertext]           │ │
│  └──────────────┬──────────────┬───────────────┘ │
│                 │              │                  │
│  ┌──────────────┴──────┐ ┌────┴───────────────┐ │
│  │   SaltGenerator      │ │   IvGenerator      │ │
│  │ · Random / Fixed     │ │ · Random / No /    │ │
│  │ · Zero              │ │   Fixed            │ │
│  └─────────────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────┘
```

### Key Design Decisions for Java Compatibility

1. **Password encoding**: NFC normalization is applied, then the password is converted to bytes. The conversion method depends on the algorithm:
   - `CHAR_TRUNC`: Each rune truncated to low 8 bits (SunJCE behavior)
   - `UTF8`: Standard UTF-8 encoding (BouncyCastle behavior)

2. **Output format**: `[salt(N bytes)] + [iv(M bytes)] + [ciphertext]` — salt first, then IV, then encrypted data. This matches jasypt's `CommonUtils.appendArrays()` order.

3. **IV handling**: For PBKDF1 algorithms (e.g., `PBEWithMD5AndDES`), the IV is derived from the key derivation output. For PBKDF2 algorithms (e.g., `PBEWITHHMACSHA512ANDAES_256`), the IV is provided externally and prepended to the output.

4. **Base64 encoding**: Standard RFC 4648 Base64 (no line breaks), matching Apache Commons Codec 1.3 behavior bundled in jasypt.

---

## Testing

```bash
# Run all tests
go test ./... -v

# Run cross-compatibility tests only
go test -v -run "TestEncryptDecryptRoundtrip|TestPBKDF1"

# Test specific algorithms
go test -v -run "AES256"
```

### Test Coverage

| Test | Description |
|------|-------------|
| `TestPBKDF1KeyDerivation` | Fixed-salt deterministic encryption |
| `TestEncryptDecryptRoundtrip` | Roundtrip with all algorithms and encoding types |
| `TestEmptyAndNil` | Edge cases for empty/nil input |
| `TestWrongPassword` | Decryption with wrong password fails |
| `TestWrongAlgorithm` | Decryption with wrong algorithm fails |
| `TestTextEncryptors` | Convenience API correctness |
| `TestUnicodePassword` | NFC normalization for Unicode passwords |
| `TestSaltAndIvSizes` | Salt/IV sizes match algorithm block sizes |

---

## Comparison with Java jasypt

| Feature | Java jasypt 1.9.3 | go-jasypt |
|---------|-------------------|-----------|
| PBEWithMD5AndDES | ✅ | ✅ |
| PBEWithSHA1AndDESede | ✅ | ⚠️ PKCS#12 derivation |
| PBEWITHHMACSHA512ANDAES_256 | ✅ (needs BC) | ✅ |
| RandomSaltGenerator | ✅ | ✅ |
| FixedSaltGenerator | ✅ | ✅ |
| ZeroSaltGenerator | ✅ | ✅ |
| RandomIvGenerator | ✅ | ✅ |
| NoIvGenerator | ✅ | ✅ |
| FixedIvGenerator | ✅ | ✅ |
| Base64 output | ✅ | ✅ |
| Hex output | ✅ | ✅ |
| Pooled encryptor | ✅ | 🔜 Future |
| EncryptableProperties | ✅ | 🔜 Future |
| CLI tool | ✅ | ✅ |
| Thread-safe | ✅ | ⚠️ Use `sync.Mutex` |

---

## License

Apache License 2.0 — matching the original jasypt project.

---

## References

- [Jasypt Official Site](http://www.jasypt.org/)
- [PKCS #5: Password-Based Cryptography Standard](https://tools.ietf.org/html/rfc2898)
- [BouncyCastle Provider](https://www.bouncycastle.org/)
