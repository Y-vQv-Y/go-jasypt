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

## 项目独立性

`go-jasypt` 是**完全自包含**的项目，不依赖同目录下的 Java 项目或任何本地外部文件。

```
go-jasypt/
├── cmd/
│   └── jasypt/          ← CLI 入口 (main.go)
├── encoding/            ← Base64 / Hex 编解码
├── iv/                  ← IV 生成器 (Random / NoIv / Fixed)
├── pbe/                 ← 核心加密引擎 (PBKDF1/PBKDF2 + CBC)
├── salt/                ← Salt 生成器 (Random / Fixed / Zero)
├── text/                ← 便捷加密器 (Basic / Strong)
├── util/                ← Unicode NFC 规范化
├── go.mod               ← 仅依赖 golang.org/x/crypto + golang.org/x/text
├── go.sum
└── compat_test.go       ← 跨语言兼容性测试
```

- ✅ 无 `replace` 指令指向本地路径
- ✅ 无 `../` 相对路径引用
- ✅ 可直接推送到 Git 仓库独立使用

---

## Installation

**Requirements:** Go 1.21+

### 方式一：作为 Go Library 引入（代码中调用）

在你的 Go 项目 `go.mod` 中添加依赖：

```bash
go get github.com/Y-vQv-Y/go-jasypt
```

然后在代码中 import：

```go
import (
    "github.com/Y-vQv-Y/go-jasypt/pbe"
    "github.com/Y-vQv-Y/go-jasypt/iv"
    "github.com/Y-vQv-Y/go-jasypt/salt"
    "github.com/Y-vQv-Y/go-jasypt/text"      // 便捷加密器
)
```

### 方式二：Go 代码直接调用

在 `go.mod` 所在目录执行：

```bash
go get github.com/Y-vQv-Y/go-jasypt
```

#### CLI 等价 Go 代码（加密）

```bash
# CLI 命令
./jasypt-go encrypt input="明文" password="PILLAR-PLUS-SECRET" \
    algorithm=PBEWITHHMACSHA512ANDAES_256 \
    keyObtentionIterations=1000 \
    ivGeneratorClassName=RandomIvGenerator \
    saltGeneratorClassName=RandomSaltGenerator
```

对应的 Go 代码：

```go
import (
    "fmt"

    "github.com/Y-vQv-Y/go-jasypt/iv"
    "github.com/Y-vQv-Y/go-jasypt/pbe"
    "github.com/Y-vQv-Y/go-jasypt/salt"
)

func encryptExample() {
    config := &pbe.Config{
        Algorithm:              "PBEWITHHMACSHA512ANDAES_256",
        Password:               "PILLAR-PLUS-SECRET",
        KeyObtentionIterations: 1000,
        SaltGenerator:          salt.NewRandomGenerator(),
        IvGenerator:            iv.NewRandomGenerator(),
        StringOutputType:       "base64",
    }

    enc, _ := pbe.NewStringEncryptor(config)
    encrypted, _ := enc.Encrypt("明文")
    fmt.Println(encrypted) // Base64 密文 → 传给 Java 解密
}
```

#### CLI 等价 Go 代码（解密）

```bash
# CLI 命令
./jasypt-go decrypt input="base64密文" password="PILLAR-PLUS-SECRET" \
    algorithm=PBEWITHHMACSHA512ANDAES_256 \
    keyObtentionIterations=1000 \
    ivGeneratorClassName=RandomIvGenerator \
    saltGeneratorClassName=RandomSaltGenerator
```

对应的 Go 代码：

```go
func decryptExample(encryptedBase64 string) {
    config := &pbe.Config{
        Algorithm:              "PBEWITHHMACSHA512ANDAES_256",
        Password:               "PILLAR-PLUS-SECRET",
        KeyObtentionIterations: 1000,
        SaltGenerator:          salt.NewRandomGenerator(),
        IvGenerator:            iv.NewRandomGenerator(),
        StringOutputType:       "base64",
    }

    enc, _ := pbe.NewStringEncryptor(config)
    decrypted, _ := enc.Decrypt(encryptedBase64)
    fmt.Println(decrypted) // "明文" → 与 Java 加密的结果一致
}
```

> **参数对照表：**
>
> | CLI 参数 | Go Config 字段 |
> |----------|---------------|
> | `algorithm=PBEWITHHMACSHA512ANDAES_256` | `Algorithm: "PBEWITHHMACSHA512ANDAES_256"` |
> | `password="..."` | `Password: "..."` |
> | `keyObtentionIterations=1000` | `KeyObtentionIterations: 1000` |
> | `ivGeneratorClassName=RandomIvGenerator` | `IvGenerator: iv.NewRandomGenerator()` |
> | `saltGeneratorClassName=RandomSaltGenerator` | `SaltGenerator: salt.NewRandomGenerator()` |
> | `stringOutputType=base64` | `StringOutputType: "base64"` |

#### 更多示例

```go
// ─── 示例 1: 最简方式（PBEWithMD5AndDES，默认随机盐）───
config := pbe.DefaultConfig()
config.Password = "mySecretKey"

enc, _ := pbe.NewStringEncryptor(config)
encrypted, _ := enc.Encrypt("Hello World")
decrypted, _ := enc.Decrypt(encrypted)

fmt.Println(encrypted) // Base64 密文（每次不同，因为随机盐）
fmt.Println(decrypted) // "Hello World"

// ─── 示例 2: 便捷方式（BasicTextEncryptor）───
import "github.com/Y-vQv-Y/go-jasypt/text"

basic := text.NewBasicTextEncryptor()
basic.SetPassword("password")
result, _ := basic.Encrypt("hello")
original, _ := basic.Decrypt(result)
fmt.Println(original) // "hello"
```

```bash
# 运行
go run main.go
```

### 方式三：编译 CLI 二进制文件

```bash
# 克隆仓库
git clone https://github.com/Y-vQv-Y/go-jasypt.git
cd go-jasypt

# 当前平台编译
go build -o jasypt-go ./cmd/jasypt

# ─── 交叉编译其他平台 ─────────────────────────

# Linux (amd64)
GOOS=linux   GOARCH=amd64 go build -o jasypt-go-linux       ./cmd/jasypt

# Linux (arm64)
GOOS=linux   GOARCH=arm64 go build -o jasypt-go-linux-arm64 ./cmd/jasypt

# macOS (Intel)
GOOS=darwin  GOARCH=amd64 go build -o jasypt-go-darwin      ./cmd/jasypt

# macOS (Apple Silicon)
GOOS=darwin  GOARCH=arm64 go build -o jasypt-go-darwin-arm64 ./cmd/jasypt

# Windows (amd64)
GOOS=windows GOARCH=amd64 go build -o jasypt-go.exe         ./cmd/jasypt

# ─── 一键编译所有平台 (Bash) ──────────────────

#!/bin/bash
for os in linux darwin windows; do
    for arch in amd64 arm64; do
        [ "$os" = "windows" ] && ext=".exe" || ext=""
        GOOS=$os GOARCH=$arch go build -o "jasypt-go-${os}-${arch}${ext}" ./cmd/jasypt
    done
done
```

编译产物复制到目标服务器后直接使用：

```bash
# Linux 服务器
chmod +x jasypt-go-linux
./jasypt-go-linux encrypt input="hello" password="secret"
```

> **注意：** 不要在 Windows 上编译 `.exe` 然后直接复制到 Linux 运行，会报 `Exec format error`。请使用上面的交叉编译命令。

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

> **⚠️ 注意事项：bash 特殊字符转义**
>
> 当明文或密码中包含 bash 特殊字符（`!` `#` `$` `\` `` ` `` `"` 等）时，**必须用单引号 `'...'` 包裹**，否则会被 bash 错误解析：
>
> ```bash
> # ❌ 错误：! 和 # 被 bash 拦截
> jasypt-go encrypt input="admin@1!.-/#" password="xxx"
> #                                  ↑ 从这里开始全被当成注释
>
> # ✅ 正确：单引号内所有字符都是字面量
> jasypt-go encrypt input='admin@1!.-/#' password="xxx"
> ```
>
> | 明文包含 | 推荐写法 | 原因 |
> |---------|---------|------|
> | 普通字符 | `input="hello"` | 双引号即可 |
> | `!` `#` `$` `\` `` ` `` | `input='...'` | 单引号阻止所有展开 |
> | 含单引号 `'` | `input="it's"` | 双引号保护单引号 |
> | **单引号 + 特殊字符** | 见下方 | 需特殊处理 |
>
> **密码同时包含单引号 `'` 和特殊字符（如 `!` `#`）时：**
>
> ```bash
> # 假设密码为: P@ss'word!.#/
>
> # ─── 方案一: ANSI-C 引用（bash 推荐）───
> jasypt-go encrypt input='hello' password=$'P@ss\'word!.#/'
>
> # ─── 方案二: 单引号拼接法（兼容所有 POSIX shell）───
> # '\'' = 结束单引号 → 转义单引号 → 重新开始单引号
> jasypt-go encrypt input='hello' password='P@ss'\''word!.#/'
>
> # ─── 方案三: 环境变量（适合脚本）───
> read -r -s PASS          # -s 不显示输入内容
> jasypt-go encrypt input='hello' password="$PASS"
> ```

### Go API

```go
package main

import (
    "fmt"
    "github.com/Y-vQv-Y/go-jasypt/iv"
    "github.com/Y-vQv-Y/go-jasypt/pbe"
    "github.com/Y-vQv-Y/go-jasypt/salt"
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
import "github.com/Y-vQv-Y/go-jasypt/text"

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
