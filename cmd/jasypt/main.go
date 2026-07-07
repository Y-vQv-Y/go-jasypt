// Command jasypt is a CLI tool for PBE encryption and decryption,
// compatible with the Java jasypt CLI (org.jasypt.intf.cli).
//
// Usage:
//
//	# Encryption
//	go-jasypt encrypt input="hello" password="secret" [algorithm=...] [keyObtentionIterations=...] [...]
//
//	# Decryption
//	go-jasypt decrypt input="base64ciphertext" password="secret" [algorithm=...] [keyObtentionIterations=...] [...]
//
// Supported optional arguments:
//
//	algorithm                     - PBE algorithm name (default: PBEWithMD5AndDES)
//	keyObtentionIterations        - Key derivation iterations (default: 1000)
//	saltGeneratorClassName        - Salt generator class (RandomSaltGenerator, FixedSaltGenerator, ZeroSaltGenerator)
//	ivGeneratorClassName          - IV generator class (RandomIvGenerator, NoIvGenerator, FixedIvGenerator)
//	stringOutputType              - "base64" or "hexadecimal" (default: base64)
//	providerName                  - Security provider name (ignored in Go, for CLI compatibility)
//	providerClassName             - Security provider class (ignored in Go, for CLI compatibility)
//	verbose                       - Enable verbose output
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/go-jasypt/jasypt/iv"
	"github.com/go-jasypt/jasypt/pbe"
	"github.com/go-jasypt/jasypt/salt"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	args := parseArgs(os.Args[2:])

	switch command {
	case "encrypt":
		runEncrypt(args)
	case "decrypt":
		runDecrypt(args)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "ERROR: Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

// parseArgs parses key=value arguments into a map.
// Values wrapped in double quotes are unwrapped (matching Java CLI behavior).
func parseArgs(raw []string) map[string]string {
	result := make(map[string]string)
	for _, arg := range raw {
		eqIdx := strings.Index(arg, "=")
		if eqIdx == -1 {
			continue
		}
		key := arg[:eqIdx]
		value := arg[eqIdx+1:]

		// Strip surrounding double quotes (Java CLI does this)
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}

		if key != "" && value != "" {
			result[key] = value
		}
	}
	return result
}

func runEncrypt(args map[string]string) {
	config := buildConfig(args)
	encryptor, err := pbe.NewStringEncryptor(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	input := args["input"]
	verbose := isVerbose(args)

	result, err := encryptor.Encrypt(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Print("\n----OUTPUT----------------------\n\n")
		fmt.Println(result)
		fmt.Println()
	} else {
		fmt.Println(result)
	}
}

func runDecrypt(args map[string]string) {
	config := buildConfig(args)
	encryptor, err := pbe.NewStringEncryptor(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	input := args["input"]
	verbose := isVerbose(args)

	result, err := encryptor.Decrypt(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Operation not possible (Bad input or parameters)\n")
		if verbose {
			fmt.Fprintf(os.Stderr, "Details: %v\n", err)
		}
		os.Exit(1)
	}

	if verbose {
		fmt.Print("\n----OUTPUT----------------------\n\n")
		fmt.Println(result)
		fmt.Println()
	} else {
		fmt.Println(result)
	}
}

func buildConfig(args map[string]string) *pbe.Config {
	config := pbe.DefaultConfig()

	// Password (required)
	if pwd, ok := args["password"]; ok {
		config.Password = pwd
	}

	// Algorithm (optional)
	if algo, ok := args["algorithm"]; ok && algo != "" {
		config.Algorithm = algo
	}

	// Key obtention iterations (optional)
	if iterStr, ok := args["keyObtentionIterations"]; ok && iterStr != "" {
		if iter, err := strconv.Atoi(iterStr); err == nil && iter > 0 {
			config.KeyObtentionIterations = iter
		}
	}

	// Salt generator (optional)
	if saltClass, ok := args["saltGeneratorClassName"]; ok && saltClass != "" {
		config.SaltGenerator = resolveSaltGenerator(saltClass)
	}

	// IV generator (optional)
	if ivClass, ok := args["ivGeneratorClassName"]; ok && ivClass != "" {
		config.IvGenerator = resolveIvGenerator(ivClass)
	}

	// String output type (optional)
	if outputType, ok := args["stringOutputType"]; ok && outputType != "" {
		config.StringOutputType = normalizeOutputType(outputType)
	}

	return config
}

func resolveSaltGenerator(className string) salt.Generator {
	switch {
	case strings.Contains(className, "RandomSaltGenerator"):
		return salt.NewRandomGenerator()
	case strings.Contains(className, "ZeroSaltGenerator"):
		return salt.NewZeroGenerator()
	case strings.Contains(className, "FixedSaltGenerator"):
		return salt.NewFixedGenerator([]byte{})
	default:
		return salt.NewRandomGenerator()
	}
}

func resolveIvGenerator(className string) iv.Generator {
	switch {
	case strings.Contains(className, "RandomIvGenerator"):
		return iv.NewRandomGenerator()
	case strings.Contains(className, "NoIvGenerator"):
		return iv.NewNoGenerator()
	case strings.Contains(className, "FixedIvGenerator"):
		return iv.NewFixedGenerator([]byte{})
	default:
		return iv.NewNoGenerator()
	}
}

func normalizeOutputType(t string) string {
	switch strings.ToLower(t) {
	case "hexadecimal", "hexa", "0x", "hex", "hexadec":
		return "hexadecimal"
	default:
		return "base64"
	}
}

func isVerbose(args map[string]string) bool {
	v, ok := args["verbose"]
	if !ok {
		return true // default verbose=true (matching Java CLI behavior)
	}
	switch strings.ToLower(v) {
	case "true", "yes", "on", "1":
		return true
	default:
		return false
	}
}

func printUsage() {
	fmt.Println(`Jasypt PBE Encryption/Decryption CLI (Go implementation)

USAGE: go-jasypt <command> [ARGUMENTS]

COMMANDS:
  encrypt    Encrypt a message
  decrypt    Decrypt a message

ARGUMENTS (format: key=value):
  Required:
    input                        The message to encrypt/decrypt
    password                     The encryption password

  Optional:
    algorithm                    PBE algorithm (default: PBEWithMD5AndDES)
                                 Supported: PBEWithMD5AndDES, PBEWithSHA1AndDESede,
                                           PBEWITHHMACSHA512ANDAES_256
    keyObtentionIterations       Key derivation iterations (default: 1000)
    saltGeneratorClassName       Salt generator (default: RandomSaltGenerator)
                                 Options: RandomSaltGenerator, FixedSaltGenerator, ZeroSaltGenerator
    ivGeneratorClassName         IV generator (default: NoIvGenerator)
                                 Options: RandomIvGenerator, NoIvGenerator, FixedIvGenerator
    stringOutputType             Output encoding (default: base64)
                                 Options: base64, hexadecimal
    providerName                 [ignored, for Java CLI compatibility]
    providerClassName            [ignored, for Java CLI compatibility]
    verbose                      Verbose output (default: true)

EXAMPLES:
  # Basic encryption with defaults
  go-jasypt encrypt input="hello" password="mySecret"

  # Strong encryption with AES-256
  go-jasypt encrypt input="hello" password="mySecret" \
      algorithm=PBEWITHHMACSHA512ANDAES_256 \
      ivGeneratorClassName=RandomIvGenerator

  # Decrypt
  go-jasypt decrypt input="encryptedBase64String" password="mySecret" \
      algorithm=PBEWITHHMACSHA512ANDAES_256 \
      ivGeneratorClassName=RandomIvGenerator`)
}
