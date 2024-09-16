package seed

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"

	"golang.org/x/crypto/pbkdf2"

	"github.com/tyler-smith/go-bip39"
)

const (
	SeedSize     = 64         // 512 bits for seed
	EntropySize  = 32         // 256 bits entropy for Bitcoin-like approach
	Pbkdf2Rounds = 2048       // Standard for BIP-39
	SaltPrefix   = "mnemonic" // Salt prefix as per BIP-39 standard
)

// GenerateEntropy generates secure random entropy similar to Bitcoin private key generation.
func GenerateEntropy() ([]byte, error) {
	entropy := make([]byte, EntropySize)
	_, err := rand.Read(entropy)
	if err != nil {
		return nil, fmt.Errorf("error generating entropy: %v", err)
	}
	return entropy, nil
}

// GeneratePhrase generates a BIP-39 mnemonic phrase from entropy.
func GeneratePhrase(entropy []byte) (string, error) {
	// Generate mnemonic from entropy
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("error generating mnemonic: %v", err)
	}
	return mnemonic, nil
}

// GenerateSeedWithSalt generates a seed using a mnemonic and optional passphrase (salt).
func GenerateSeedWithSalt(mnemonic, passphrase string) []byte {
	// Create the salt by prepending the salt prefix (BIP-39 standard uses "mnemonic" as the salt prefix)
	salt := SaltPrefix + passphrase

	// Use PBKDF2 with HMAC-SHA512 to derive the seed
	seed := pbkdf2.Key([]byte(mnemonic), []byte(salt), Pbkdf2Rounds, SeedSize, sha512.New)

	return seed
}

// Example validation: Check if length is valid for BIP-39
func IsValidEntropy(entropy []byte) bool {
	// Valid entropy lengths are 16, 20, 24, 28, 32 bytes
	validLengths := map[int]bool{
		16: true,
		20: true,
		24: true,
		28: true,
		32: true,
	}
	return validLengths[len(entropy)]
}

// SetKeyFromPassphrase generates both a mnemonic and a seed, performing cryptographic functions.
func SetKeyFromPassphrase(passphrase string) (string, []byte, error) {
	// Step 1: Generate entropy
	entropy, err := GenerateEntropy()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate entropy: %v", err)
	}

	// Step 2: Generate the mnemonic phrase from entropy
	mnemonic, err := GeneratePhrase(entropy)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate phrase: %v", err)
	}

	// Step 3: Generate the seed using the mnemonic and optional passphrase
	seed := GenerateSeedWithSalt(mnemonic, passphrase)

	// Return both the mnemonic and the seed
	return mnemonic, seed, nil
}
