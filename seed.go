package seed

import (
	"crypto/rand"
	"fmt"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/argon2"
)

const (
	SeedSize    = 64        // 512 bits for seed
	EntropySize = 32        // 256 bits entropy for Bitcoin-like approach
	SaltSize    = 16        // 128 bits for salt size
	Rounds      = 3         // Number of Argon2 rounds/iterations
	Memory      = 64 * 1024 // Memory cost for Argon2 (in KiB)
	Parallelism = 4         // Parallelism factor for Argon2
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

// GenerateSeedWithSalt generates a seed using a mnemonic and salt.
func GenerateSeedWithSalt(mnemonic string, salt []byte) ([]byte, error) {
	// Ensure the salt is 16 bytes by slicing if necessary
	if len(salt) > SaltSize {
		salt = salt[:SaltSize]
	}

	// Convert the mnemonic to a byte array
	mnemonicBytes := []byte(mnemonic)

	// Use Argon2 to generate a memory-hard seed
	seed := argon2.IDKey(mnemonicBytes, salt, Rounds, Memory, Parallelism, SeedSize)

	return seed, nil
}

// SetKeyFromPassphrase generates both a mnemonic and a seed, performing cryptographic functions.
func SetKeyFromPassphrase() (string, []byte, error) {
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

	// Step 3: Generate random salt (16 bytes)
	salt := make([]byte, SaltSize)
	_, err = rand.Read(salt)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	// Step 4: Generate the seed using the mnemonic and salt
	seed, err := GenerateSeedWithSalt(mnemonic, salt)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate seed: %v", err)
	}

	// Return both the mnemonic and the seed
	return mnemonic, seed, nil
}
