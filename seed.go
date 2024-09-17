package seed

import (
	"crypto/rand"
	"fmt"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/argon2"
)

const (
	SeedSize    = 64 // 512 bits for seed
	EntropySize = 32 // 256 bits entropy
)

// GenerateEntropy generates secure random entropy's private key generation.
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
func GenerateSeedWithSalt(mnemonic string) ([]byte, error) {
	// Generate random salt (32 bytes)
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("error generating salt: %v", err)
	}

	// Convert the mnemonic to a byte array
	mnemonicBytes := []byte(mnemonic)

	// Use Argon2 to generate a memory-hard seed
	seed := argon2.IDKey(mnemonicBytes, salt, 1, 64*1024, 4, SeedSize)

	return seed, nil
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

	// Step 3: Generate the seed using the mnemonic and salt
	seed, err := GenerateSeedWithSalt(mnemonic)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate seed: %v", err)
	}

	// Return both the mnemonic and the seed
	return mnemonic, seed, nil
}

func main() {
	// Call SetKeyFromPassphrase to generate a mnemonic and a seed
	mnemonic, seed, err := SetKeyFromPassphrase()
	if err != nil {
		fmt.Printf("Error generating mnemonic and seed: %v\n", err)
		return
	}

	// Print the generated mnemonic
	fmt.Printf("Generated Mnemonic: %s\n", mnemonic)

	// Print the generated seed in hexadecimal format
	fmt.Printf("Generated Seed: %x\n", seed)
}
