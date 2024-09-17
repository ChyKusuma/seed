package seed

import (
	"crypto/rand"
	"fmt"

	"github.com/tyler-smith/go-bip39"
)

const (
	SeedSize    = 64 // 512 bits for seed
	EntropySize = 32 // 256 bits entropy for Bitcoin-like approach
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

// GenerateSeedWithPassphrase generates a seed using a mnemonic and a passphrase.
func GenerateSeedWithPassphrase(mnemonic, passphrase string) ([]byte, error) {
	// Generate seed from mnemonic and passphrase
	seed := bip39.NewSeed(mnemonic, passphrase)
	return seed, nil
}

// GenerateMnemonicAndSeed generates a mnemonic and a seed from a passphrase.
func GenerateMnemonicAndSeed(passphrase string) (mnemonic string, seed []byte, err error) {
	// Step 1: Generate entropy
	entropy, err := GenerateEntropy()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate entropy: %v", err)
	}

	// Step 2: Generate the mnemonic phrase from entropy
	mnemonic, err = GeneratePhrase(entropy)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate mnemonic: %v", err)
	}

	// Step 3: Generate the seed using the mnemonic and passphrase
	seed, err = GenerateSeedWithPassphrase(mnemonic, passphrase)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate seed: %v", err)
	}

	// Return both the mnemonic and the seed
	return mnemonic, seed, nil
}

func main() {
	// Define a passphrase for seed generation
	passphrase := "example passphrase" // Replace with your passphrase

	// Call GenerateMnemonicAndSeed to generate a mnemonic and a seed
	mnemonic, seed, err := GenerateMnemonicAndSeed(passphrase)
	if err != nil {
		fmt.Printf("Error generating mnemonic and seed: %v\n", err)
		return
	}

	// Print the generated mnemonic
	fmt.Printf("Generated Mnemonic: %s\n", mnemonic)

	// Print the generated seed in hexadecimal format
	fmt.Printf("Generated Seed: %x\n", seed)
}
