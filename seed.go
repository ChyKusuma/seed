package seed

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/tyler-smith/go-bip39"
)

const (
	EntropySize = 32 // 256 bits entropy
)

// GenerateEntropy generates secure random entropy for private key generation.
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
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("error generating mnemonic: %v", err)
	}
	return mnemonic, nil
}

// GenerateSeed generates a seed using a mnemonic without a passphrase.
func GenerateSeed(mnemonic string) ([]byte, error) {
	seed := bip39.NewSeed(mnemonic, "") // No passphrase
	return seed, nil
}

// HashSeed hashes the seed using SHA-256 and truncates to 128 bits.
func HashSeed(seed []byte) ([]byte, error) {
	hash := sha256.Sum256(seed)
	return hash[:16], nil
}

// EncodeBase32 encodes the data in Base32 without padding.
func EncodeBase32(data []byte) string {
	encoded := base32.StdEncoding.EncodeToString(data)
	return strings.TrimRight(encoded, "=")
}

// GenerateMnemonicAndSeed generates a mnemonic and a hashed, Base32-encoded seed.
func GenerateMnemonicAndSeed() (mnemonic string, base32Seed string, err error) {
	entropy, err := GenerateEntropy()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate entropy: %v", err)
	}

	mnemonic, err = GeneratePhrase(entropy)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate mnemonic: %v", err)
	}

	seed, err := GenerateSeed(mnemonic)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate seed: %v", err)
	}

	hashedSeed, err := HashSeed(seed)
	if err != nil {
		return "", "", fmt.Errorf("failed to hash seed: %v", err)
	}
	base32Seed = EncodeBase32(hashedSeed)

	return mnemonic, base32Seed, nil
}

