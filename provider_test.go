package simplecipher

import (
	"fmt"
	"io"
)

// Example_defaultProvider demonstrates using the DefaultProvider for backward compatibility.
func Example_defaultProvider() {
	// This is the traditional way of using simplecipher
	// It uses the DefaultProvider internally
	cipher := SimpleCTR("my-password")
	plaintext := "Hello, World!"

	encrypted, err := cipher.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}

	decrypted, err := cipher.Decrypt(encrypted)
	if err != nil {
		panic(err)
	}

	fmt.Println(decrypted)
	// Output: Hello, World!
}

// Example_customProvider demonstrates creating and using a custom Provider
// with different configuration (Base64 encoding instead of Hex).
func Example_customProvider() {
	// Create a custom provider with Base64 encoding
	provider := &Provider{
		StringCodec: Base64StdCodec,
		SaltFunc: func() string {
			return "my-custom-salt"
		},
	}

	// Use the provider to create ciphers
	cipher := provider.SimpleCTR("my-password")
	plaintext := "Secret Message"

	encrypted, err := cipher.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}

	// The encrypted text will be in Base64 format
	fmt.Printf("Encrypted (Base64): %s\n", encrypted)

	decrypted, err := cipher.Decrypt(encrypted)
	if err != nil {
		panic(err)
	}

	fmt.Println(decrypted)
	// Output: Encrypted (Base64): <base64-encoded-ciphertext>
	// Secret Message
}

// Example_multipleProviders demonstrates using multiple independent Providers
// with different configurations simultaneously without interference.
func Example_multipleProviders() {
	// Provider 1: Hex encoding with salt "alpha"
	providerAlpha := &Provider{
		StringCodec: HexCodec,
		SaltFunc:    func() string { return "alpha-salt" },
	}

	// Provider 2: Base64 encoding with salt "beta"
	providerBeta := &Provider{
		StringCodec: Base64StdCodec,
		SaltFunc:    func() string { return "beta-salt" },
	}

	password := "shared-password"
	plaintext := "data"

	// Both providers work independently
	cipher1 := providerAlpha.SimpleCTR(password)
	cipher2 := providerBeta.SimpleCTR(password)

	encrypted1, _ := cipher1.Encrypt(plaintext)
	encrypted2, _ := cipher2.Encrypt(plaintext)

	fmt.Printf("Provider Alpha (Hex): %s\n", encrypted1)
	fmt.Printf("Provider Beta (Base64): %s\n", encrypted2)

	// Each provider can decrypt its own ciphertext
	decrypted1, _ := cipher1.Decrypt(encrypted1)
	decrypted2, _ := cipher2.Decrypt(encrypted2)

	fmt.Println(decrypted1)
	fmt.Println(decrypted2)
	// Output: Provider Alpha (Hex): <hex-ciphertext>
	// Provider Beta (Base64): <base64-ciphertext>
	// data
	// data
}

// Example_customKeyDerivation demonstrates using a Provider to create keys
// with custom salt and length options.
func Example_customKeyDerivation() {
	provider := &Provider{
		StringCodec: HexCodec,
		SaltFunc: func() string {
			return "my-fixed-salt"
		},
	}

	// Create AES-256 key (default)
	key256 := provider.NewAesKey("my-passphrase")
	fmt.Printf("AES-256 key length: %d bytes\n", len(key256.Bytes()))

	// Create AES-128 key with custom salt
	key128 := provider.NewAesKey(
		"my-passphrase",
		WithLen(Aes128),
		WithSalt("custom-salt"),
	)
	fmt.Printf("AES-128 key length: %d bytes\n", len(key128.Bytes()))

	// Output: AES-256 key length: 32 bytes
	// AES-128 key length: 16 bytes
}

// Example_streamEncryption demonstrates using a Provider for stream-based
// encryption suitable for large files or streaming data.
func Example_streamEncryption() {
	provider := &Provider{
		StringCodec: HexCodec,
		SaltFunc:    func() string { return "stream-salt" },
	}

	// Create a stream cipher
	stream := provider.SimpleCTRStream("password")

	// Simulate reading from a source and writing to a destination
	source := io.NopCloser(io.Reader(nil)) // In real code, this would be a file
	dest := io.Discard                     // In real code, this would be a file

	// Encrypt streaming data (error handling omitted for brevity)
	_ = stream.EncryptStream(source, dest)

	// Later, decrypt the stream
	encryptedSource := io.NopCloser(io.Reader(nil))
	decryptedDest := io.Discard

	_ = stream.DecryptStream(encryptedSource, decryptedDest)
}

// Example_aeadEncryption demonstrates using a Provider for AEAD (authenticated
// encryption with associated data) using GCM mode.
func Example_aeadEncryption() {
	provider := &Provider{
		StringCodec: HexCodec,
		SaltFunc:    func() string { return "aead-salt" },
	}

	// Create a GCM cipher with derived key and nonce
	cipher := provider.SimpleGCM("key-passphrase", "nonce-passphrase")

	plaintext := "Authenticated Message"
	encrypted, err := cipher.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}

	decrypted, err := cipher.Decrypt(encrypted)
	if err != nil {
		panic(err)
	}

	fmt.Println(decrypted)
	// Output: Authenticated Message
}

// Example_customKeyAndIV demonstrates manually creating ciphers with custom
// key and IV values using a Provider.
func Example_customKeyAndIV() {
	provider := &Provider{
		StringCodec: HexCodec,
		SaltFunc:    func() string { return "default-salt" },
	}

	// Create a custom AES-256 key
	keyPassphrase := "secure-passphrase"
	key := provider.NewAesKey(keyPassphrase, WithLen(Aes256))

	// Create an IV
	ivPassphrase := "initialization-vector"
	iv := provider.NewIv(ivPassphrase)

	// Use them to create a cipher
	cipher := provider.NewCTR(key, iv)

	plaintext := "Encrypted with custom key and IV"
	encrypted, err := cipher.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}

	decrypted, err := cipher.Decrypt(encrypted)
	if err != nil {
		panic(err)
	}

	fmt.Println(decrypted)
	// Output: Encrypted with custom key and IV
}

// Example_providerComparison shows the difference between using DefaultProvider
// (backward compatible) and custom Provider (recommended for new code).
func Example_providerComparison() {
	// OLD WAY (still supported for backward compatibility)
	// Modifying global DefaultSalt affects all subsequent cipher creation
	DefaultSalt = func() string { return "old-style-salt" }
	cipherOld := SimpleCTR("password")
	_ = cipherOld

	// NEW WAY (recommended)
	// Create isolated providers that don't affect global state
	myProvider := &Provider{
		StringCodec: HexCodec,
		SaltFunc:    func() string { return "new-style-salt" },
	}
	cipherNew := myProvider.SimpleCTR("password")
	_ = cipherNew

	// The new way is thread-safe and doesn't have global side effects
	fmt.Println("Both approaches work, but Provider pattern is recommended for new code")
	// Output: Both approaches work, but Provider pattern is recommended for new code
}
