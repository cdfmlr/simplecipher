package simplecipher

import (
	"fmt"
	"io"
	"testing"
)

// testProvider returns a Provider instance for testing purposes.
// with Hex encoding and a fixed salt.
func testProvider() *Provider {
	return &Provider{
		StringCodec: HexCodec,
		SaltFunc:    func() string { return "testsalt" },
	}
}

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
	// fmt.Printf("Encrypted (Base64): %s\n", encrypted)

	decrypted, err := cipher.Decrypt(encrypted)
	if err != nil {
		panic(err)
	}

	fmt.Println(decrypted)
	// Output: Secret Message
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

	// fmt.Printf("Provider Alpha (Hex): %s\n", encrypted1)
	// fmt.Printf("Provider Beta (Base64): %s\n", encrypted2)

	// Each provider can decrypt its own ciphertext
	decrypted1, _ := cipher1.Decrypt(encrypted1)
	decrypted2, _ := cipher2.Decrypt(encrypted2)

	fmt.Println(decrypted1)
	fmt.Println(decrypted2)
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

// TestProviderConfig verifies that Provider configuration (SaltFunc and StringCodec)
// properly affects key derivation and encryption/decryption.
func TestProviderConfig(t *testing.T) {
	const (
		passphrase = "test-passphrase"
		plaintext  = "Hello, World!"
	)

	t.Run("SaltFunc affects key derivation", func(t *testing.T) {
		// Create two providers with different salt functions
		provider1 := &Provider{
			StringCodec: HexCodec,
			SaltFunc:    func() string { return "salt1" },
		}
		provider2 := &Provider{
			StringCodec: HexCodec,
			SaltFunc:    func() string { return "salt2" },
		}

		// Derive keys from the same passphrase
		key1 := provider1.NewAesKey(passphrase)
		key2 := provider2.NewAesKey(passphrase)

		// Keys should be different due to different salts
		bytes1 := key1.Bytes()
		bytes2 := key2.Bytes()

		if len(bytes1) != len(bytes2) {
			t.Fatalf("key lengths differ: %d vs %d", len(bytes1), len(bytes2))
		}

		// Check that the keys are different
		same := true
		for i := range bytes1 {
			if bytes1[i] != bytes2[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("keys with different salts should be different")
		}
	})

	t.Run("SaltFunc affects encryption output", func(t *testing.T) {
		// Create two providers with different salt functions
		provider1 := &Provider{
			StringCodec: HexCodec,
			SaltFunc:    func() string { return "salt1" },
		}
		provider2 := &Provider{
			StringCodec: HexCodec,
			SaltFunc:    func() string { return "salt2" },
		}

		// Create ciphers with fixed IV to make encryption deterministic
		ivPassphrase := "fixed-iv"
		key1 := provider1.NewAesKey(passphrase)
		iv1 := provider1.NewIv(ivPassphrase)
		cipher1 := provider1.NewCTR(key1, iv1)

		key2 := provider2.NewAesKey(passphrase)
		iv2 := provider2.NewIv(ivPassphrase)
		cipher2 := provider2.NewCTR(key2, iv2)

		// Encrypt the same plaintext
		encrypted1, err := cipher1.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("cipher1 encryption failed: %v", err)
		}

		encrypted2, err := cipher2.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("cipher2 encryption failed: %v", err)
		}

		// Ciphertexts should be different due to different keys/IVs from different salts
		if encrypted1 == encrypted2 {
			t.Error("encrypted texts with different salts should be different")
		}
	})

	t.Run("StringCodec affects encoding output format", func(t *testing.T) {
		// Create two providers with different string codecs but same salt
		providerHex := &Provider{
			StringCodec: HexCodec,
			SaltFunc:    func() string { return "same-salt" },
		}
		providerBase64 := &Provider{
			StringCodec: Base64StdCodec,
			SaltFunc:    func() string { return "same-salt" },
		}

		// Create ciphers with fixed IV
		ivPassphrase := "fixed-iv"
		keyHex := providerHex.NewAesKey(passphrase)
		ivHex := providerHex.NewIv(ivPassphrase)
		cipherHex := providerHex.NewCTR(keyHex, ivHex)

		keyBase64 := providerBase64.NewAesKey(passphrase)
		ivBase64 := providerBase64.NewIv(ivPassphrase)
		cipherBase64 := providerBase64.NewCTR(keyBase64, ivBase64)

		// Encrypt the same plaintext
		encryptedHex, err := cipherHex.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("hex cipher encryption failed: %v", err)
		}

		encryptedBase64, err := cipherBase64.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("base64 cipher encryption failed: %v", err)
		}

		// The encrypted strings should be different due to different encoding
		if encryptedHex == encryptedBase64 {
			t.Error("encrypted texts with different codecs should have different encodings")
		}

		// Hex should only contain hex characters
		for _, c := range encryptedHex {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				t.Errorf("hex encoded string contains non-hex character: %c", c)
			}
		}

		// Base64 should contain base64 characters
		// (we don't check exact pattern, just that it's different from hex)
		if len(encryptedBase64) == 0 {
			t.Error("base64 encoded string is empty")
		}
	})

	t.Run("Provider configuration affects encryption and decryption consistency", func(t *testing.T) {
		// Create a provider with specific configuration
		provider := &Provider{
			StringCodec: Base64StdCodec,
			SaltFunc:    func() string { return "consistent-salt" },
		}

		// Create cipher with fixed IV for deterministic encryption
		ivPassphrase := "fixed-iv"
		key := provider.NewAesKey(passphrase)
		iv := provider.NewIv(ivPassphrase)
		cipher := provider.NewCTR(key, iv)

		// Encrypt
		encrypted, err := cipher.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		// Decrypt
		decrypted, err := cipher.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}

		// Should get back the original plaintext
		if decrypted != plaintext {
			t.Errorf("decrypted text doesn't match: got %q, want %q", decrypted, plaintext)
		}
	})

	t.Run("Cross-provider decryption fails with different configurations", func(t *testing.T) {
		// Create two providers with different salts
		provider1 := &Provider{
			StringCodec: HexCodec,
			SaltFunc:    func() string { return "salt1" },
		}
		provider2 := &Provider{
			StringCodec: HexCodec,
			SaltFunc:    func() string { return "salt2" },
		}

		// Encrypt with provider1
		ivPassphrase := "fixed-iv"
		key1 := provider1.NewAesKey(passphrase)
		iv1 := provider1.NewIv(ivPassphrase)
		cipher1 := provider1.NewCTR(key1, iv1)
		encrypted, err := cipher1.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		// Try to decrypt with provider2 (different salt, so different key)
		key2 := provider2.NewAesKey(passphrase)
		iv2 := provider2.NewIv(ivPassphrase)
		cipher2 := provider2.NewCTR(key2, iv2)
		decrypted, err := cipher2.Decrypt(encrypted)
		if err != nil {
			// This is expected to fail if codec differs, but CTR mode won't error
			t.Logf("decryption error (expected): %v", err)
		}

		// Due to different keys, decrypted text should not match plaintext
		if decrypted == plaintext {
			t.Error("decryption with different salt should not produce correct plaintext")
		}
	})

	t.Run("Provider affects IV derivation", func(t *testing.T) {
		provider1 := &Provider{
			StringCodec: HexCodec,
			SaltFunc:    func() string { return "salt1" },
		}
		provider2 := &Provider{
			StringCodec: HexCodec,
			SaltFunc:    func() string { return "salt2" },
		}

		ivPassphrase := "iv-passphrase"
		iv1 := provider1.NewIv(ivPassphrase)
		iv2 := provider2.NewIv(ivPassphrase)

		bytes1 := iv1.Bytes()
		bytes2 := iv2.Bytes()

		if len(bytes1) != len(bytes2) {
			t.Fatalf("IV lengths differ: %d vs %d", len(bytes1), len(bytes2))
		}

		// IVs should be different due to different salts
		same := true
		for i := range bytes1 {
			if bytes1[i] != bytes2[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("IVs with different salts should be different")
		}
	})

	t.Run("Provider affects Nonce derivation for GCM", func(t *testing.T) {
		provider1 := &Provider{
			StringCodec: HexCodec,
			SaltFunc:    func() string { return "salt1" },
		}
		provider2 := &Provider{
			StringCodec: HexCodec,
			SaltFunc:    func() string { return "salt2" },
		}

		noncePassphrase := "nonce-passphrase"
		nonce1 := provider1.NewNonce(noncePassphrase)
		nonce2 := provider2.NewNonce(noncePassphrase)

		bytes1 := nonce1.Bytes()
		bytes2 := nonce2.Bytes()

		if len(bytes1) != len(bytes2) {
			t.Fatalf("nonce lengths differ: %d vs %d", len(bytes1), len(bytes2))
		}

		// Nonces should be different due to different salts
		same := true
		for i := range bytes1 {
			if bytes1[i] != bytes2[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("nonces with different salts should be different")
		}
	})

	t.Run("SimpleCTR uses provider configuration", func(t *testing.T) {
		provider1 := &Provider{
			StringCodec: HexCodec,
			SaltFunc:    func() string { return "salt1" },
		}
		provider2 := &Provider{
			StringCodec: Base64StdCodec,
			SaltFunc:    func() string { return "salt2" },
		}

		// Use SimpleCTR which should use the provider's configuration
		cipher1 := provider1.SimpleCTR(passphrase)
		cipher2 := provider2.SimpleCTR(passphrase)

		// Each can encrypt and decrypt its own data
		encrypted1, err := cipher1.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("cipher1 encryption failed: %v", err)
		}

		encrypted2, err := cipher2.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("cipher2 encryption failed: %v", err)
		}

		// Verify they can decrypt their own ciphertext
		decrypted1, err := cipher1.Decrypt(encrypted1)
		if err != nil {
			t.Fatalf("cipher1 decryption failed: %v", err)
		}
		if decrypted1 != plaintext {
			t.Errorf("cipher1: got %q, want %q", decrypted1, plaintext)
		}

		decrypted2, err := cipher2.Decrypt(encrypted2)
		if err != nil {
			t.Fatalf("cipher2 decryption failed: %v", err)
		}
		if decrypted2 != plaintext {
			t.Errorf("cipher2: got %q, want %q", decrypted2, plaintext)
		}
	})
}
