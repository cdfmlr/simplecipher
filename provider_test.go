package simplecipher

import (
	"fmt"
	"io"
	"testing"

	"github.com/cdfmlr/simplecipher/v2/kdf"
)

// testProvider returns a Provider instance for testing purposes.
// with Hex encoding and a fixed salt.
func testProvider() *Provider {
	return &Provider{
		StringCodec:   HexCodec,
		SaltFunc:      func() string { return "testsalt" },
		KeyDerivation: kdf.NewScrypt(2048, 8, 1), // Default KDF for tests
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
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return "salt1" },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
		}
		provider2 := &Provider{
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return "salt2" },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
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
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return "salt1" },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
		}
		provider2 := &Provider{
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return "salt2" },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
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
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return "salt1" },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
		}
		provider2 := &Provider{
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return "salt2" },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
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
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return "salt1" },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
		}
		provider2 := &Provider{
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return "salt2" },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
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
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return "salt1" },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
		}
		provider2 := &Provider{
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return "salt2" },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
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

// TestCustomKeyDerivation tests the customizable KeyDerivation feature in Provider.
func TestCustomKeyDerivation(t *testing.T) {
	const (
		passphrase = "test-passphrase"
		salt       = "test-salt"
		plaintext  = "Hello, World!"
	)

	t.Run("Different KDF algorithms produce different keys", func(t *testing.T) {
		// Create providers with different KDF algorithms
		providerScrypt := &Provider{
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return salt },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
		}
		providerPbkdf2 := &Provider{
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return salt },
			KeyDerivation: kdf.CheapPbkdf2(),
		}
		providerArgon2 := &Provider{
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return salt },
			KeyDerivation: kdf.CheapArgon2id(),
		}

		// Derive keys from the same passphrase using different KDFs
		keyScrypt := providerScrypt.NewAesKey(passphrase)
		keyPbkdf2 := providerPbkdf2.NewAesKey(passphrase)
		keyArgon2 := providerArgon2.NewAesKey(passphrase)

		bytesScrypt := keyScrypt.Bytes()
		bytesPbkdf2 := keyPbkdf2.Bytes()
		bytesArgon2 := keyArgon2.Bytes()

		// All keys should have the same length (AES-256)
		if len(bytesScrypt) != 32 || len(bytesPbkdf2) != 32 || len(bytesArgon2) != 32 {
			t.Fatalf("key lengths differ: scrypt=%d, pbkdf2=%d, argon2=%d",
				len(bytesScrypt), len(bytesPbkdf2), len(bytesArgon2))
		}

		// Keys should be different due to different KDF algorithms
		if bytesEqual(bytesScrypt, bytesPbkdf2) {
			t.Error("scrypt and pbkdf2 keys should be different")
		}
		if bytesEqual(bytesScrypt, bytesArgon2) {
			t.Error("scrypt and argon2 keys should be different")
		}
		if bytesEqual(bytesPbkdf2, bytesArgon2) {
			t.Error("pbkdf2 and argon2 keys should be different")
		}
	})

	t.Run("Different KDF parameters produce different keys", func(t *testing.T) {
		// Create providers with different scrypt parameters
		providerWeak := &Provider{
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return salt },
			KeyDerivation: kdf.NewScrypt(1024, 8, 1),
		}
		providerDefault := &Provider{
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return salt },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
		}
		providerStrong := &Provider{
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return salt },
			KeyDerivation: kdf.NewScrypt(4096, 8, 1),
		}

		keyWeak := providerWeak.NewAesKey(passphrase)
		keyDefault := providerDefault.NewAesKey(passphrase)
		keyStrong := providerStrong.NewAesKey(passphrase)

		bytesWeak := keyWeak.Bytes()
		bytesDefault := keyDefault.Bytes()
		bytesStrong := keyStrong.Bytes()

		// Keys with different parameters should be different
		if bytesEqual(bytesWeak, bytesDefault) {
			t.Error("keys with different N parameters should be different")
		}
		if bytesEqual(bytesDefault, bytesStrong) {
			t.Error("keys with different N parameters should be different")
		}
	})

	t.Run("Custom KDF affects encryption/decryption", func(t *testing.T) {
		// Create provider with custom KDF
		provider := &Provider{
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return salt },
			KeyDerivation: kdf.RecommendedArgon2id(),
		}

		// Create cipher
		cipher := provider.SimpleCTR(passphrase)

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

	t.Run("Cross-provider decryption fails with different KDFs", func(t *testing.T) {
		// Create two providers with different KDFs
		providerScrypt := &Provider{
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return salt },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
		}
		providerPbkdf2 := &Provider{
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return salt },
			KeyDerivation: kdf.CheapPbkdf2(),
		}

		// Encrypt with scrypt provider
		ivPassphrase := "fixed-iv"
		keyScrypt := providerScrypt.NewAesKey(passphrase)
		ivScrypt := providerScrypt.NewIv(ivPassphrase)
		cipherScrypt := providerScrypt.NewCTR(keyScrypt, ivScrypt)
		encrypted, err := cipherScrypt.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		// Try to decrypt with pbkdf2 provider (different KDF, so different key)
		keyPbkdf2 := providerPbkdf2.NewAesKey(passphrase)
		ivPbkdf2 := providerPbkdf2.NewIv(ivPassphrase)
		cipherPbkdf2 := providerPbkdf2.NewCTR(keyPbkdf2, ivPbkdf2)
		decrypted, err := cipherPbkdf2.Decrypt(encrypted)
		if err != nil {
			t.Logf("decryption error (expected): %v", err)
		}

		// Due to different KDFs, decrypted text should not match plaintext
		if decrypted == plaintext {
			t.Error("decryption with different KDF should not produce correct plaintext")
		}
	})

	t.Run("DefaultProvider uses default KDF", func(t *testing.T) {
		// Verify DefaultProvider has a KeyDerivation configured
		if DefaultProvider.KeyDerivation == nil {
			t.Fatal("DefaultProvider.KeyDerivation should not be nil")
		}

		t.Logf("DefaultProvider.KeyDerivation: \n%#v", DefaultProvider.KeyDerivation)
		t.Logf("DefaultProvider.Salt: \n%#v", DefaultProvider.SaltFunc())

		// Create a manual provider with the same default configuration
		manualProvider := &Provider{
			StringCodec:   DefaultProvider.StringCodec,
			SaltFunc:      DefaultProvider.SaltFunc,
			KeyDerivation: kdf.NewScrypt(2048, 8, 1), // TODO: new default KDF for v2
		}

		// Keys should be identical
		key1 := DefaultProvider.NewAesKey(passphrase)
		key2 := manualProvider.NewAesKey(passphrase)

		if !bytesEqual(key1.Bytes(), key2.Bytes()) {
			t.Error("DefaultProvider should use scrypt with N=2048, r=8, p=1 for backward compatibility")
		}
	})

	t.Run("Custom KDF works with all key derivation methods", func(t *testing.T) {
		provider := &Provider{
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return salt },
			KeyDerivation: kdf.RecommendedPbkdf2(),
		}

		// Test NewAesKey
		aesKey := provider.NewAesKey(passphrase)
		if len(aesKey.Bytes()) != 32 {
			t.Errorf("NewAesKey should return 32 bytes, got %d", len(aesKey.Bytes()))
		}

		// Test NewNonce
		nonce := provider.NewNonce(passphrase)
		if len(nonce.Bytes()) != 12 {
			t.Errorf("NewNonce should return 12 bytes, got %d", len(nonce.Bytes()))
		}

		// Test NewIv
		iv := provider.NewIv(passphrase)
		if len(iv.Bytes()) != 16 {
			t.Errorf("NewIv should return 16 bytes (AES block size), got %d", len(iv.Bytes()))
		}

		// Test NewKey
		customKey := provider.NewKey(passphrase, Aes128, salt)
		if len(customKey.Bytes()) != 16 {
			t.Errorf("NewKey should return 16 bytes for AES-128, got %d", len(customKey.Bytes()))
		}
	})

	t.Run("Custom KDF with different key lengths", func(t *testing.T) {
		provider := &Provider{
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return salt },
			KeyDerivation: kdf.CheapScrypt(),
		}

		// Test AES-128
		key128 := provider.NewAesKey(passphrase, WithLen(Aes128))
		if len(key128.Bytes()) != 16 {
			t.Errorf("AES-128 key should be 16 bytes, got %d", len(key128.Bytes()))
		}

		// Test AES-192
		key192 := provider.NewAesKey(passphrase, WithLen(Aes192))
		if len(key192.Bytes()) != 24 {
			t.Errorf("AES-192 key should be 24 bytes, got %d", len(key192.Bytes()))
		}

		// Test AES-256
		key256 := provider.NewAesKey(passphrase, WithLen(Aes256))
		if len(key256.Bytes()) != 32 {
			t.Errorf("AES-256 key should be 32 bytes, got %d", len(key256.Bytes()))
		}

		// Verify all keys are non-nil and have correct lengths
		if key128.Bytes() == nil || key192.Bytes() == nil || key256.Bytes() == nil {
			t.Error("keys should not be nil")
		}
	})

	t.Run("Nil KDF falls back to padding/truncation", func(t *testing.T) {
		provider := &Provider{
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return salt },
			KeyDerivation: nil, // Explicitly nil
		}

		// Should still work but use fallback mechanism
		key := provider.NewAesKey(passphrase)
		keyBytes := key.Bytes()

		if len(keyBytes) != 32 {
			t.Errorf("key length should be 32 bytes even with nil KDF, got %d", len(keyBytes))
		}

		// The key should not be nil or empty
		if keyBytes == nil || len(keyBytes) == 0 {
			t.Error("key should not be nil or empty even with nil KDF")
		}
	})

	t.Run("Custom KDF with GCM cipher", func(t *testing.T) {
		provider := &Provider{
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return salt },
			KeyDerivation: kdf.CheapArgon2id(),
		}

		// Create GCM cipher with custom KDF
		cipher := provider.SimpleGCM(passphrase, "nonce-passphrase")

		// Encrypt
		encrypted, err := cipher.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("GCM encryption failed: %v", err)
		}

		// Decrypt
		decrypted, err := cipher.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("GCM decryption failed: %v", err)
		}

		if decrypted != plaintext {
			t.Errorf("GCM decrypted text doesn't match: got %q, want %q", decrypted, plaintext)
		}
	})

	t.Run("Custom KDF with CBC cipher", func(t *testing.T) {
		provider := &Provider{
			StringCodec:   HexCodec,
			SaltFunc:      func() string { return salt },
			KeyDerivation: kdf.RecommendedScrypt(),
		}

		// Create CBC cipher with custom KDF
		cipher := provider.SimpleCBC(passphrase)

		// Encrypt
		encrypted, err := cipher.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("CBC encryption failed: %v", err)
		}

		// Decrypt
		decrypted, err := cipher.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("CBC decryption failed: %v", err)
		}

		if decrypted != plaintext {
			t.Errorf("CBC decrypted text doesn't match: got %q, want %q", decrypted, plaintext)
		}
	})

	t.Run("Multiple providers with different KDFs work independently", func(t *testing.T) {
		providers := []*Provider{
			{
				StringCodec:   HexCodec,
				SaltFunc:      func() string { return "salt1" },
				KeyDerivation: kdf.CheapScrypt(),
			},
			{
				StringCodec:   HexCodec,
				SaltFunc:      func() string { return "salt2" },
				KeyDerivation: kdf.CheapPbkdf2(),
			},
			{
				StringCodec:   HexCodec,
				SaltFunc:      func() string { return "salt3" },
				KeyDerivation: kdf.CheapArgon2id(),
			},
		}

		// Each provider should be able to encrypt and decrypt independently
		for i, provider := range providers {
			cipher := provider.SimpleCTR(passphrase)

			encrypted, err := cipher.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("provider %d encryption failed: %v", i, err)
			}

			decrypted, err := cipher.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("provider %d decryption failed: %v", i, err)
			}

			if decrypted != plaintext {
				t.Errorf("provider %d: got %q, want %q", i, decrypted, plaintext)
			}
		}
	})
}

// Example_customKDF demonstrates using a Provider with a custom KDF algorithm.
func Example_customKDF() {
	// Create a provider with a customized Argon2id KDF instead of the default one.
	provider := &Provider{
		StringCodec: HexCodec,
		SaltFunc:    func() string { return "my-salt" },
		// use a preset profile: KeyDerivation: kdf.RecommendedArgon2id(),
		// or customize parameters as needed:
		KeyDerivation: kdf.NewArgon2id(1, 64*1024, 1),
	}

	// Use the provider to create a cipher
	cipher := provider.SimpleCTR("my-password")
	plaintext := "Encrypted with Argon2id"

	encrypted, err := cipher.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}

	decrypted, err := cipher.Decrypt(encrypted)
	if err != nil {
		panic(err)
	}

	fmt.Println(decrypted)
	// Output: Encrypted with Argon2id
}

// bytesEqual is a helper function to check if two byte slices are equal.
func bytesEqual(a, b []byte) bool {
	// return bytes.Equal(a, b)
	return string(a) == string(b)
}

// // HOW CLAUDE CODE LIKE A PRO:
// func bytesEqual_claude(a, b []byte) bool {
// 	if len(a) != len(b) {
// 		return false
// 	}
// 	for i := range a {
// 		if a[i] != b[i] {
// 			return false
// 		}
// 	}
// 	return true
// }
//
// func BenchmarkBytesEqual(b *testing.B) {
// 	aa := []byte("This is a sample byte slice for testing.")
// 	// bb := []byte("totally different")
// 	bb := make([]byte, len(aa))
// 	copy(bb, aa)
//
// 	methods := map[string]func(a, b []byte) bool{
// 		"bytes.Equal":       bytes.Equal,
// 		"string":            func(a, b []byte) bool { return string(a) == string(b) },
// 		"claude":            bytesEqual_claude,
// 		"reflect.DeepEqual": func(a, b []byte) bool { return reflect.DeepEqual(a, b) },
// 	}
//
// 	for name, fn := range methods {
// 		b.Run(name, func(b *testing.B) {
// 			for b.Loop() {
// 				fn(aa, bb)
// 			}
// 		})
// 	}
// }
