package simplecipher

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/cdfmlr/simplecipher/v2/codec"
	"github.com/cdfmlr/simplecipher/v2/kdf"
)

// testProvider returns a Provider instance for testing purposes.
// with Hex encoding and a fixed salt.
func testProvider() *Provider {
	return &Provider{
		StringCodec:   codec.Hex,
		SaltFunc:      func() string { return "testsalt" },
		KeyDerivation: kdf.NewScrypt(2048, 8, 1), // Default KDF for tests
	}
}

// TestNewProvider tests the NewProvider function with various options
func TestNewProvider(t *testing.T) {
	t.Run("noOptions", func(t *testing.T) {
		p := NewProvider()

		if p == nil {
			t.Fatal("NewProvider returned nil")
		}

		// Check that all fields are set (not nil)
		if p.StringCodec == nil {
			t.Error("StringCodec should not be nil")
		}
		if p.SaltFunc == nil {
			t.Error("SaltFunc should not be nil")
		}
		if p.KeyDerivation == nil {
			t.Error("KeyDerivation should not be nil")
		}

		// Verify defaults match DefaultProvider
		defaultP := defaultProvider()
		if p.SaltFunc() != defaultP.SaltFunc() {
			t.Errorf("SaltFunc mismatch: got %q, want %q", p.SaltFunc(), defaultP.SaltFunc())
		}
		if !reflect.DeepEqual(p.StringCodec, defaultP.StringCodec) {
			t.Errorf("StringCodec type mismatch with default: got %#v, want %#v", p.StringCodec, defaultP.StringCodec)
		}
		if !reflect.DeepEqual(p.KeyDerivation, defaultP.KeyDerivation) {
			t.Errorf("KeyDerivation mismatch with default: got %#v, want %#v", p.KeyDerivation, defaultP.KeyDerivation)
		}
	})

	t.Run("customStringCodec", func(t *testing.T) {
		customCodec := codec.Base64Std
		p := NewProvider(WithStringCodec(customCodec))

		if p.StringCodec != customCodec {
			t.Errorf("StringCodec not set correctly")
		}

		// Other fields should use defaults
		defaultP := defaultProvider()
		if p.SaltFunc() != defaultP.SaltFunc() {
			t.Errorf("SaltFunc mismatch: got %q, want %q", p.SaltFunc(), defaultP.SaltFunc())
		}
		if !reflect.DeepEqual(p.KeyDerivation, defaultP.KeyDerivation) {
			t.Errorf("KeyDerivation mismatch with default: got %#v, want %#v", p.KeyDerivation, defaultP.KeyDerivation)
		}
	})

	t.Run("customSaltFunc", func(t *testing.T) {
		customSalt := "my-custom-salt-12345"
		customSaltFunc := func() string { return customSalt }

		p := NewProvider(WithSaltFunc(customSaltFunc))

		if p.SaltFunc == nil {
			t.Fatal("SaltFunc should not be nil")
		}

		if p.SaltFunc() != customSalt {
			t.Errorf("SaltFunc returned %q, want %q", p.SaltFunc(), customSalt)
		}

		// Other fields should use defaults
		defaultP := defaultProvider()
		if !reflect.DeepEqual(p.StringCodec, defaultP.StringCodec) {
			t.Errorf("StringCodec type mismatch with default: got %#v, want %#v", p.StringCodec, defaultP.StringCodec)
		}
		if !reflect.DeepEqual(p.KeyDerivation, defaultP.KeyDerivation) {
			t.Errorf("KeyDerivation mismatch with default: got %#v, want %#v", p.KeyDerivation, defaultP.KeyDerivation)
		}
	})

	t.Run("customKeyDerivation", func(t *testing.T) {
		customKDF := kdf.NewScrypt(4096, 16, 2)

		p := NewProvider(WithKeyDerivation(customKDF))

		if p.KeyDerivation != customKDF {
			t.Error("KeyDerivation not set correctly")
		}

		// Other fields should use defaults
		defaultP := defaultProvider()
		if p.SaltFunc() != defaultP.SaltFunc() {
			t.Errorf("SaltFunc mismatch: got %q, want %q", p.SaltFunc(), defaultP.SaltFunc())
		}
		if !reflect.DeepEqual(p.StringCodec, defaultP.StringCodec) {
			t.Errorf("StringCodec type mismatch with default: got %#v, want %#v", p.StringCodec, defaultP.StringCodec)
		}
	})

	t.Run("allOptions", func(t *testing.T) {
		customCodec := codec.Base64URL
		customSalt := "multi-option-salt"
		customSaltFunc := func() string { return customSalt }
		customKDF := kdf.NewPbkdf2(10000, nil)

		p := NewProvider(
			WithStringCodec(customCodec),
			WithSaltFunc(customSaltFunc),
			WithKeyDerivation(customKDF),
		)

		// All custom values should be set
		if p.StringCodec != customCodec {
			t.Error("StringCodec not set correctly")
		}
		if p.SaltFunc() != customSalt {
			t.Errorf("SaltFunc returned %q, want %q", p.SaltFunc(), customSalt)
		}
		if p.KeyDerivation != customKDF {
			t.Error("KeyDerivation not set correctly")
		}
	})

	t.Run("options override each other in order", func(t *testing.T) {
		salt1 := "salt-1"
		salt2 := "salt-2"

		p := NewProvider(
			WithSaltFunc(func() string { return salt1 }),
			WithSaltFunc(func() string { return salt2 }), // This should win
		)

		if p.SaltFunc() != salt2 {
			t.Errorf("SaltFunc returned %q, want %q (last option should win)", p.SaltFunc(), salt2)
		}
	})
}

// TestProviderOption tests individual provider option functions
func TestProviderOption(t *testing.T) {
	t.Run("WithStringCodec sets codec", func(t *testing.T) {
		p := &Provider{}
		codecInstance := codec.Base64Std

		opt := WithStringCodec(codecInstance)
		opt(p)

		if p.StringCodec != codecInstance {
			t.Error("WithStringCodec did not set StringCodec")
		}
	})

	t.Run("WithSaltFunc sets salt function", func(t *testing.T) {
		p := &Provider{}
		expectedSalt := "test-salt"
		saltFunc := func() string { return expectedSalt }

		opt := WithSaltFunc(saltFunc)
		opt(p)

		if p.SaltFunc == nil {
			t.Fatal("WithSaltFunc did not set SaltFunc")
		}
		if p.SaltFunc() != expectedSalt {
			t.Errorf("SaltFunc returned %q, want %q", p.SaltFunc(), expectedSalt)
		}
	})

	t.Run("WithKeyDerivation sets KDF", func(t *testing.T) {
		p := &Provider{}
		kdfInstance := kdf.NewScrypt(8192, 16, 4)

		opt := WithKeyDerivation(kdfInstance)
		opt(p)

		if p.KeyDerivation != kdfInstance {
			t.Error("WithKeyDerivation did not set KeyDerivation")
		}
	})

	t.Run("Options can be nil-safe", func(t *testing.T) {
		// Options should not panic when given nil values
		p := &Provider{}

		WithStringCodec(nil)(p)
		WithSaltFunc(nil)(p)
		WithKeyDerivation(nil)(p)

		// Provider fields should be nil (options just set what they're given)
		if p.StringCodec != nil {
			t.Error("StringCodec should be nil")
		}
		if p.SaltFunc != nil {
			t.Error("SaltFunc should be nil")
		}
		if p.KeyDerivation != nil {
			t.Error("KeyDerivation should be nil")
		}
	})
}

// TestProviderEnsure tests the Ensure method
func TestProviderEnsure(t *testing.T) {
	t.Run("Ensure fills nil fields with defaults", func(t *testing.T) {
		p := &Provider{
			// All fields nil
		}

		p.Ensure()

		// All fields should now be non-nil
		if p.StringCodec == nil {
			t.Error("StringCodec should be set by Ensure")
		}
		if p.SaltFunc == nil {
			t.Error("SaltFunc should be set by Ensure")
		}
		if p.KeyDerivation == nil {
			t.Error("KeyDerivation should be set by Ensure")
		}
	})

	t.Run("Ensure preserves non-nil fields", func(t *testing.T) {
		customCodec := codec.Base64URL
		customSalt := "preserve-me"
		customSaltFunc := func() string { return customSalt }
		customKDF := kdf.NewScrypt(1024, 4, 1)

		p := &Provider{
			StringCodec:   customCodec,
			SaltFunc:      customSaltFunc,
			KeyDerivation: customKDF,
		}

		p.Ensure()

		// All custom values should be preserved
		if p.StringCodec != customCodec {
			t.Error("Ensure modified StringCodec")
		}
		if p.SaltFunc() != customSalt {
			t.Error("Ensure modified SaltFunc")
		}
		if p.KeyDerivation != customKDF {
			t.Error("Ensure modified KeyDerivation")
		}
	})

	t.Run("Ensure fills only nil fields", func(t *testing.T) {
		customCodec := codec.Base64Std

		p := &Provider{
			StringCodec: customCodec,
			// SaltFunc and KeyDerivation are nil
		}

		p.Ensure()

		// StringCodec should be preserved
		if p.StringCodec != customCodec {
			t.Error("Ensure modified StringCodec")
		}

		// Nil fields should be filled
		if p.SaltFunc == nil {
			t.Error("SaltFunc should be set by Ensure")
		}
		if p.KeyDerivation == nil {
			t.Error("KeyDerivation should be set by Ensure")
		}
	})

	t.Run("Ensure can be called multiple times safely", func(t *testing.T) {
		p := &Provider{}

		p.Ensure()
		salt1 := p.SaltFunc()

		p.Ensure()
		salt2 := p.SaltFunc()

		// Second Ensure shouldn't change values
		if salt1 != salt2 {
			t.Error("Ensure modified fields on second call")
		}
	})

	t.Run("Ensure uses same defaults as NewProvider", func(t *testing.T) {
		p1 := &Provider{}
		p1.Ensure()

		p2 := NewProvider()

		// Both should have same default salt
		if p1.SaltFunc() != p2.SaltFunc() {
			t.Errorf("Ensure and NewProvider use different default salts: %q vs %q",
				p1.SaltFunc(), p2.SaltFunc())
		}
	})
}

// TestProviderIntegration tests that NewProvider with options works correctly
// in real encryption/decryption scenarios
func TestProviderIntegration(t *testing.T) {
	t.Run("Provider created with NewProvider can encrypt/decrypt", func(t *testing.T) {
		p := NewProvider(
			WithStringCodec(codec.Base64Std),
			WithSaltFunc(func() string { return "integration-test-salt" }),
			WithKeyDerivation(kdf.NewScrypt(2048, 8, 1)),
		)

		cipher := p.SimpleCBC("test-password")
		plaintext := "Hello, Integration Test!"

		encrypted, err := cipher.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		decrypted, err := cipher.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		if decrypted != plaintext {
			t.Errorf("Decrypted text doesn't match: got %q, want %q", decrypted, plaintext)
		}
	})

	t.Run("Different providers with different salts produce different ciphertexts", func(t *testing.T) {
		p1 := NewProvider(WithSaltFunc(func() string { return "salt-A" }))
		p2 := NewProvider(WithSaltFunc(func() string { return "salt-B" }))

		password := "same-password"
		plaintext := "same-plaintext"

		// Both encrypt the same plaintext with same password
		cipher1 := p1.SimpleCBC(password)
		cipher2 := p2.SimpleCBC(password)

		encrypted1, _ := cipher1.Encrypt(plaintext)
		encrypted2, _ := cipher2.Encrypt(plaintext)

		// Ciphertexts should be different (different salts = different keys)
		if encrypted1 == encrypted2 {
			t.Error("Different providers with different salts should produce different ciphertexts")
		}

		// But each can decrypt its own
		decrypted1, _ := cipher1.Decrypt(encrypted1)
		decrypted2, _ := cipher2.Decrypt(encrypted2)

		if decrypted1 != plaintext || decrypted2 != plaintext {
			t.Error("Providers should be able to decrypt their own ciphertexts")
		}
	})

	t.Run("Provider with Base64 codec produces valid Base64", func(t *testing.T) {
		p := NewProvider(WithStringCodec(codec.Base64Std))
		cipher := p.SimpleCBC("password")

		encrypted, err := cipher.Encrypt("test")
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		// Base64 strings should only contain valid Base64 characters
		// We can test by trying to decode it
		decoded, err := codec.Base64Std.DecodeString(encrypted)
		if err != nil {
			t.Errorf("Encrypted text is not valid Base64: %v", err)
		}
		if len(decoded) == 0 {
			t.Error("Decoded ciphertext should not be empty")
		}
	})
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
			StringCodec:   codec.Hex,
			SaltFunc:      func() string { return "salt1" },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
		}
		provider2 := &Provider{
			StringCodec:   codec.Hex,
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
			StringCodec:   codec.Hex,
			SaltFunc:      func() string { return "salt1" },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
		}
		provider2 := &Provider{
			StringCodec:   codec.Hex,
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
			StringCodec: codec.Hex,
			SaltFunc:    func() string { return "same-salt" },
		}
		providerBase64 := &Provider{
			StringCodec: codec.Base64Std,
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
			StringCodec: codec.Base64Std,
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
			StringCodec:   codec.Hex,
			SaltFunc:      func() string { return "salt1" },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
		}
		provider2 := &Provider{
			StringCodec:   codec.Hex,
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
			StringCodec:   codec.Hex,
			SaltFunc:      func() string { return "salt1" },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
		}
		provider2 := &Provider{
			StringCodec:   codec.Hex,
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
			StringCodec:   codec.Hex,
			SaltFunc:      func() string { return "salt1" },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
		}
		provider2 := &Provider{
			StringCodec:   codec.Hex,
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
			StringCodec: codec.Hex,
			SaltFunc:    func() string { return "salt1" },
		}
		provider2 := &Provider{
			StringCodec: codec.Base64Std,
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
			StringCodec:   codec.Hex,
			SaltFunc:      func() string { return salt },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
		}
		providerPbkdf2 := &Provider{
			StringCodec:   codec.Hex,
			SaltFunc:      func() string { return salt },
			KeyDerivation: kdf.CheapPbkdf2(),
		}
		providerArgon2 := &Provider{
			StringCodec:   codec.Hex,
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
			StringCodec:   codec.Hex,
			SaltFunc:      func() string { return salt },
			KeyDerivation: kdf.NewScrypt(1024, 8, 1),
		}
		providerDefault := &Provider{
			StringCodec:   codec.Hex,
			SaltFunc:      func() string { return salt },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
		}
		providerStrong := &Provider{
			StringCodec:   codec.Hex,
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
			StringCodec:   codec.Hex,
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
			StringCodec:   codec.Hex,
			SaltFunc:      func() string { return salt },
			KeyDerivation: kdf.NewScrypt(2048, 8, 1),
		}
		providerPbkdf2 := &Provider{
			StringCodec:   codec.Hex,
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
		t.Logf("DefaultProvider.StringCodec: \n%#v", DefaultProvider.StringCodec)

		// Create a manual provider with the same default configuration
		manualProvider := &Provider{
			StringCodec:   DefaultProvider.StringCodec,
			SaltFunc:      DefaultProvider.SaltFunc,
			KeyDerivation: kdf.NewArgon2id(1, 16*1024, 1), // i.e. the kdf.CheapArgon2id()
		}

		// Keys should be identical
		key1 := DefaultProvider.NewAesKey(passphrase)
		key2 := manualProvider.NewAesKey(passphrase)

		if !bytesEqual(key1.Bytes(), key2.Bytes()) {
			t.Error("DefaultProvider should use Argon2id with Time: 1, Memory: 16*1024, Threads: 1 for backward compatibility to v2.x")
		}
	})

	t.Run("Custom KDF works with all key derivation methods", func(t *testing.T) {
		provider := &Provider{
			StringCodec:   codec.Hex,
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
			StringCodec:   codec.Hex,
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
			StringCodec:   codec.Hex,
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
			StringCodec:   codec.Hex,
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
			StringCodec:   codec.Hex,
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
				StringCodec:   codec.Hex,
				SaltFunc:      func() string { return "salt1" },
				KeyDerivation: kdf.CheapScrypt(),
			},
			{
				StringCodec:   codec.Hex,
				SaltFunc:      func() string { return "salt2" },
				KeyDerivation: kdf.CheapPbkdf2(),
			},
			{
				StringCodec:   codec.Hex,
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

// bytesEqual is a helper function to check if two byte slices are equal.
func bytesEqual(a, b []byte) bool {
	// return bytes.Equal(a, b)
	return string(a) == string(b)
}

func ExampleNewProvider() {
	sc := NewProvider(
		WithSaltFunc(func() string { return "example-salt" }),
		WithStringCodec(codec.Base64Std),
		WithKeyDerivation(kdf.NewScrypt(16*1024, 8, 1)),
	)

	cipher := sc.SimpleCTR("example-password")
	plaintext := "Hello, Example!"

	encrypted, _ := cipher.Encrypt(plaintext)
	decrypted, _ := cipher.Decrypt(encrypted)

	fmt.Println(decrypted)
	// Output: Hello, Example!
}

// Example_defaultProvider demonstrates using the DefaultProvider.
func ExampleDefaultProvider() {
	// uses the DefaultProvider internally
	cipher := SimpleCTR("my-password")
	plaintext := "Hello, World!"

	encrypted, err := cipher.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}

	// or you can use DefaultProvider explicitly
	cipher = DefaultProvider.SimpleCTR("my-password")

	decrypted, err := cipher.Decrypt(encrypted)
	if err != nil {
		panic(err)
	}

	fmt.Println(decrypted)
	// Output: Hello, World!
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
