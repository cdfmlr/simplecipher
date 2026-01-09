package simplecipher

import (
	"encoding/hex"
	"testing"
)

// This file provides compatibility tests to ensure that
// key generation and cipher algorithms with default options (salt, mainly)
// always produce the same output for the same input across minor versions.

// The current hardcoded expected values are for version v0.* and v1.*.
// It is expected the next major version (v2.0.0) will NOT be compatible
// with these values.

// Results across major versions may differ if the default key generation
// method / default salt value changes.

func TestDefaultConfigurations(t *testing.T) {
	gotDefaultSalt := DefaultProvider.SaltFunc()
	expectedDefaultSalt := "5f11a4921aea524b9d3cb7f2514b0724"
	if gotDefaultSalt != expectedDefaultSalt {
		t.Errorf("Default salt mismatch: expected %s, got %s", expectedDefaultSalt, gotDefaultSalt)
	}

	gotDefaultCodec := DefaultStringCodec
	expectedCodec := HexCodec
	if gotDefaultCodec != expectedCodec {
		t.Errorf("Default string codec mismatch: expected %T, got %T", expectedCodec, gotDefaultCodec)
	}
}

func TestKeyGen_Compatibility(t *testing.T) {
	t.Run("keyGenAlgo", func(t *testing.T) {
		// test the algorithm produces deterministic output
		g := keyGen{
			Passphrase:    "test-passphrase",
			Len:           Aes256,
			Salt:          "test-salt",
			KeyDerivation: DefaultProvider.KeyDerivation,
		}

		// we hardcode the expected output here to ensure compatibility
		expectedHexKey := "eba123f25994cffa65e966cfb7dac9a392550c8d42bc293b0be3fd29bb38dfb1"
		generatedKey := g.Bytes()
		generatedHexKey := hex.EncodeToString(generatedKey)

		if generatedHexKey != expectedHexKey {
			t.Errorf("Key generation compatibility test failed: expected %s, got %s", expectedHexKey, generatedHexKey)
		}
	})
	t.Run("defaultNewAesKey", func(t *testing.T) {
		// test that default options produce expected output
		g := NewAesKey("test-passphrase")

		expectedHexKey := "cab609583b99f229cc5ad0a0091e87c1d1397a97261de4e187f5db6a445ef3fd"
		generatedKey := g.Bytes()
		generatedHexKey := hex.EncodeToString(generatedKey)

		if generatedHexKey != expectedHexKey {
			t.Errorf("Default key generation compatibility test failed: expected %s, got %s", expectedHexKey, generatedHexKey)
		}
	})
	t.Run("defaultNewNonce", func(t *testing.T) {
		// test that default options produce expected output
		g := NewNonce("test-passphrase")

		expectedHexKey := "cab609583b99f229cc5ad0a0"
		generatedKey := g.Bytes()
		generatedHexKey := hex.EncodeToString(generatedKey)

		if generatedHexKey != expectedHexKey {
			t.Errorf("Default nonce generation compatibility test failed: expected %s, got %s", expectedHexKey, generatedHexKey)
		}
	})
	t.Run("defaultNewIv", func(t *testing.T) {
		// notice that: NewIv is deterministic while NewRandomIv is not
		got := NewIv("test-passphrase-for-iv").Bytes()

		expectedHexKey := "8b2ea2c4c19b8f58cbef3452c30a857b"
		generatedKey := got
		generatedHexKey := hex.EncodeToString(generatedKey)

		if generatedHexKey != expectedHexKey {
			t.Errorf("Default IV generation compatibility test failed: expected %s, got %s", expectedHexKey, generatedHexKey)
		}

	})
}

func TestSimpleCTR_Compatibility(t *testing.T) {
	cipher := SimpleCTR("hello-world")

	// hack to set iv to deterministic value
	fixedIv := NewIv("test-iv-for-ctr")
	cipher.(*streamToBlock).Stream.(*steam).iv = fixedIv

	t.Run("keyDerivation", func(t *testing.T) {
		expectedKey := "862e69236dbd3a28de8a8bc30c98bca47d6906907355771ec0bda705e65a44f5"

		gotKey := cipher.(*streamToBlock).Stream.(*steam).key.Bytes()
		gotHexKey := hex.EncodeToString(gotKey)

		if gotHexKey != expectedKey {
			t.Errorf("Key derivation mismatch: expected %s, got %s", expectedKey, gotHexKey)
		}
	})

	plaintext := "The quick brown fox jumps over the lazy dog."
	expectedCiphertext := "102ff679517c6ca85312d3b38fa1de6faef72e66a44449290486355d6f92b37d34eeb294f654fa715c70a19cf0180741026f4b3e0e9116888c47c4d8"

	t.Run("encryption", func(t *testing.T) {
		ciphertext, err := cipher.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		if ciphertext != expectedCiphertext {
			t.Errorf("Ciphertext mismatch: expected %s, got %s", expectedCiphertext, ciphertext)
		}
	})

	t.Run("decryption", func(t *testing.T) {
		decryptedText, err := cipher.Decrypt(expectedCiphertext)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		if decryptedText != plaintext {
			t.Errorf("Decrypted text mismatch: expected %s, got %s", plaintext, decryptedText)
		}
	})
}

func TestSimpleGCM_Compatibility(t *testing.T) {
	cipher := SimpleGCM("hello-gcm-passphrase", "hello-gcm-nonce")

	t.Run("keyDerivation", func(t *testing.T) {
		expectedKey := "6dc9e1f2255e2f8a6bf6ff05b6320e1d8cf4597ecb5f920fac74f5df2a570570"

		gotKey := cipher.(*gcm).key.Bytes()
		gotHexKey := hex.EncodeToString(gotKey)

		if gotHexKey != expectedKey {
			t.Errorf("Key derivation mismatch: expected %s, got %s", expectedKey, gotHexKey)
		}

		expectedNonce := "832986af2346ff41fcce1b0a"

		gotNonce := cipher.(*gcm).nonce.Bytes()
		gotHexNonce := hex.EncodeToString(gotNonce)

		if gotHexNonce != expectedNonce {
			t.Errorf("Nonce derivation mismatch: expected %s, got %s", expectedNonce, gotHexNonce)
		}
	})

	plaintext := "The quick brown fox jumps over the lazy dog."
	expectedCiphertext := "1561086e16ade8addfdd7332c69be199a4afd8a817ca40896cf03bfda9a03b7e0a49c233eed5f31cff7604366195555cd7b671067bca78ba70c43bae"

	t.Run("encryption", func(t *testing.T) {
		ciphertext, err := cipher.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		if ciphertext != expectedCiphertext {
			t.Errorf("Ciphertext mismatch: expected %s, got %s", expectedCiphertext, ciphertext)
		}
	})

	t.Run("decryption", func(t *testing.T) {
		decryptedText, err := cipher.Decrypt(expectedCiphertext)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		if decryptedText != plaintext {
			t.Errorf("Decrypted text mismatch: expected %s, got %s", plaintext, decryptedText)
		}
	})
}
