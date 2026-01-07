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
	gotDefaultSalt := DefaultSalt()
	expectedDefaultSalt := "3c7bef42a1524af19442b1b0a5751d29"
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
	oldDefaultCodec := DefaultStringCodec
	defer func() {
		DefaultStringCodec = oldDefaultCodec
	}()
	DefaultStringCodec = HexCodec

	oldSalt := DefaultSalt
	defer func() {
		DefaultSalt = oldSalt
	}()
	DefaultSalt = func() string { return "3c7bef42a1524af19442b1b0a5751d29" }

	t.Run("keyGenAlgo", func(t *testing.T) {
		// test the algorithm produces deterministic output
		g := keyGen{
			Passphrase: "test-passphrase",
			Len:        Aes256,
			Salt:       "test-salt",
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

		expectedHexKey := "9a732599fd5d150bc8f7423ff1cf2bdc0d0c847e6d87496acc22742a9767b9b5"
		generatedKey := g.Bytes()
		generatedHexKey := hex.EncodeToString(generatedKey)

		if generatedHexKey != expectedHexKey {
			t.Errorf("Default key generation compatibility test failed: expected %s, got %s", expectedHexKey, generatedHexKey)
		}
	})
	t.Run("defaultNewNonce", func(t *testing.T) {
		// test that default options produce expected output
		g := NewNonce("test-passphrase")

		expectedHexKey := "9a732599fd5d150bc8f7423f"
		generatedKey := g.Bytes()
		generatedHexKey := hex.EncodeToString(generatedKey)

		if generatedHexKey != expectedHexKey {
			t.Errorf("Default nonce generation compatibility test failed: expected %s, got %s", expectedHexKey, generatedHexKey)
		}
	})
	t.Run("defaultNewIv", func(t *testing.T) {
		// notice that: NewIv is deterministic while NewRandomIv is not
		got := NewIv("test-passphrase-for-iv").Bytes()

		expectedHexKey := "2d977ef33e31fdd7a4ba914a68173018"
		generatedKey := got
		generatedHexKey := hex.EncodeToString(generatedKey)

		if generatedHexKey != expectedHexKey {
			t.Errorf("Default IV generation compatibility test failed: expected %s, got %s", expectedHexKey, generatedHexKey)
		}

	})
}

func TestSimpleCTR_Compatibility(t *testing.T) {
	oldDefaultCodec := DefaultStringCodec
	defer func() {
		DefaultStringCodec = oldDefaultCodec
	}()
	DefaultStringCodec = HexCodec

	oldSalt := DefaultSalt
	defer func() {
		DefaultSalt = oldSalt
	}()
	DefaultSalt = func() string { return "3c7bef42a1524af19442b1b0a5751d29" }

	cipher := SimpleCTR("hello-world")

	// hack to set iv to deterministic value
	fixedIv := NewIv("test-iv-for-ctr")
	cipher.(*streamToBlock).Stream.(*steam).iv = fixedIv

	t.Run("keyDerivation", func(t *testing.T) {
		expectedKey := "c4a515a80c23eb49930284ceec73d1ba4b05755b3b0f103e2ab264614434f959"

		gotKey := cipher.(*streamToBlock).Stream.(*steam).key.Bytes()
		gotHexKey := hex.EncodeToString(gotKey)

		if gotHexKey != expectedKey {
			t.Errorf("Key derivation mismatch: expected %s, got %s", expectedKey, gotHexKey)
		}
	})

	plaintext := "The quick brown fox jumps over the lazy dog."
	expectedCiphertext := "c05325d9a20f8944892180fbe69a947ad94aae6cfcb329e677d977574bf150ad36e9ee2f0b607a2f28968c1a8e3bfef7410ef9ccf6449a16248ebb89"

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
	oldDefaultCodec := DefaultStringCodec
	defer func() {
		DefaultStringCodec = oldDefaultCodec
	}()
	DefaultStringCodec = HexCodec

	oldSalt := DefaultSalt
	defer func() {
		DefaultSalt = oldSalt
	}()
	DefaultSalt = func() string { return "3c7bef42a1524af19442b1b0a5751d29" }

	cipher := SimpleGCM("hello-gcm-passphrase", "hello-gcm-nonce")

	t.Run("keyDerivation", func(t *testing.T) {
		expectedKey := "1f06c0896e13ea9690c10e0b0a95738b9279727c7b8dc95244ec99d02850e4c2"

		gotKey := cipher.(*gcm).key.Bytes()
		gotHexKey := hex.EncodeToString(gotKey)

		if gotHexKey != expectedKey {
			t.Errorf("Key derivation mismatch: expected %s, got %s", expectedKey, gotHexKey)
		}

		expectedNonce := "81ee36b8443b2216aafd4abc"

		gotNonce := cipher.(*gcm).nonce.Bytes()
		gotHexNonce := hex.EncodeToString(gotNonce)

		if gotHexNonce != expectedNonce {
			t.Errorf("Nonce derivation mismatch: expected %s, got %s", expectedNonce, gotHexNonce)
		}
	})

	plaintext := "The quick brown fox jumps over the lazy dog."
	expectedCiphertext := "b5a70c351a43ddd0d772031dd7b03f33163d8b232ccf5a20f647da53010bf8cde63ac4b8d22c49884f34f7c2293af4982c2a9a50a68bf37188440792"

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
