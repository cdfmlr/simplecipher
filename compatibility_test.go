package simplecipher

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/cdfmlr/simplecipher/v2/codec"
	"github.com/cdfmlr/simplecipher/v2/dontpanic"
)

// This file provides compatibility tests to ensure that
// key generation and cipher algorithms with default options (salt, mainly)
// always produce the same output for the same input across minor versions.

// The current hardcoded expected values are for version v2.*.*
// It is expected the previous (v0.*.*, v1.*.*) or next (v3.*.*) major versions
// will NOT be compatible with these values.

// Results across major versions may differ if the default key generation
// method / default salt value changes.

func TestDefaultConfigurations(t *testing.T) {
	gotDefaultSalt := DefaultProvider.SaltFunc()
	expectedDefaultSalt := "5f11a4921aea524b9d3cb7f2514b0724"
	if gotDefaultSalt != expectedDefaultSalt {
		t.Errorf("Default salt mismatch: expected %s, got %s", expectedDefaultSalt, gotDefaultSalt)
	}

	gotDefaultCodec := codec.DefaultStringCodec
	expectedCodec := codec.Hex
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
		expectedHexKey := "2eea684f8fff4bdefaad200437773bf748df25ba4da7894a15fbf33c983dd943"
		generatedKey := g.Bytes()
		generatedHexKey := hex.EncodeToString(generatedKey)

		if generatedHexKey != expectedHexKey {
			t.Errorf("Key generation compatibility test failed: expected %s, got %s", expectedHexKey, generatedHexKey)
		}
	})
	t.Run("defaultNewAesKey", func(t *testing.T) {
		// test that default options produce expected output
		g := NewAesKey("test-passphrase")

		expectedHexKey := "2b5da4f98c55132932d00e52d3a04e3e62bba7bf83eec7511bdb987ca7118f92"
		generatedKey := g.Bytes()
		generatedHexKey := hex.EncodeToString(generatedKey)

		if generatedHexKey != expectedHexKey {
			t.Errorf("Default key generation compatibility test failed: expected %s, got %s", expectedHexKey, generatedHexKey)
		}
	})
	t.Run("defaultNewNonce", func(t *testing.T) {
		// test that default options produce expected output
		g := NewNonce("test-passphrase")

		expectedHexKey := "12856a1b0344d333ea8ed26e"
		generatedKey := g.Bytes()
		generatedHexKey := hex.EncodeToString(generatedKey)

		if generatedHexKey != expectedHexKey {
			t.Errorf("Default nonce generation compatibility test failed: expected %s, got %s", expectedHexKey, generatedHexKey)
		}
	})
	t.Run("defaultNewIv", func(t *testing.T) {
		// notice that: NewIv is deterministic while NewRandomIv is not
		got := NewIv("test-passphrase-for-iv").Bytes()

		expectedHexKey := "25089e9197eb9d44d9c3d05d901ec6cf"
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
		expectedKey := "c312ee53fe8fa080fc4700c30d04e0c4845677dd0dc7895cb0239cbead78477c"

		gotKey := cipher.(*streamToBlock).Stream.(*steam).key.Bytes()
		gotHexKey := hex.EncodeToString(gotKey)

		if gotHexKey != expectedKey {
			t.Errorf("Key derivation mismatch: expected %s, got %s", expectedKey, gotHexKey)
		}
	})

	plaintext := "The quick brown fox jumps over the lazy dog."
	expectedCiphertext := "c7c2537644adcd9ceb2bdd66fd1f2361c2a56a740c0cfef73f234f799555ce95ca87832de5eafd925e6b6313f03f75d23a38af9b6db3f37f233d0a33"

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

	fixedNonce := NewNonce("test-nonce-for-gcm")
	cipher.(*gcm).nonce = fixedNonce

	t.Run("keyDerivation", func(t *testing.T) {
		expectedKey := "b4dc3178e0dac469939124c6c64edd7064e903aa7ab9395c843c9e17781d9db2"

		gotKey := cipher.(*gcm).key.Bytes()
		gotHexKey := hex.EncodeToString(gotKey)

		if gotHexKey != expectedKey {
			t.Errorf("Key derivation mismatch: expected %s, got %s", expectedKey, gotHexKey)
		}

		expectedNonce := "5713ceee6756f8cedd94c285"

		gotNonce := cipher.(*gcm).nonce.Bytes()
		gotHexNonce := hex.EncodeToString(gotNonce)

		if gotHexNonce != expectedNonce {
			t.Errorf("Nonce derivation mismatch: expected %s, got %s", expectedNonce, gotHexNonce)
		}

		expectedAad := "c53f57bccb3c917f1d8f8e8b"

		gotAad := cipher.(*gcm).additionalData.Bytes()
		gotHexAad := hex.EncodeToString(gotAad)

		if gotHexAad != expectedAad {
			t.Errorf("Aad derivation mismatch: expected %s, got %s", expectedAad, gotHexAad)
		}
	})

	plaintext := "The quick brown fox jumps over the lazy dog."
	expectedCiphertext := "5713ceee6756f8cedd94c285cbec2ad626d419a71cf11446bc233772a972b96f16c93a8c706f29e21f085437cca8b866748ba9bbac54ae8aba9a3daac7405598f2090620843ede4b"

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

func Test_recoverFromPanic(t *testing.T) {
	var err error

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("failed to recover a panic: %v", r)
		}
		if !errors.Is(err, dontpanic.ErrPanic) {
			t.Errorf("expected error to wrap ErrPanic, got: %v", err)
		}
		if !strings.Contains(err.Error(), "test panic") {
			t.Errorf("expected error message to contain 'test panic', got: %v", err)
		}
	}()

	defer dontpanic.RecoverTo(&err)

	panic("test panic")
}
