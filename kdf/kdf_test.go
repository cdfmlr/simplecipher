package kdf

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"reflect"
	"testing"

	cryptoArgon2 "golang.org/x/crypto/argon2"
	cryptoHkdf "golang.org/x/crypto/hkdf"
	cryptoPbkdf2 "golang.org/x/crypto/pbkdf2"
	cryptoScrypt "golang.org/x/crypto/scrypt"
)

// Test_KDFs tests the KDF implementations from golang.org/x/crypto.
func Test_KDFs(t *testing.T) {
	password := []byte("some password")
	salt := []byte("somesaltvalue12") // 16 bytes salt
	keyLen := 32

	t.Run("argon2id", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("argon2id panicked: %v", r)
			}
		}()

		gotKey := cryptoArgon2.IDKey(password, salt, 1, 64*1024, 4, uint32(keyLen))

		gotKeyHex := hex.EncodeToString(gotKey)
		expectedKeyHex := "1ef067f6c2bedd422b7ed99d8315a8a5f28d4ea6cb03cd68783bb9f8c9d5622b"

		if !reflect.DeepEqual(gotKeyHex, expectedKeyHex) {
			t.Errorf("argon2id key mismatch:\n  Got:\n%v\n  Want:\n%v", gotKeyHex, expectedKeyHex)
		}

		t.Logf("argon2id: derived key: %v", gotKeyHex)
	})

	t.Run("scrypt", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("scrypt panicked: %v", r)
			}
		}()

		gotKey, err := cryptoScrypt.Key(password, salt, 32768, 8, 1, keyLen)
		if err != nil {
			t.Errorf("scrypt.Key returned error: %v", err)
		}

		gotKeyHex := hex.EncodeToString(gotKey)
		expectedKeyHex := "479acc67f6bae871c290331f82b0ffa9b38e6498370672e9f313b9e6145febde"

		if !reflect.DeepEqual(gotKeyHex, expectedKeyHex) {
			t.Errorf("scrypt key mismatch:\n  Got:\n%v\n  Want:\n%v", gotKeyHex, expectedKeyHex)
		}

		t.Logf("scrypt: derived key: %v", gotKeyHex)
	})

	t.Run("pbkdf2", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("pbkdf2 panicked: %v", r)
			}
		}()

		gotKey := cryptoPbkdf2.Key(password, salt, 4096, keyLen, sha1.New)

		gotKeyHex := hex.EncodeToString(gotKey)
		expectedKeyHex := "942276e6bddc924e0a32162c39ceae4383e67652e9f7d8b7bbf841a26929e57b"

		if !reflect.DeepEqual(gotKeyHex, expectedKeyHex) {
			t.Errorf("pbkdf2 key mismatch:\n  Got:\n%v\n  Want:\n%v", gotKeyHex, expectedKeyHex)
		}

		t.Logf("pbkdf2: derived key: %v", gotKeyHex)
	})

	t.Run("hkdf", func(t *testing.T) {
		// NOTICE: HKDF is not for key derivation from human-memorable passwords.

		defer func() {
			if r := recover(); r != nil {
				t.Errorf("hkdf panicked: %v", r)
			}
		}()

		hkdfReader := cryptoHkdf.New(sha256.New, password, salt, nil)

		gotKey := make([]byte, keyLen)
		_, err := io.ReadFull(hkdfReader, gotKey)
		if err != nil {
			t.Errorf("failed to read hkdf: %v", err)
		}

		gotKeyHex := hex.EncodeToString(gotKey)
		expectedKeyHex := "afe18a13793f3a4cb9fe2d6a3f85cad0e34a325ab00e981cdcf1b38e0be712da"

		if !reflect.DeepEqual(gotKeyHex, expectedKeyHex) {
			t.Errorf("hkdf key mismatch:\n  Got:\n%v\n  Want:\n%v", gotKeyHex, expectedKeyHex)
		}

		t.Logf("hkdf: derived key: %v", gotKeyHex)
	})
}
