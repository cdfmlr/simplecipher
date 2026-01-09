package kdf

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"reflect"
	"testing"

	cryptoArgon2 "golang.org/x/crypto/argon2"
	cryptoHkdf "golang.org/x/crypto/hkdf"
	cryptoPbkdf2 "golang.org/x/crypto/pbkdf2"
	cryptoScrypt "golang.org/x/crypto/scrypt"
)

// Test_UpstreamKDFs tests the KDF implementations from golang.org/x/crypto.
func Test_UpstreamKDFs(t *testing.T) {
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

// TestProfileCompatibility tests backward compatibility of all preset KDF profiles.
// These tests use hardcoded expected results to ensure that profile implementations
// remain consistent across versions.
func TestProfileCompatibility(t *testing.T) {
	// Standard test vectors
	password := []byte("test_password_2026")
	salt := []byte("test_salt_16byte")
	keyLen := 16

	tests := []struct {
		name     string
		kdf      KeyDerivation
		expected string
	}{
		// argon2id
		{name: "CheapArgon2id", kdf: CheapArgon2id(), expected: "17647424170c121f7fb05fc5b6ee5c0d"},
		{name: "RecommendedArgon2id", kdf: RecommendedArgon2id(), expected: "e9efc53ffc21efd88955364463436b70"},
		{name: "StrongArgon2id", kdf: StrongArgon2id(), expected: "9fc99deb1536ce0bea578f92fbedf4ee"},
		// scrypt
		{name: "CheapScrypt", kdf: CheapScrypt(), expected: "7a2a7791b09b0b24dc3f62b51f0eb155"},
		{name: "RecommendedScrypt", kdf: RecommendedScrypt(), expected: "42896e046cb6aa97ebf0685730cb969c"},
		{name: "StrongScrypt", kdf: StrongScrypt(), expected: "f584290f8c90f9d1eee2f14d83584b1b"},
		// pbkdf2
		{name: "CheapPbkdf2", kdf: CheapPbkdf2(), expected: "46776df24f5c4d4b0a0b3486c23731ac"},
		{name: "RecommendedPbkdf2", kdf: RecommendedPbkdf2(), expected: "37d6ff4d59d1ef7fef982490adeb7220"},
		{name: "StrongPbkdf2", kdf: StrongPbkdf2(), expected: "c3b3df49373975d3eea6babd6c7f8b21"},
		// hkdf
		{name: "CheapHkdf", kdf: CheapHkdf(), expected: "c364e1b9f7c0b3c533eef07e43e90c43"},
		{name: "RecommendedHkdf", kdf: RecommendedHkdf(), expected: "973ed707fb726832cb6c7baccf0eb365"},
		{name: "StrongHkdf", kdf: StrongHkdf(), expected: "5a6cfc3b9d27a157c109fb15e4339b01"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := tt.kdf.Derive(password, salt, keyLen)
			if err != nil {
				t.Errorf("%s got error: %v, expected: nil", tt.name, err)
			}

			gotHex := hex.EncodeToString(key)
			if gotHex != tt.expected {
				t.Errorf("%s backward compatibility broken:\n  Got:      %s\n  Expected: %s",
					tt.name, gotHex, tt.expected)
			}

			t.Logf("%s got expected result: %s", tt.name, gotHex)
		})
	}
}

// TestArgon2id tests the Argon2id KeyDerivation implementation
func TestArgon2id(t *testing.T) {
	password := []byte("test_password_123")
	salt := []byte("test_salt_value_")
	keyLen := 32

	t.Run("basic derivation", func(t *testing.T) {
		kdf := NewArgon2id(1, 64*1024, 4)
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("deterministic output", func(t *testing.T) {
		kdf := NewArgon2id(1, 64*1024, 4)
		key1, err1 := kdf.Derive(password, salt, keyLen)
		key2, err2 := kdf.Derive(password, salt, keyLen)

		if err1 != nil || err2 != nil {
			t.Fatalf("Derive failed: %v, %v", err1, err2)
		}
		if !bytes.Equal(key1, key2) {
			t.Error("Same inputs should produce same output")
		}
	})

	t.Run("different passwords produce different keys", func(t *testing.T) {
		kdf := NewArgon2id(1, 64*1024, 4)
		key1, _ := kdf.Derive([]byte("password1"), salt, keyLen)
		key2, _ := kdf.Derive([]byte("password2"), salt, keyLen)

		if bytes.Equal(key1, key2) {
			t.Error("Different passwords should produce different keys")
		}
	})

	t.Run("different salts produce different keys", func(t *testing.T) {
		kdf := NewArgon2id(1, 64*1024, 4)
		key1, _ := kdf.Derive(password, []byte("salt1___________"), keyLen)
		key2, _ := kdf.Derive(password, []byte("salt2___________"), keyLen)

		if bytes.Equal(key1, key2) {
			t.Error("Different salts should produce different keys")
		}
	})

	t.Run("different key lengths", func(t *testing.T) {
		kdf := NewArgon2id(1, 64*1024, 4)
		key16, _ := kdf.Derive(password, salt, 16)
		key32, _ := kdf.Derive(password, salt, 32)
		key64, _ := kdf.Derive(password, salt, 64)

		if len(key16) != 16 || len(key32) != 32 || len(key64) != 64 {
			t.Error("Key lengths don't match requested lengths")
		}
	})

	t.Run("CheapArgon2id profile", func(t *testing.T) {
		kdf := CheapArgon2id()
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("CheapArgon2id Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("RecommendedArgon2id profile", func(t *testing.T) {
		kdf := RecommendedArgon2id()
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("RecommendedArgon2id Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("StrongArgon2id profile", func(t *testing.T) {
		kdf := StrongArgon2id()
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("StrongArgon2id Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("empty password", func(t *testing.T) {
		kdf := NewArgon2id(1, 64*1024, 4)
		key, err := kdf.Derive([]byte(""), salt, keyLen)
		if err != nil {
			t.Fatalf("Derive with empty password failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("empty salt", func(t *testing.T) {
		kdf := NewArgon2id(1, 64*1024, 4)
		key, err := kdf.Derive(password, []byte(""), keyLen)
		if err != nil {
			t.Fatalf("Derive with empty salt failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})
}

// TestPbkdf2 tests the PBKDF2 KeyDerivation implementation
func TestPbkdf2(t *testing.T) {
	password := []byte("test_password_123")
	salt := []byte("test_salt_value_")
	keyLen := 32

	t.Run("basic derivation with SHA256", func(t *testing.T) {
		kdf := NewPbkdf2(10000, sha256.New)
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("basic derivation with SHA1", func(t *testing.T) {
		kdf := NewPbkdf2(10000, sha1.New)
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("basic derivation with SHA512", func(t *testing.T) {
		kdf := NewPbkdf2(10000, sha512.New)
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("deterministic output", func(t *testing.T) {
		kdf := NewPbkdf2(10000, sha256.New)
		key1, err1 := kdf.Derive(password, salt, keyLen)
		key2, err2 := kdf.Derive(password, salt, keyLen)

		if err1 != nil || err2 != nil {
			t.Fatalf("Derive failed: %v, %v", err1, err2)
		}
		if !bytes.Equal(key1, key2) {
			t.Error("Same inputs should produce same output")
		}
	})

	t.Run("different passwords produce different keys", func(t *testing.T) {
		kdf := NewPbkdf2(10000, sha256.New)
		key1, _ := kdf.Derive([]byte("password1"), salt, keyLen)
		key2, _ := kdf.Derive([]byte("password2"), salt, keyLen)

		if bytes.Equal(key1, key2) {
			t.Error("Different passwords should produce different keys")
		}
	})

	t.Run("different salts produce different keys", func(t *testing.T) {
		kdf := NewPbkdf2(10000, sha256.New)
		key1, _ := kdf.Derive(password, []byte("salt1___________"), keyLen)
		key2, _ := kdf.Derive(password, []byte("salt2___________"), keyLen)

		if bytes.Equal(key1, key2) {
			t.Error("Different salts should produce different keys")
		}
	})

	t.Run("different iterations produce different keys", func(t *testing.T) {
		kdf1 := NewPbkdf2(1000, sha256.New)
		kdf2 := NewPbkdf2(10000, sha256.New)
		key1, _ := kdf1.Derive(password, salt, keyLen)
		key2, _ := kdf2.Derive(password, salt, keyLen)

		if bytes.Equal(key1, key2) {
			t.Error("Different iteration counts should produce different keys")
		}
	})

	t.Run("different hash functions produce different keys", func(t *testing.T) {
		kdf1 := NewPbkdf2(10000, sha256.New)
		kdf2 := NewPbkdf2(10000, sha512.New)
		key1, _ := kdf1.Derive(password, salt, keyLen)
		key2, _ := kdf2.Derive(password, salt, keyLen)

		if bytes.Equal(key1, key2) {
			t.Error("Different hash functions should produce different keys")
		}
	})

	t.Run("different key lengths", func(t *testing.T) {
		kdf := NewPbkdf2(10000, sha256.New)
		key16, _ := kdf.Derive(password, salt, 16)
		key32, _ := kdf.Derive(password, salt, 32)
		key64, _ := kdf.Derive(password, salt, 64)

		if len(key16) != 16 || len(key32) != 32 || len(key64) != 64 {
			t.Error("Key lengths don't match requested lengths")
		}
	})

	t.Run("CheapPbkdf2 profile", func(t *testing.T) {
		kdf := CheapPbkdf2()
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("CheapPbkdf2 Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("RecommendedPbkdf2 profile", func(t *testing.T) {
		kdf := RecommendedPbkdf2()
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("RecommendedPbkdf2 Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("StrongPbkdf2 profile", func(t *testing.T) {
		kdf := StrongPbkdf2()
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("StrongPbkdf2 Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("empty password", func(t *testing.T) {
		kdf := NewPbkdf2(10000, sha256.New)
		key, err := kdf.Derive([]byte(""), salt, keyLen)
		if err != nil {
			t.Fatalf("Derive with empty password failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("empty salt", func(t *testing.T) {
		kdf := NewPbkdf2(10000, sha256.New)
		key, err := kdf.Derive(password, []byte(""), keyLen)
		if err != nil {
			t.Fatalf("Derive with empty salt failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("low iteration count", func(t *testing.T) {
		kdf := NewPbkdf2(1, sha256.New)
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("Derive with low iteration count failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})
}

// TestScrypt tests the Scrypt KeyDerivation implementation
func TestScrypt(t *testing.T) {
	password := []byte("test_password_123")
	salt := []byte("test_salt_value_")
	keyLen := 32

	t.Run("basic derivation", func(t *testing.T) {
		kdf := NewScrypt(16384, 8, 1)
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("deterministic output", func(t *testing.T) {
		kdf := NewScrypt(16384, 8, 1)
		key1, err1 := kdf.Derive(password, salt, keyLen)
		key2, err2 := kdf.Derive(password, salt, keyLen)

		if err1 != nil || err2 != nil {
			t.Fatalf("Derive failed: %v, %v", err1, err2)
		}
		if !bytes.Equal(key1, key2) {
			t.Error("Same inputs should produce same output")
		}
	})

	t.Run("different passwords produce different keys", func(t *testing.T) {
		kdf := NewScrypt(16384, 8, 1)
		key1, _ := kdf.Derive([]byte("password1"), salt, keyLen)
		key2, _ := kdf.Derive([]byte("password2"), salt, keyLen)

		if bytes.Equal(key1, key2) {
			t.Error("Different passwords should produce different keys")
		}
	})

	t.Run("different salts produce different keys", func(t *testing.T) {
		kdf := NewScrypt(16384, 8, 1)
		key1, _ := kdf.Derive(password, []byte("salt1___________"), keyLen)
		key2, _ := kdf.Derive(password, []byte("salt2___________"), keyLen)

		if bytes.Equal(key1, key2) {
			t.Error("Different salts should produce different keys")
		}
	})

	t.Run("different N parameters produce different keys", func(t *testing.T) {
		kdf1 := NewScrypt(16384, 8, 1)
		kdf2 := NewScrypt(32768, 8, 1)
		key1, _ := kdf1.Derive(password, salt, keyLen)
		key2, _ := kdf2.Derive(password, salt, keyLen)

		if bytes.Equal(key1, key2) {
			t.Error("Different N parameters should produce different keys")
		}
	})

	t.Run("different r parameters produce different keys", func(t *testing.T) {
		kdf1 := NewScrypt(16384, 8, 1)
		kdf2 := NewScrypt(16384, 16, 1)
		key1, _ := kdf1.Derive(password, salt, keyLen)
		key2, _ := kdf2.Derive(password, salt, keyLen)

		if bytes.Equal(key1, key2) {
			t.Error("Different r parameters should produce different keys")
		}
	})

	t.Run("different p parameters produce different keys", func(t *testing.T) {
		kdf1 := NewScrypt(16384, 8, 1)
		kdf2 := NewScrypt(16384, 8, 2)
		key1, _ := kdf1.Derive(password, salt, keyLen)
		key2, _ := kdf2.Derive(password, salt, keyLen)

		if bytes.Equal(key1, key2) {
			t.Error("Different p parameters should produce different keys")
		}
	})

	t.Run("different key lengths", func(t *testing.T) {
		kdf := NewScrypt(16384, 8, 1)
		key16, _ := kdf.Derive(password, salt, 16)
		key32, _ := kdf.Derive(password, salt, 32)
		key64, _ := kdf.Derive(password, salt, 64)

		if len(key16) != 16 || len(key32) != 32 || len(key64) != 64 {
			t.Error("Key lengths don't match requested lengths")
		}
	})

	t.Run("CheapScrypt profile", func(t *testing.T) {
		kdf := CheapScrypt()
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("CheapScrypt Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("RecommendedScrypt profile", func(t *testing.T) {
		kdf := RecommendedScrypt()
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("RecommendedScrypt Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("StrongScrypt profile", func(t *testing.T) {
		kdf := StrongScrypt()
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("StrongScrypt Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("empty password", func(t *testing.T) {
		kdf := NewScrypt(16384, 8, 1)
		key, err := kdf.Derive([]byte(""), salt, keyLen)
		if err != nil {
			t.Fatalf("Derive with empty password failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("empty salt", func(t *testing.T) {
		kdf := NewScrypt(16384, 8, 1)
		key, err := kdf.Derive(password, []byte(""), keyLen)
		if err != nil {
			t.Fatalf("Derive with empty salt failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("invalid N parameter (not power of 2)", func(t *testing.T) {
		kdf := NewScrypt(16383, 8, 1) // Not a power of 2
		_, err := kdf.Derive(password, salt, keyLen)
		if err == nil {
			t.Error("Expected error with invalid N parameter, got nil")
		}
	})

	t.Run("invalid parameters (r * p >= 2^30)", func(t *testing.T) {
		kdf := NewScrypt(16384, 1<<15, 1<<15)
		_, err := kdf.Derive(password, salt, keyLen)
		if err == nil {
			t.Error("Expected error with invalid r*p parameter, got nil")
		}
	})
}

// TestHkdf tests the HKDF KeyDerivation implementation
func TestHkdf(t *testing.T) {
	password := []byte("test_password_123")
	salt := []byte("test_salt_value_")
	keyLen := 32

	t.Run("basic derivation with SHA256", func(t *testing.T) {
		kdf := NewHkdf(sha256.New, nil, 0)
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("basic derivation with SHA1", func(t *testing.T) {
		kdf := NewHkdf(sha1.New, nil, 0)
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("basic derivation with SHA512", func(t *testing.T) {
		kdf := NewHkdf(sha512.New, nil, 0)
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("derivation with info", func(t *testing.T) {
		info := []byte("application specific context")
		kdf := NewHkdf(sha256.New, info, 0)
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("derivation with iterations", func(t *testing.T) {
		kdf := NewHkdf(sha256.New, nil, 3)
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("deterministic output", func(t *testing.T) {
		kdf := NewHkdf(sha256.New, nil, 0)
		key1, err1 := kdf.Derive(password, salt, keyLen)
		key2, err2 := kdf.Derive(password, salt, keyLen)

		if err1 != nil || err2 != nil {
			t.Fatalf("Derive failed: %v, %v", err1, err2)
		}
		if !bytes.Equal(key1, key2) {
			t.Error("Same inputs should produce same output")
		}
	})

	t.Run("different passwords produce different keys", func(t *testing.T) {
		kdf := NewHkdf(sha256.New, nil, 0)
		key1, _ := kdf.Derive([]byte("password1"), salt, keyLen)
		key2, _ := kdf.Derive([]byte("password2"), salt, keyLen)

		if bytes.Equal(key1, key2) {
			t.Error("Different passwords should produce different keys")
		}
	})

	t.Run("different salts produce different keys", func(t *testing.T) {
		kdf := NewHkdf(sha256.New, nil, 0)
		key1, _ := kdf.Derive(password, []byte("salt1___________"), keyLen)
		key2, _ := kdf.Derive(password, []byte("salt2___________"), keyLen)

		if bytes.Equal(key1, key2) {
			t.Error("Different salts should produce different keys")
		}
	})

	t.Run("different info produce different keys", func(t *testing.T) {
		kdf1 := NewHkdf(sha256.New, []byte("info1"), 0)
		kdf2 := NewHkdf(sha256.New, []byte("info2"), 0)
		key1, _ := kdf1.Derive(password, salt, keyLen)
		key2, _ := kdf2.Derive(password, salt, keyLen)

		if bytes.Equal(key1, key2) {
			t.Error("Different info should produce different keys")
		}
	})

	t.Run("different iterations produce different keys", func(t *testing.T) {
		kdf1 := NewHkdf(sha256.New, nil, 0)
		kdf2 := NewHkdf(sha256.New, nil, 1)
		key1, _ := kdf1.Derive(password, salt, keyLen)
		key2, _ := kdf2.Derive(password, salt, keyLen)

		if bytes.Equal(key1, key2) {
			t.Error("Different iterations should produce different keys")
		}
	})

	t.Run("different hash functions produce different keys", func(t *testing.T) {
		kdf1 := NewHkdf(sha256.New, nil, 0)
		kdf2 := NewHkdf(sha512.New, nil, 0)
		key1, _ := kdf1.Derive(password, salt, keyLen)
		key2, _ := kdf2.Derive(password, salt, keyLen)

		if bytes.Equal(key1, key2) {
			t.Error("Different hash functions should produce different keys")
		}
	})

	t.Run("different key lengths", func(t *testing.T) {
		kdf := NewHkdf(sha256.New, nil, 0)
		key16, _ := kdf.Derive(password, salt, 16)
		key32, _ := kdf.Derive(password, salt, 32)
		key64, _ := kdf.Derive(password, salt, 64)

		if len(key16) != 16 || len(key32) != 32 || len(key64) != 64 {
			t.Error("Key lengths don't match requested lengths")
		}
	})

	t.Run("CheapHkdf profile", func(t *testing.T) {
		kdf := CheapHkdf()
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("CheapHkdf Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("RecommendedHkdf profile", func(t *testing.T) {
		kdf := RecommendedHkdf()
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("RecommendedHkdf Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("StrongHkdf profile", func(t *testing.T) {
		kdf := StrongHkdf()
		key, err := kdf.Derive(password, salt, keyLen)
		if err != nil {
			t.Fatalf("StrongHkdf Derive failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("empty password", func(t *testing.T) {
		kdf := NewHkdf(sha256.New, nil, 0)
		key, err := kdf.Derive([]byte(""), salt, keyLen)
		if err != nil {
			t.Fatalf("Derive with empty password failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("empty salt", func(t *testing.T) {
		kdf := NewHkdf(sha256.New, nil, 0)
		key, err := kdf.Derive(password, []byte(""), keyLen)
		if err != nil {
			t.Fatalf("Derive with empty salt failed: %v", err)
		}
		if len(key) != keyLen {
			t.Errorf("Expected key length %d, got %d", keyLen, len(key))
		}
	})

	t.Run("large key length", func(t *testing.T) {
		kdf := NewHkdf(sha256.New, nil, 0)
		// SHA256 can produce up to 255 * HashLen bytes
		largeKeyLen := 255 * 32
		key, err := kdf.Derive(password, salt, largeKeyLen)
		if err != nil {
			t.Fatalf("Derive with large key length failed: %v", err)
		}
		if len(key) != largeKeyLen {
			t.Errorf("Expected key length %d, got %d", largeKeyLen, len(key))
		}
	})
}

// TestKeyDerivationInterface tests that all implementations satisfy the interface
func TestKeyDerivationInterface(t *testing.T) {
	password := []byte("test_password")
	salt := []byte("test_salt_16byte")
	keyLen := 32

	implementations := []struct {
		name string
		kdf  KeyDerivation
	}{
		{"Argon2id", NewArgon2id(1, 16*1024, 1)},
		{"Pbkdf2", NewPbkdf2(1000, sha256.New)},
		{"Scrypt", NewScrypt(16384, 8, 1)},
		{"Hkdf", NewHkdf(sha256.New, nil, 0)},
	}

	for _, impl := range implementations {
		t.Run(impl.name, func(t *testing.T) {
			key, err := impl.kdf.Derive(password, salt, keyLen)
			if err != nil {
				t.Errorf("%s.Derive failed: %v", impl.name, err)
			}
			if len(key) != keyLen {
				t.Errorf("%s: expected key length %d, got %d", impl.name, keyLen, len(key))
			}
		})
	}
}

// Benchmark profiles
//
//	go test -bench . -benchmem > benchmark-result.txt
func BenchmarkProfiles(b *testing.B) {
	param := struct {
		password []byte
		salt     []byte
		keyLen   int
	}{
		password: []byte("benchmark_password"),
		salt:     []byte("benchmark_salt16"),
		keyLen:   32,
	}

	profiles := []struct {
		name string
		kdf  KeyDerivation
	}{
		{"CheapArgon2id", CheapArgon2id()},
		{"RecommendedArgon2id", RecommendedArgon2id()},
		{"StrongArgon2id", StrongArgon2id()},

		{"CheapScrypt", CheapScrypt()},
		{"RecommendedScrypt", RecommendedScrypt()},
		{"StrongScrypt", StrongScrypt()},

		{"CheapPbkdf2", CheapPbkdf2()},
		{"RecommendedPbkdf2", RecommendedPbkdf2()},
		{"StrongPbkdf2", StrongPbkdf2()},

		{"CheapHkdf", CheapHkdf()},
		{"RecommendedHkdf", RecommendedHkdf()},
		{"StrongHkdf", StrongHkdf()},
	}

	for _, profile := range profiles {
		b.Run(profile.name, func(b *testing.B) {
			kdf := profile.kdf
			param := param // used to be chosen from a params slice
			for b.Loop() {
				_, _ = kdf.Derive(param.password, param.salt, param.keyLen)
			}
		})
	}
}
