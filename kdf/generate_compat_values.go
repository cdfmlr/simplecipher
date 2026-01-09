//go:build ignore
// +build ignore

package main

import (
	"encoding/hex"
	"fmt"

	"github.com/cdfmlr/simplecipher/v2/kdf"
)

func main() {
	password := []byte("test_password_2026")
	salt := []byte("test_salt_16byte")
	keyLen := 16

	profiles := []struct {
		name string
		kdf  kdf.KeyDerivation
	}{
		{"CheapArgon2id", kdf.CheapArgon2id()},
		{"RecommendedArgon2id", kdf.RecommendedArgon2id()},
		{"StrongArgon2id", kdf.StrongArgon2id()},

		{"CheapScrypt", kdf.CheapScrypt()},
		{"RecommendedScrypt", kdf.RecommendedScrypt()},
		{"StrongScrypt", kdf.StrongScrypt()},

		{"CheapPbkdf2", kdf.CheapPbkdf2()},
		{"RecommendedPbkdf2", kdf.RecommendedPbkdf2()},
		{"StrongPbkdf2", kdf.StrongPbkdf2()},

		{"CheapHkdf", kdf.CheapHkdf()},
		{"RecommendedHkdf", kdf.RecommendedHkdf()},
		{"StrongHkdf", kdf.StrongHkdf()},
	}

	fmt.Printf("tests := []struct { name string; kdf KeyDerivation; expected string }{\n")
	for _, p := range profiles {
		key, err := p.kdf.Derive(password, salt, keyLen)
		if err != nil {
			panic(err)
		}
		// fmt.Printf("%20s: %s\n", p.name, hex.EncodeToString(key))
		fmt.Printf("    {name: %q, kdf: %s(), expected: %q},\n", p.name, p.name, hex.EncodeToString(key))
	}
	fmt.Printf("}\n")
}
