package simplecipher

import (
	"fmt"
	"testing"
	"time"
)

func FuzzNewGCM(f *testing.F) {
	// key: bytes, nonce: bytes, additionalData: bytes, plaintext: string
	f.Add([]byte("key0key1key2key3"), []byte("nonce0nonce1"), []byte("additionalData"), "plain-text-plain-text000")
	f.Add([]byte("key0key1key2key3key4key5key6key7"), []byte("nonce0nonce1"), []byte("additionalData"), "plain-text-plain")

	f.Fuzz(func(t *testing.T, key, nonce []byte, additionalData []byte, plaintext string) {
		// fix strange behavior of go fuzz that fucks with GCM:
		// Encrypt error: recovered from panic: crypto/cipher: invalid buffer overlap of output and additional data
		key = append([]byte{}, key...)
		nonce = append([]byte{}, nonce...)
		additionalData = append([]byte{}, additionalData...)

		createGCM := func(p *Provider) Block {
			return p.NewGCM(Bytes(key), Bytes(nonce), Bytes(additionalData))
		}

		// t.Logf("key len: %d, nonce len: %d, additionalData len: %d", len(key), len(nonce), len(additionalData))
		// t.Logf("key: %x", key)
		// t.Logf("nonce: %x", nonce)
		// t.Logf("additionalData: %x", additionalData)
		// t.Logf("plaintext: %s", plaintext)

		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			testErrorCipher("badKeyLen", t, createGCM, plaintext)
			return
		}
		if len(nonce) != 12 {
			testErrorCipher("badNonceLen", t, createGCM, plaintext)
			return
		}

		testCipher("", t, createGCM, plaintext)
	})
}

func FuzzSimpleGCM(f *testing.F) {
	// key: string, nonce: string, plaintext: string
	f.Add("key", "additionalData", "plaintext")

	f.Fuzz(func(t *testing.T, key, additionalData, plaintext string) {
		createSimpleGCM := func(p *Provider) Block {
			return p.SimpleGCM(key, additionalData)
		}

		testCipher("", t, createSimpleGCM, plaintext)
	})
}

func ExampleSimpleGCM() {
	sc := NewProvider(
		WithSaltFunc(func() string { return "NaCl" }),
	)

	key := "my-secret-key"
	aad := time.Now().Format(time.DateOnly)

	plainText := "Hello, World!"

	cipher := sc.SimpleGCM(key, aad)

	encrypted, _ := cipher.Encrypt(plainText)
	// fmt.Println(encrypted)

	decrypted, _ := cipher.Decrypt(encrypted)
	fmt.Println(decrypted)

	// Output: Hello, World!
}

// I failed to en/de-crypt GCM with openssl. So the interoperability
// is unsure, but the current GCM implementation is manually
// cross-checked with https://gchq.github.io/CyberChef/, the result lgtm.
