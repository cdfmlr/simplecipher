package simplecipher

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func FuzzNewGCM(f *testing.F) {
	// key: bytes, nonce: bytes, additionalData: bytes, plaintext: string
	f.Add([]byte("key0key1key2key3"), []byte("nonce0nonce1"), []byte("additionalData"), "plain-text-plain-text000")
	f.Add([]byte("key0key1key2key3key4key5key6key7"), []byte("nonce0nonce1"), []byte("additionalData"), "plain-text-plain")

	f.Fuzz(func(t *testing.T, key, nonce []byte, additionalData []byte, plaintext string) {
		// fix strange behavior of go fuzz that interferes with GCM:
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
	sc := Provider{
		StringCodec: HexCodec,
		SaltFunc:    func() string { return "NaCl" },
	}

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

// ////// GCM Stream Tests ////////

func FuzzNewGCMStream(f *testing.F) {
	// key: bytes, nonce: bytes, additionalData: bytes, plaintext: string
	f.Add([]byte("key0key1key2key3"), []byte("nonce0nonce1"), []byte("additionalData"), "plain-text-plain-text000")
	f.Add([]byte("key0key1key2key3key4key5key6key7"), []byte("nonce0nonce1"), []byte("additionalData"), "plain-text-plain")

	f.Fuzz(func(t *testing.T, key, nonce []byte, additionalData []byte, plaintext string) {
		// fix strange behavior of go fuzz that interferes with GCM:
		// Encrypt error: recovered from panic: crypto/cipher: invalid buffer overlap of output and additional data
		key = append([]byte{}, key...)
		nonce = append([]byte{}, nonce...)
		additionalData = append([]byte{}, additionalData...)

		createGCMStream := func(p *Provider) Stream {
			return p.NewGCMStream(Bytes(key), Bytes(nonce), Bytes(additionalData))
		}

		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			testErrorStream("badKeyLen", t, createGCMStream, plaintext)
			return
		}
		if len(nonce) != 12 {
			testErrorStream("badNonceLen", t, createGCMStream, plaintext)
			return
		}

		testStream("", t, createGCMStream, plaintext)
	})
}

func FuzzSimpleGCMStream(f *testing.F) {
	// key: string, additionalData: string, plaintext: string
	f.Add("key", "additionalData", "plaintext")

	f.Fuzz(func(t *testing.T, key, additionalData, plaintext string) {
		createSimpleGCMStream := func(p *Provider) Stream {
			return p.SimpleGCMStream(key, additionalData)
		}

		testStream("", t, createSimpleGCMStream, plaintext)
	})
}

func ExampleSimpleGCMStream() {
	sc := Provider{
		StringCodec: HexCodec,
		SaltFunc:    func() string { return "NaCl" },
	}

	key := "my-secret-key"
	aad := time.Now().Format(time.DateOnly)

	plainText := "Hello, World!"

	stream := sc.SimpleGCMStream(key, aad)

	// Encrypting
	plaintextReader := bytes.NewReader([]byte(plainText))
	encryptedBuffer := new(bytes.Buffer)

	_ = stream.EncryptStream(plaintextReader, encryptedBuffer)

	encrypted := encryptedBuffer.String()
	// fmt.Println(hex.EncodeToString([]byte(encrypted)))

	// Decrypting
	encryptedReader := bytes.NewReader([]byte(encrypted))
	decryptedBuffer := new(bytes.Buffer)

	_ = stream.DecryptStream(encryptedReader, decryptedBuffer)

	decrypted := decryptedBuffer.String()

	fmt.Println(decrypted)

	// Output: Hello, World!
}
