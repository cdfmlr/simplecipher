package simplecipher

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"testing"
)

// testCipher tests the given cipher implementation.
//
// It encrypts and decrypts the plaintext using the cipher instance
// created by the newCipher function, and checks if the decrypted text
// is the same as the original plaintext.
//
// It repeats the same process with another cipher instance created
// to check if the implementation is deterministic.
func testCipher(name string, t *testing.T, newCipher func() Cipher, plaintext string) {
	// Make sure not using the default salt value
	// for (maybe) a tiny bit of more security for lazy users who don't
	// provide their own salt.
	DefaultSalt = func() string { return "testsalt" }

	cipher := newCipher()

	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("%v: Encrypt error: %v", name, err)
	}

	decrypted, err := cipher.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("%v: Decrypt error: %v", name, err)
	}

	if decrypted != plaintext {
		t.Fatalf("%v: decrypted (%s) != plaintext (%s)", name, decrypted, plaintext)
	}

	anotherCipher := newCipher()

	// encrypting by cipher and decrypting by anotherCipher

	anotherDecrypted, err := anotherCipher.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if anotherDecrypted != plaintext {
		t.Fatalf("%v: anotherDecrypted != plaintext", name)
	}

	// encrypting by anotherCipher and decrypting by cipher

	anotherCiphertext, err := anotherCipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("%v: anotherCipher Encrypt error: %v", name, err)
	}
	anotherCiphertextDecrypted, err := cipher.Decrypt(anotherCiphertext)
	if anotherCiphertextDecrypted != plaintext {
		t.Fatalf("%v: anotherCiphertextDecrypted != plaintext", name)
	}

	// we cannot compare the ciphertexts because the iv may be different
}

// testErrorCipher tests the given cipher implementation with a wrong setting.
// It is expected to error out (but not panic) when encrypting or decrypting.
func testErrorCipher(name string, t *testing.T, newCipher func() Cipher, plaintext string) {
	DefaultSalt = func() string { return "testsalt" }

	cipher := newCipher()

	errCount := 0

	_, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Logf("%v: expected Encrypt error: %v", name, err)
		errCount++
	} else {
		t.Logf("%v: Encrypt not erroring", name)
	}

	ciphertext := hex.EncodeToString([]byte(plaintext))
	_, err = cipher.Decrypt(ciphertext)
	if err != nil {
		t.Logf("%v: expected Decrypt error: %v", name, err)
		errCount++
	} else {
		t.Logf("%v: Decrypt not erroring", name)
	}

	if errCount == 0 {
		t.Fatalf("%v: expected error, got none", name)
	}
}

func FuzzNewCBC(f *testing.F) {
	// key: bytes, iv: bytes, plaintext: string
	f.Add([]byte("key0key1key2key3"), []byte("iv00iv01iv02iv03"), "plain-text-plain-text000")
	f.Add([]byte("key0key1key2key3key4key5key6key7"), []byte("iv00iv01iv02iv03"), "plain-text-plain")
	f.Add([]byte("badkey"), []byte("badnonce"), "badplaintext")

	f.Fuzz(func(t *testing.T, key, iv []byte, plaintext string) {
		createNewCBC := func() Cipher {
			return NewCBC(Bytes(key), Bytes(iv))
		}

		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			testErrorCipher("badKeyLen", t, createNewCBC, plaintext)
			return
		}
		if len(iv) != aes.BlockSize {
			testErrorCipher("badIvLen", t, createNewCBC, plaintext)
			return
		}
		// "output smaller than input" is no longer happening after prepending iv to ciphertext.
		//if len(plaintext) <= len(key)+len(iv) {
		//	testErrorCipher("outputSmallerThenInput", t, createNewCBC, plaintext)
		//	return
		//}
		if len(plaintext)%aes.BlockSize != 0 {
			testErrorCipher("badPlaintextLen", t, createNewCBC, plaintext)
			return
		}

		testCipher("", t, createNewCBC, plaintext)
	})
}

func FuzzSimpleCBC(f *testing.F) {
	// key: string, plaintext: string
	f.Add("key", "plain-text-plain-text000")
	f.Add("key", "plain-text-plain")

	f.Fuzz(func(t *testing.T, key, plaintext string) {
		createSimpleCBC := func() Cipher {
			return SimpleCBC(key)
		}

		testCipher("", t, createSimpleCBC, plaintext)
	})
}

func FuzzNewStreamAsBlock(f *testing.F) {
	newBlocks := map[string]func(key, iv Key) Cipher{
		"NewCFB": NewCFB,
		"NewCTR": NewCTR,
		"NewOFB": NewOFB,
	}

	// key: bytes, nonce: bytes, plaintext: string
	f.Add([]byte("key0key1key2key3"), []byte("iv00iv01iv02iv03"), "plain-text-plain-text000")
	f.Add([]byte("key0key1key2key3key4key5key6key7"), []byte("iv00iv01iv02iv03"), "plain-text-plain")
	f.Add([]byte("badkey"), []byte("badnonce"), "badplaintext")

	f.Fuzz(func(t *testing.T, key, iv []byte, plaintext string) {
		for name, newBlock := range newBlocks {
			createNewBlock := func() Cipher {
				return newBlock(Bytes(key), Bytes(iv))
			}

			if len(key) != 16 && len(key) != 24 && len(key) != 32 {
				testErrorCipher(name+"-badKeyLen", t, createNewBlock, plaintext)
				return
			}
			if len(iv) != aes.BlockSize {
				testErrorCipher(name+"-badIvLen", t, createNewBlock, plaintext)
				return
			}

			testCipher(name, t, createNewBlock, plaintext)
		}
	})
}

func FuzzSimpleStreamAsBlock(f *testing.F) {
	newBlocks := map[string]func(key string) Cipher{
		"SimpleCFB": SimpleCFB,
		"SimpleCTR": SimpleCTR,
		"SimpleOFB": SimpleOFB,
	}

	// key: string, plaintext: string
	f.Add("key", "plain-text-plain-text000")
	f.Add("key", "plain-text-plain")

	f.Fuzz(func(t *testing.T, key, plaintext string) {
		for name, newBlock := range newBlocks {
			createSimpleBlock := func() Cipher {
				return newBlock(key)
			}

			testCipher(name, t, createSimpleBlock, plaintext)
		}
	})
}

func ExampleSimpleCTR() {
	DefaultSalt = func() string { return "NaCl" }

	key := "my-secret-key"
	plainText := "Hello, World!"

	cipher := SimpleCTR(key)

	encrypted, _ := cipher.Encrypt(plainText)
	// fmt.Println(encrypted)

	decrypted, _ := cipher.Decrypt(encrypted)
	fmt.Println(decrypted)

	// Output: Hello, World!
}
