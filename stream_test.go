package simplecipher

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func testErrorStream(name string, t *testing.T, newStream func() Stream, plaintext string) {
	DefaultSalt = func() string { return "testsalt" }

	errorCount := 0

	stream := newStream()

	plaintextReader := bytes.NewReader([]byte(plaintext))
	ciphertextWriter := new(bytes.Buffer)

	err := stream.EncryptStream(plaintextReader, ciphertextWriter)
	if err != nil {
		t.Logf("%v: expected EncryptStream error: %v", name, err)
		errorCount++
	} else {
		t.Logf("%v: EncryptStream not erroring", name)
	}

	ciphertextReader := bytes.NewReader(ciphertextWriter.Bytes())
	decryptedWriter := new(bytes.Buffer)

	err = stream.DecryptStream(ciphertextReader, decryptedWriter)
	if err != nil {
		t.Logf("%v: expected DecryptStream error: %v", name, err)
		errorCount++
	} else {
		t.Logf("%v: DecryptStream not erroring", name)
	}

	if errorCount == 0 {
		t.Fatalf("%v: expected error, got none", name)
	}
}

func testStream(name string, t *testing.T, newStream func() Stream, plaintext string) {
	DefaultSalt = func() string { return "testsalt" }

	stream := newStream()

	plaintextReader := bytes.NewReader([]byte(plaintext))
	ciphertextWriter := new(bytes.Buffer)

	err := stream.EncryptStream(plaintextReader, ciphertextWriter)
	if err != nil {
		t.Fatalf("%v: EncryptStream error: %v", name, err)
	}

	ciphertext := ciphertextWriter.String()

	ciphertextReader := bytes.NewReader([]byte(ciphertext))
	decryptedWriter := new(bytes.Buffer)

	err = stream.DecryptStream(ciphertextReader, decryptedWriter)
	if err != nil {
		t.Fatalf("%v: DecryptStream error: %v", name, err)
	}

	if decryptedWriter.String() != plaintext {
		t.Fatalf("%v: decrypted (%s) != plaintext (%s)", name, decryptedWriter.String(), plaintext)
	}

	// encrypting by stream and decrypting by anotherStream

	anotherStream := newStream()

	anotherDecryptedWriter := new(bytes.Buffer)
	ciphertextReader = bytes.NewReader([]byte(ciphertext))

	err = anotherStream.DecryptStream(ciphertextReader, anotherDecryptedWriter)
	if anotherDecryptedWriter.String() != plaintext {
		t.Fatalf("%v: anotherDecrypted (%s) != plaintext (%s):", name, anotherDecryptedWriter.String(), plaintext)
	}

	// encrypting by anotherStream and decrypting by stream

	anotherCiphertextWriter := new(bytes.Buffer)
	plaintextReader = bytes.NewReader([]byte(plaintext))

	err = anotherStream.EncryptStream(plaintextReader, anotherCiphertextWriter)
	if err != nil {
		t.Fatalf("%v: anotherStream EncryptStream error: %v", name, err)
	}

	anotherCiphertextReader := bytes.NewReader(anotherCiphertextWriter.Bytes())
	anotherDecryptedWriter = new(bytes.Buffer)

	err = stream.DecryptStream(anotherCiphertextReader, anotherDecryptedWriter)
	if anotherDecryptedWriter.String() != plaintext {
		t.Fatalf("%v: anotherDecrypted != plaintext", name)
	}
}

func fuzzNewStream(f *testing.F, newStream func(key, iv []byte) Stream) {
	// key: bytes, iv: bytes, plaintext: string
	f.Add([]byte("key0key1key2key3"), []byte("iv00iv01iv02iv03"), "plain-text-plain-text000")

	f.Fuzz(func(t *testing.T, key, iv []byte, plaintext string) {
		newStream := func() Stream {
			return newStream(key, iv)
		}

		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			testErrorStream("badKeyLen", t, newStream, plaintext)
			return
		}
		if len(iv) != aes.BlockSize {
			testErrorStream("badIvLen", t, newStream, plaintext)
			return
		}

		testStream("", t, newStream, plaintext)
	})
}

func fuzzSimpleStream(f *testing.F, newStream func(key string) Stream) {
	// key: string, plaintext: string
	f.Add("key", "plain-text-plain-text000")

	f.Fuzz(func(t *testing.T, key, plaintext string) {
		createSimpleStream := func() Stream {
			return newStream(key)
		}

		testStream("", t, createSimpleStream, plaintext)
	})
}

func FuzzNewCFBStream(f *testing.F) {
	fuzzNewStream(f, func(key, iv []byte) Stream {
		return NewCFBStream(Bytes(key), Bytes(iv))
	})
}

func FuzzSimpleCFBStream(f *testing.F) {
	fuzzSimpleStream(f, func(key string) Stream {
		return SimpleCFBStream(key)
	})
}

func FuzzNewOFBStream(f *testing.F) {
	fuzzNewStream(f, func(key, iv []byte) Stream {
		return NewOFBStream(Bytes(key), Bytes(iv))
	})
}

func FuzzSimpleOFBStream(f *testing.F) {
	fuzzSimpleStream(f, func(key string) Stream {
		return SimpleOFBStream(key)
	})
}

func FuzzNewCTRStream(f *testing.F) {
	fuzzNewStream(f, func(key, iv []byte) Stream {
		return NewCTRStream(Bytes(key), Bytes(iv))
	})
}

func FuzzSimpleCTRStream(f *testing.F) {
	fuzzSimpleStream(f, func(key string) Stream {
		return SimpleCTRStream(key)
	})
}
