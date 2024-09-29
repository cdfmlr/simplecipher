# simplecipher

Package simplecipher provides a simple interface for encrypting and 
decrypting data using a symmetric key.

Features:

- **string in -> string out**: Input key, input plaintext, output ciphertext or output plaintext are all strings. Optional hex, base64 or base32 encoding for ciphertext.
- **Key derivation**: Able to generate a secure key matching the required length from an arbitrary passphrase.
- Padding and unpadding for plaintext if necessary.

Cipher modes:

- AEAD mode: working with string: GCM.
- Block mode: working with string: CBC, CFB, OFB, CTR.
- Stream mode: working with io.Reader and io.Writer: CFB, OFB, CTR.

Low-level cipher:

- Currently, the only supported underlying block cipher is AES (AES-128, AES-192 and AES-256).

## Usage

Install:

```bash
go get github.com/cdfmlr/simplecipher
```

Example:

```go
package main

import (
	"fmt"
	"github.com/cdfmlr/simplecipher"
)

func init() {
	// Set your own salt for key derivation.
	// Never trust the default one.
	simplecipher.DefaultSalt = func() string { return "NaCl" }
}

func main() {
	// don't worry about the key length, we will derive a secure key from it.
	key := "123456"

	// plaintext to be encrypted, any string
	plaintext := "Hello, world!"

	// instance a cipher with the key (and DefaultSalt)
	cipher := simplecipher.SimpleCTR(key)

	// encrypt with cipher
	encrypted, _ := cipher.Encrypt(plaintext)
	fmt.Println("ciphertext:", encrypted)

	// decrypt with cipher
	decrypted, _ := cipher.Decrypt(encrypted)
	fmt.Println("plaintext:", decrypted)
}
```

Best practice:

- Create a new cipher instance for each encryption.
- Store and pass the key securely.
- Remember to set you own salt for key derivation. And Keep it secret and safe too if possible. (Notice: You need to use the same salt for decryption and encryption.)

## Which mode should I use?

<details>
    <summary>Click to see the decision tree</summary>

```mermaid
flowchart TD
	streamOrBlock{stream or block?}
	associatedData{associated authenticated data?}
	simpleOrCompatibleStream{simple or compatible?}
	simpleOrCompatibleAEAD{simple or compatible?}
	simpleOrCompatibleBlock{simple or compatible?}
	
	newStreams(NewCFBStream, NewOFBStream, NewCTRStream)
	simpleStreams(SimpleCFBStream, SimpleOFBStream, SimpleCTRStream)

	newBlocks(NewCBC, NewCFB, NewOFB, NewCTR)
	simpleBlocks(SimpleCBC, SimpleCFB, SimpleOFB, SimpleCTR)

	newAEADs(NewGCM)
	simpleAEADs(SimpleGCM)

	streamOrBlock--->|io.Reader in, io.Writer out|simpleOrCompatibleStream
	streamOrBlock--->|string in, string out|associatedData
	
	simpleOrCompatibleStream--->|I am a Cryptography Muggle|simpleStreams
	simpleOrCompatibleStream--->|I want to encrypt/decrypt wiht other tools|newStreams

	associatedData--->|I don't know|simpleOrCompatibleBlock
	associatedData--->|Yes|simpleOrCompatibleAEAD

	simpleOrCompatibleBlock--->|Any string as the key|simpleBlocks
	simpleOrCompatibleBlock--->|I want to encrypt/decrypt wiht other tools|newBlocks

	simpleOrCompatibleAEAD--->|Any string as the key|simpleAEADs
	simpleOrCompatibleAEAD--->|I want to encrypt/decrypt wiht other tools|newAEADs

	newBlocks--->|What's the difference?|NewCTR
	simpleBlocks--->|What's the difference?|SimpleCTR
	newStreams--->|What's the difference?|NewCTRStream
	simpleStreams--->|What's the difference?|SimpleCTRStream
```

</details>

What's your use case?

- I just want to encrypt/decrypt a string: use `SimpleCTR` or `NewCTR`.
    - Plus, if you want to associate some authenticated data with the ciphertext: use `SimpleGCM` or `NewGCM`.
- I am expecting to encrypt/decrypt a lot of data from/to an `io.Reader`/`io.Writer`: use `SimpleCTRStream` or `NewCTRStream`.

What's the difference between `SimpleXXX` and `NewXXX`?

- I only use this package for encryption/decryption with another string as the key (or password): `SimpleXXX`;
- I want to encrypt/decrypt with other tools (for example, encrypting via simplecipher, decrypting via OpenSSL), or I am happy to tweak things like iv: `NewXXX`.

And why `CTR`? what's the difference between `CTR`, `CFB`, `OFB` and `CBC`?

- Just use `CTR` if you don't know what to choose. (Because I prefer this name, literally.)
- Or learn some cryptography and choose the right one for your use case: [Block cipher mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation).

## License

BSD-3-Clause license. See [LICENSE](LICENSE) file for details.
