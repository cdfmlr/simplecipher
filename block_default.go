package simplecipher

// NewCFB creates a new CFB cipher with the given key and iv using the DefaultProvider.
//
// The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
// The iv must be [aes.BlockSize] bytes long.
//
// The iv will be prepended to the ciphertext during encryption,
// and the first block of the ciphertext will be treated as the IV during decryption.
//
// Use SimpleCFB if you are not familiar with this.
//
// See also: [cipher.NewCFBDecrypter], [cipher.NewCFBEncrypter] for low-level usage.
func NewCFB(key, iv Key) Block {
	return DefaultProvider.NewCFB(key, iv)
}

// SimpleCFB creates a new AES-256-CFB cipher with a key derived from
// the given keyPassphrase and a random iv prepended to the ciphertext.
//
// See also: [NewCFB] for more control.
func SimpleCFB(keyPassphrase string) Block {
	return DefaultProvider.SimpleCFB(keyPassphrase)
}

// NewOFB creates a new OFB cipher with the given key and iv using the DefaultProvider.
//
// The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
// The iv must be [aes.BlockSize] bytes long.
//
// The iv will be prepended to the ciphertext during encryption,
// and the first block of the ciphertext will be treated as the IV during decryption.
//
// Use [SimpleOFB] if you are not familiar with this.
//
// See also: [cipher.NewOFB] for low-level usage.
func NewOFB(key, iv Key) Block {
	return DefaultProvider.NewOFB(key, iv)
}

// SimpleOFB creates a new AES-256-OFB cipher with a key derived from
// the given keyPassphrase and a random iv prepended to the ciphertext.
//
// See also: [NewOFB] for more control.
func SimpleOFB(keyPassphrase string) Block {
	return DefaultProvider.SimpleOFB(keyPassphrase)
}

// NewCTR creates a new CTR cipher with the given key and iv using the DefaultProvider.
//
// The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
// The iv must be [aes.BlockSize] bytes long.
//
// The iv will be prepended to the ciphertext during encryption,
// and the first block of the ciphertext will be treated as the IV during decryption.
//
// Use [SimpleCTR] if you are not familiar with this.
//
// See also: [cipher.NewCTR] for low-level usage.
func NewCTR(key, iv Key) Block {
	return DefaultProvider.NewCTR(key, iv)
}

// SimpleCTR creates a new AES-256-CTR cipher with a key derived from
// the given keyPassphrase and a random iv prepended to the ciphertext.
//
// See also: [NewCTR] for more control.
func SimpleCTR(keyPassphrase string) Block {
	return DefaultProvider.SimpleCTR(keyPassphrase)
}
