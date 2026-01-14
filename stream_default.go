package simplecipher

// NewCFBStream creates a new CFB stream cipher with the given key and iv using the DefaultProvider.
//
// The iv will be used as the initial value for the CFB mode.
//
// It's caller's responsibility to ensure the following:
//
//   - The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
//   - The IV must be [aes.BlockSize] bytes long.
//
// Use [SimpleCFBStream] if you are not familiar with these.
// See also: [cipher.NewCFBDecrypter], [cipher.NewCFBEncrypter] for low-level usage.
func NewCFBStream(key, iv Key) Stream {
	return DefaultProvider.NewCFBStream(key, iv)
}

// SimpleCFBStream creates a new AES-256-CFB stream cipher from the given key and iv using the DefaultProvider.
//
// An [Aes256] key for encryption/decryption will be derived from the
// arbitrary keyPassphrase string via scrypt.
//
// The iv will be a random value.
//
// See also: [NewCFBStream] for more control.
func SimpleCFBStream(keyPassphrase string) Stream {
	return DefaultProvider.SimpleCFBStream(keyPassphrase)
}

// NewOFBStream creates a new OFB stream cipher with the given key and iv using the DefaultProvider.
//
// The iv will be used as the initial value for the OFB mode.
//
// It's caller's responsibility to ensure the following:
//
//   - The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
//   - The IV must be [aes.BlockSize] bytes long.
//
// Use [SimpleOFBStream] if you are not familiar with these.
// See also: [cipher.NewOFB] for low-level usage.
func NewOFBStream(key, iv Key) Stream {
	return DefaultProvider.NewOFBStream(key, iv)
}

// SimpleOFBStream creates a new AES-256-OFB stream cipher from the given key and iv using the DefaultProvider.
//
// An [Aes256] key for encryption/decryption will be derived from the
// arbitrary keyPassphrase string via scrypt.
//
// The iv will be a random value.
//
// See also: [NewOFBStream] for more control.
func SimpleOFBStream(keyPassphrase string) Stream {
	return DefaultProvider.SimpleOFBStream(keyPassphrase)
}

// NewCTRStream creates a new CTR stream cipher with the given key and iv using the DefaultProvider.
//
// The iv will be used as the initial value for the CTR mode.
//
// It's caller's responsibility to ensure the following:
//
//   - The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
//   - The IV must be [aes.BlockSize] bytes long.
//
// Use [SimpleCTRStream] if you are not familiar with these.
// See also: [cipher.NewCTR] for low-level usage.
func NewCTRStream(key, iv Key) Stream {
	return DefaultProvider.NewCTRStream(key, iv)
}

// SimpleCTRStream creates a new AES-256-CTR stream cipher from the given key and iv using the DefaultProvider.
//
// An [Aes256] key for encryption/decryption will be derived from the
// arbitrary keyPassphrase string via scrypt.
//
// The iv will be a random value.
//
// See also: [NewCTRStream] for more control.
func SimpleCTRStream(keyPassphrase string) Stream {
	return DefaultProvider.SimpleCTRStream(keyPassphrase)
}
