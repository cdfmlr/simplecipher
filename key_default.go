package simplecipher

// NewKey derives a new key in the specified length from the passphrase.
//
// The output key will be derived from the Passphrase (with Salt) via
// Sequential Memory-Hard Functions (see [scrypt.Key] for details).
//
// Any UTF-8 string can be used as an input key (including "") and Salt.
//
// More than 32 bytes are recommended for the Passphrase.
// And at least 8 bytes are recommended for Salt.
//
// Use [NewAesKey], [NewNonce], or [NewIv] for specific key types.
func NewKey(passphrase string, len KeyLen, salt string) Key {
	return DefaultProvider.NewKey(passphrase, len, salt)
}

// NewAesKey creates a new AES key derived from the passphrase using the DefaultProvider's salt.
//
// [Aes256] and [DefaultProvider.SaltFunc] are used by default.
// Use [WithSalt] and [WithLen] options to customize the key derivation.
//
// For custom salt function, use DefaultProvider.NewAesKey() or create your own Provider.
func NewAesKey(passphrase string, options ...KeyGenOption) Key {
	return DefaultProvider.NewAesKey(passphrase, options...)
}

// NewNonce creates a new nonce with default [NonceSize] using the DefaultProvider's salt.
//
// The output key will be derived from the passphrase via
// Sequential Memory-Hard Functions with [DefaultProvider.SaltFunc].
//
// For custom salt function, use DefaultProvider.NewNonce() or create your own Provider.
func NewNonce(passphrase string, options ...KeyGenOption) Key {
	return DefaultProvider.NewNonce(passphrase, options...)
}

// NewRandomNonce creates a new random nonce with [NonceSize] bytes.
func NewRandomNonce() Key {
	return DefaultProvider.NewRandomNonce()
}

// NewIv creates a new IV with [aes.BlockSize] bytes using the DefaultProvider's salt.
//
// The output key will be derived from the passphrase via
// Sequential Memory-Hard Functions with [DefaultProvider.SaltFunc].
//
// For custom salt function, use DefaultProvider.NewIv() or create your own Provider.
func NewIv(passphrase string, options ...KeyGenOption) Key {
	return DefaultProvider.NewIv(passphrase, options...)
}

// NewRandomIv creates a new random IV with [aes.BlockSize] bytes.
func NewRandomIv() Key {
	return DefaultProvider.NewRandomIv()
}
