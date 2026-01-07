package kdf

// KeyDerivation is a key derivation function (KDF) interface.
type KeyDerivation interface {
	// Derive derives a key from the given password and salt.
	Derive(password, salt []byte, keyLen int) ([]byte, error)
}

func recoverFromPanic(err *error) {
	if r := recover(); r != nil {
		*err = r.(error)
	}
}
