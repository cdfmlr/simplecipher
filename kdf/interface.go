package kdf

// KeyDerivation is a key derivation function (KDF) interface.
//
// Prefer:
//   - generic key derivation: Argon2id > scrypt > PBKDF2.
//   - for machine secrets (fast key splitting/refining): use HKDF.
//
// KeyDerivation is for internal use in simplecipher only.
// So it is NOT simplified to accept string args like the outer Block/Stream
// interfaces do. This is by design.
type KeyDerivation interface {
	// Derive derives a key from the given password and salt.
	Derive(password, salt []byte, keyLen int) ([]byte, error)
}
