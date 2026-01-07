package kdf

import "golang.org/x/crypto/scrypt"

// Scrypt derives a key that can be used as cryptographic key.
//
// N is a CPU/memory cost parameter, which must be a power of two greater than 1.
// r and p must satisfy r * p < 2^30. If the parameters do not satisfy the
// limits, the function returns a nil byte slice and an error.
//
// The recommended parameters for interactive logins as of 2017 are N=32768, r=8
// and p=1. The parameters N, r, and p should be increased as memory latency and
// CPU parallelism increases; consider setting N to the highest power of 2 you
// can derive within 100 milliseconds.
type Scrypt struct {
	N int // CPU/memory cost parameter, which must be a power of two greater than 1
	R int // block size parameter, r and p must satisfy r * p < 2^30.
	P int // parallelization parameter
}

var _ KeyDerivation = (*Scrypt)(nil)

// Derive a key from the given password and salt using scrypt.
// Remember to get a good random salt.
func (s *Scrypt) Derive(password, salt []byte, keyLen int) (key []byte, err error) {
	defer recoverFromPanic(&err)

	key, err = scrypt.Key(password, salt, s.N, s.R, s.P, keyLen)
	return key, err
}
