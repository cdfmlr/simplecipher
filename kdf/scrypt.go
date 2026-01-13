package kdf

import (
	"fmt"

	cryptoScrypt "golang.org/x/crypto/scrypt"
)

// scrypt derives a key that can be used as cryptographic key.
type scrypt struct {
	N int // CPU/memory cost parameter, which must be a power of two greater than 1
	R int // block size parameter, r and p must satisfy r * p < 2^30.
	P int // parallelization parameter
}

// NewScrypt creates a scrypt key derivation function.
//
// scrypt derives a key that can be used as cryptographic key.
//
// N is a CPU/memory cost parameter, which must be a power of two greater than 1.
// r and p must satisfy r * p < 2^30. If the parameters do not satisfy the
// limits, the function returns a nil byte slice and an error.
//
// The recommended parameters for interactive logins as of 2017 are N=32768, r=8
// and p=1. The parameters N, r, and p should be increased as memory latency and
// CPU parallelism increases; consider setting N to the highest power of 2 you
// can derive within 100 milliseconds.
func NewScrypt(N, r, p int) KeyDerivation {
	return &scrypt{
		N: N,
		R: r,
		P: p,
	}
}

var _ KeyDerivation = (*scrypt)(nil)

func (s *scrypt) check() error {
	if s.N <= 1 {
		return fmt.Errorf("%w: scrypt N parameter must be greater than 1", ErrKdfConfig)
	}
	if s.R <= 0 {
		return fmt.Errorf("%w: scrypt r parameter must be greater than zero", ErrKdfConfig)
	}
	if s.P <= 0 {
		return fmt.Errorf("%w: scrypt p parameter must be greater than zero", ErrKdfConfig)
	}

	// // cryptoScrypt.Key will do the slow checks itself,
	// // so we can skip them here.
	//
	// if (s.N & (s.N - 1)) != 0 {
	// 	return fmt.Errorf("%w: scrypt N parameter must be a power of two", ErrKdfConfig)
	// }
	// if uint64(s.R)*uint64(s.P) >= 1<<30 {
	// 	return fmt.Errorf("%w: scrypt r and p parameters must satisfy r * p < 2^30", ErrKdfConfig)
	// }
	return nil
}

// Derive a key from the given password and salt using scrypt.
// Remember to get a good random salt.
func (s *scrypt) Derive(password, salt []byte, keyLen int) (key []byte, err error) {
	defer recoverFromPanic(&err)

	if err := s.check(); err != nil {
		return nil, err
	}

	if keyLen == 0 {
		return []byte{}, nil
	}
	if keyLen < 0 {
		return nil, ErrNegKeyLen
	}
	if keyLen > 1<<31 {
		return nil, fmt.Errorf("%w: key length too large", ErrKdfConfig)
	}

	key, err = cryptoScrypt.Key(password, salt, s.N, s.R, s.P, keyLen)
	return key, err
}

// profiles

// CheapScrypt use N=2^13 (8 MiB) for low memory usage and fast derivation.
//
// Commonly take around 10ms on modern (2025) hardware.
func CheapScrypt() KeyDerivation {
	return &scrypt{
		N: 8192, R: 8, P: 1,
	}
}

// RecommendedScrypt use N=2^15 (32 MiB) as golang.org/x/crypto/scrypt RECOMMENDED.
//
// Commonly take around 40ms on modern (2025) hardware.
func RecommendedScrypt() KeyDerivation {
	return &scrypt{
		N: 32768, R: 8, P: 1,
	}
}

// StrongScrypt use N=2^17 (128 MiB) as OWASP RECOMMENDED.
//
// Commonly take ~160ms on modern (2025) hardware.
func StrongScrypt() KeyDerivation {
	return &scrypt{
		N: 131072, R: 8, P: 1,
	}
}
