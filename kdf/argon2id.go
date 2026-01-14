package kdf

import (
	"fmt"

	"github.com/cdfmlr/simplecipher/v2/dontpanic"
	cryptoArgon2 "golang.org/x/crypto/argon2"
)

// argon2id derives a key that can be used as cryptographic key.
type argon2id struct {
	Time    uint32 // Time parameter specifies the number of passes over the memory
	Memory  uint32 // Memory parameter specifies the size of the memory in KiB
	Threads uint8  // Number of parallel Threads
}

// NewArgon2id creates a new Argon2id key derivation function with the specified
// parameters. The CPU cost and parallelism degree must be greater than zero.
//
// [RFC 9106 Section 7.3] recommends time=1, and memory=64*1024 as a sensible number.
// If using that amount of memory (64 MB) is not possible in some contexts then
// the time parameter can be increased to compensate.
//
// The time parameter specifies the number of passes over the memory and the
// memory parameter specifies the size of the memory in KiB. For example
// memory=64*1024 sets the memory cost to ~64 MB. The number of threads can be
// adjusted to the numbers of available CPUs. The cost parameters should be
// increased as memory latency and CPU parallelism increases.
//
// [RFC 9106 Section 7.3]: https://www.rfc-editor.org/rfc/rfc9106.html#section-7.3
func NewArgon2id(time uint32, memory uint32, threads uint8) KeyDerivation {
	return &argon2id{
		Time:    time,
		Memory:  memory,
		Threads: threads,
	}
}

var _ KeyDerivation = (*argon2id)(nil)

func (a *argon2id) check() error {
	if a.Time == 0 {
		return fmt.Errorf("%w: argon2id time parameter must be greater than zero", ErrKdfConfig)
	}
	if a.Memory == 0 {
		return fmt.Errorf("%w: argon2id memory parameter must be greater than zero", ErrKdfConfig)
	}
	if a.Threads == 0 {
		return fmt.Errorf("%w: argon2id threads parameter must be greater than zero", ErrKdfConfig)
	}
	return nil
}

// Derive a key from the given password and salt using argon2id.
// Remember to get a good random salt.
func (a *argon2id) Derive(password, salt []byte, keyLen int) (key []byte, err error) {
	defer dontpanic.RecoverTo(&err)

	if err := a.check(); err != nil {
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

	key = cryptoArgon2.IDKey(password, salt, a.Time, a.Memory, a.Threads, uint32(keyLen))
	return key, nil
}

// profiles

// CheapArgon2id will comfortably run in ~ 10ms on modern (2025) laptops.
func CheapArgon2id() KeyDerivation {
	return &argon2id{
		Time: 1, Memory: 16 * 1024, Threads: 1,
	}
}

// RecommendedArgon2id is in the middle of the OWASP RECOMMENDATION and the
// RFC 9106 SECOND RECOMMENDATION.
//
// It requires about 64MB of RAM and will take around 80ms.
func RecommendedArgon2id() KeyDerivation {
	return &argon2id{
		Time: 2, Memory: 64 * 1024, Threads: 1,
	}
}

// StrongArgon2id is the FIRST RECOMMENDED SETTINGS from RFC 9106 Section 7.4.
//
// It requires about 2GB of RAM and will take more than 1s (<2s) on common hardware in 2025.
func StrongArgon2id() KeyDerivation {
	return &argon2id{
		Time: 1, Memory: 2 * 1024 * 1024, Threads: 1,
	}
}
