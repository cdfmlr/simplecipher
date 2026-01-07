package kdf

import "golang.org/x/crypto/argon2"

// Argon2id derives a key that can be used as cryptographic key.
// The CPU cost and parallelism degree must be greater than zero.
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
type Argon2id struct {
	Time    uint32 // Time parameter specifies the number of passes over the memory
	Memory  uint32 // Memory parameter specifies the size of the memory in KiB
	Threads uint8  // Number of parallel Threads
}

var _ KeyDerivation = (*Argon2id)(nil)

// Derive a key from the given password and salt using Argon2id.
// Remember to get a good random salt.
func (a *Argon2id) Derive(password, salt []byte, keyLen int) (key []byte, err error) {
	defer recoverFromPanic(&err)

	key = argon2.IDKey(password, salt, a.Time, a.Memory, a.Threads, uint32(keyLen))
	return key, nil
}
