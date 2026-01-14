package simplecipher

import (
	"github.com/cdfmlr/simplecipher/v2/codec"
	"github.com/cdfmlr/simplecipher/v2/kdf"
)

// DefaultProvider is a ready-to-use Provider instance with default configuration.
// It uses Hex for string encoding and delegates to DefaultSalt for the salt function.
var DefaultProvider = &Provider{
	StringCodec:   codec.Hex,
	SaltFunc:      func() string { return "5f11a4921aea524b9d3cb7f2514b0724" },
	KeyDerivation: kdf.CheapArgon2id(), // Time: 1, Memory: 16*1024, Threads: 1
}
