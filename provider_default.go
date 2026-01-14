package simplecipher

import (
	"github.com/cdfmlr/simplecipher/v2/codec"
	"github.com/cdfmlr/simplecipher/v2/kdf"
)

// defaultProvider returns a Provider with default configurations.
// this is wrapped in a function to avoid unintended modifications
// to the default values.
func defaultProvider() *Provider {
	return &Provider{
		StringCodec:   codec.Hex,
		SaltFunc:      func() string { return "5f11a4921aea524b9d3cb7f2514b0724" },
		KeyDerivation: kdf.CheapArgon2id(), // Time: 1, Memory: 16*1024, Threads: 1
	}
}

// DefaultProvider is a ready-to-use Provider instance with default configs:
//   - StringCodec: codec.Hex, encodes/decodes bytes to/from hex strings.
//   - SaltFunc: a fixed salt hardcode "5f11a4921aea524b9d3cb7f2514b0724",
//     promised to be consistent across simplecipher v2 versions.
//     Callers MUST override this in production!
//   - KeyDerivation: kdf.CheapArgon2id, a quick Argon2id KDF with
//     Time: 1, Memory: 16*1024, Threads: 1.
//     It typically derives a key in ~10ms.
var DefaultProvider = defaultProvider()
