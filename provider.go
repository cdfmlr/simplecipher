package simplecipher

// TODO: consider splitting Provider into multiple smaller internal providers:
//           keyProvider, blockProvider and streamProvider.
//       Or I personally much more prefer to call these internal things
//       "config"s instead of "provider"s, since they are literally configs.
//       This can help reduce the size of the Provider struct
//       and make it easier to manage different aspects of the configuration.
//       BTW, I think keep a single Provider exported to users is still a good
//       idea, for simplicity and ease of use.

// Provider encapsulates the configuration for cipher operations.
// It groups all cipher-related configuration and provides methods to create
// ciphers, keys, and other cryptographic primitives.
//
// It is highly recommended to create a Provider instance by NewProvider() with
// custom ProviderOption.
//
// Be careful when constructing a literal Provider struct. The Ensure() method
// is recommended to be called before using such instances, to avoid potential
// unexpected behaviors.
type Provider struct {
	// StringCodec is the codec used to encode/decode ciphertext strings.
	// Defaults to Hex.
	StringCodec StringCodec

	// SaltFunc is a function that returns the salt used for key derivation.
	// Defaults to a fixed random string.
	SaltFunc SaltFunc

	// KeyDerivation is the key derivation function used to derive keys from passphrases.
	// Defaults to a cheap Argon2id KDF (Time: 1, Memory: 16*1024, Threads: 1).
	KeyDerivation KeyDerivation
}

// NewProvider creates a new Provider with the given options.
// Available options include setting the StringCodec, SaltFunc, and KeyDerivation.
// Any fields not set or nil will be filled with default values (see [DefaultProvider]).
func NewProvider(options ...ProviderOption) *Provider {
	p := &Provider{}
	for _, option := range options {
		option(p)
	}
	p.Ensure()
	return p
}

type ProviderOption func(*Provider)

// WithStringCodec sets the StringCodec for the Provider.
func WithStringCodec(codec StringCodec) ProviderOption {
	return func(p *Provider) {
		p.StringCodec = codec
	}
}

// WithSaltFunc sets the SaltFunc for the Provider.
func WithSaltFunc(saltFunc func() string) ProviderOption {
	return func(p *Provider) {
		p.SaltFunc = saltFunc
	}
}

// WithKeyDerivation sets the KeyDerivation function for the Provider.
func WithKeyDerivation(kdf KeyDerivation) ProviderOption {
	return func(p *Provider) {
		p.KeyDerivation = kdf
	}
}

// Ensure fills in any unexpected nil fields with default values.
// This should (only) be called during Provider initialization.
func (p *Provider) Ensure() {
	defaultConfig := defaultProvider()

	if p.StringCodec == nil {
		p.StringCodec = defaultConfig.StringCodec
	}
	if p.SaltFunc == nil {
		p.SaltFunc = defaultConfig.SaltFunc
	}
	if p.KeyDerivation == nil {
		p.KeyDerivation = defaultConfig.KeyDerivation
	}
}

// config is an internal alias for Provider to make struct field names clearer.
// Using "config" instead of "provider" better reflects its role as a configuration container.
type config = Provider

// ============ Block Block Methods ============

// NewCBC creates a new CBC cipher with the given key and iv.
//
// The iv will be prepended to the ciphertext during encryption,
// and the first block of the ciphertext will be treated as the IV during decryption.
//
// It's caller's responsibility to ensure the following:
//
//   - The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
//   - The IV must be [aes.BlockSize] bytes long.
//   - The plaintext must be padded to a multiple of [aes.BlockSize] bytes.
//
// Use [Provider.SimpleCBC] if you are not familiar with these.
//
// See also: [cipher.NewCBCDecrypter], [cipher.NewCBCEncrypter] for low-level usage.
func (p *Provider) NewCBC(key, iv Key) Block {
	return newCBC(key, iv, p)
}

// SimpleCBC creates a new AES-256-CBC cipher with the given key.
//
// The keyPassphrase parameter can be any arbitrary string. It will be used to
// derive the real key used in the CBC mode via scrypt.
//
// Random iv will be generated for each encryption and prepended to the
// ciphertext.
//
// The plaintext is automatically padded to a multiple of [aes.BlockSize] bytes
// with PKCS7 padding.
//
// See also: [Provider.NewCBC] for more control.
func (p *Provider) SimpleCBC(keyPassphrase string) Block {
	return newSimpleCBC(keyPassphrase, p)
}

// NewCFB creates a new CFB cipher with the given key and iv.
//
// The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
// The iv must be [aes.BlockSize] bytes long.
//
// The iv will be prepended to the ciphertext during encryption,
// and the first block of the ciphertext will be treated as the IV during decryption.
//
// Use [Provider.SimpleCFB] if you are not familiar with this.
//
// See also: [cipher.NewCFBDecrypter], [cipher.NewCFBEncrypter] for low-level usage.
func (p *Provider) NewCFB(key, iv Key) Block {
	return newStreamToBlock(p.NewCFBStream(key, iv), p)
}

// SimpleCFB creates a new AES-256-CFB cipher with a key derived from
// the given keyPassphrase and a random iv prepended to the ciphertext.
//
// See also: [Provider.NewCFB] for more control.
func (p *Provider) SimpleCFB(keyPassphrase string) Block {
	return newStreamToBlock(p.SimpleCFBStream(keyPassphrase), p)
}

// NewOFB creates a new OFB cipher with the given key and iv.
//
// The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
// The iv must be [aes.BlockSize] bytes long.
//
// The iv will be prepended to the ciphertext during encryption,
// and the first block of the ciphertext will be treated as the IV during decryption.
//
// Use [Provider.SimpleOFB] if you are not familiar with this.
//
// See also: [cipher.NewOFB] for low-level usage.
func (p *Provider) NewOFB(key, iv Key) Block {
	return newStreamToBlock(p.NewOFBStream(key, iv), p)
}

// SimpleOFB creates a new AES-256-OFB cipher with a key derived from
// the given keyPassphrase and a random iv prepended to the ciphertext.
//
// See also: [Provider.NewOFB] for more control.
func (p *Provider) SimpleOFB(keyPassphrase string) Block {
	return newStreamToBlock(p.SimpleOFBStream(keyPassphrase), p)
}

// NewCTR creates a new CTR cipher with the given key and iv.
//
// The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
// The iv must be [aes.BlockSize] bytes long.
//
// The iv will be prepended to the ciphertext during encryption,
// and the first block of the ciphertext will be treated as the IV during decryption.
//
// Use [Provider.SimpleCTR] if you are not familiar with this.
//
// See also: [cipher.NewCTR] for low-level usage.
func (p *Provider) NewCTR(key, iv Key) Block {
	return newStreamToBlock(p.NewCTRStream(key, iv), p)
}

// SimpleCTR creates a new AES-256-CTR cipher with a key derived from
// the given keyPassphrase and a random iv prepended to the ciphertext.
//
// See also: [Provider.NewCTR] for more control.
func (p *Provider) SimpleCTR(keyPassphrase string) Block {
	return newStreamToBlock(p.SimpleCTRStream(keyPassphrase), p)
}

// ============ Stream Block Methods ============

// NewCFBStream creates a new CFB stream cipher with the given key and iv.
//
// The iv will be used as the initial value for the CFB mode.
//
// It's caller's responsibility to ensure the following:
//
//   - The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
//   - The IV must be [aes.BlockSize] bytes long.
//
// Use [Provider.SimpleCFBStream] if you are not familiar with these.
// See also: [cipher.NewCFBDecrypter], [cipher.NewCFBEncrypter] for low-level usage.
func (p *Provider) NewCFBStream(key, iv Key) Stream {
	return newSteam(key, iv, cfbStreamBuilder)
}

// SimpleCFBStream creates a new AES-256-CFB stream cipher from the given key and iv.
//
// An [Aes256] key for encryption/decryption will be derived from the
// arbitrary keyPassphrase string via scrypt.
//
// The iv will be a random value.
//
// See also: [Provider.NewCFBStream] for more control.
func (p *Provider) SimpleCFBStream(keyPassphrase string) Stream {
	return p.NewCFBStream(p.NewAesKey(keyPassphrase), p.NewRandomIv())
}

// NewOFBStream creates a new OFB stream cipher with the given key and iv.
//
// The iv will be used as the initial value for the OFB mode.
//
// It's caller's responsibility to ensure the following:
//
//   - The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
//   - The IV must be [aes.BlockSize] bytes long.
//
// Use [Provider.SimpleOFBStream] if you are not familiar with these.
// See also: [cipher.NewOFB] for low-level usage.
func (p *Provider) NewOFBStream(key, iv Key) Stream {
	return newSteam(key, iv, ofbStreamBuilder)
}

// SimpleOFBStream creates a new AES-256-OFB stream cipher from the given key and iv.
//
// An [Aes256] key for encryption/decryption will be derived from the
// arbitrary keyPassphrase string via scrypt.
//
// The iv will be a random value.
//
// See also: [Provider.NewOFBStream] for more control.
func (p *Provider) SimpleOFBStream(keyPassphrase string) Stream {
	return p.NewOFBStream(p.NewAesKey(keyPassphrase), p.NewRandomIv())
}

// NewCTRStream creates a new CTR stream cipher with the given key and iv.
//
// The iv will be used as the initial value for the CTR mode.
//
// It's caller's responsibility to ensure the following:
//
//   - The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
//   - The IV must be [aes.BlockSize] bytes long.
//
// Use [Provider.SimpleCTRStream] if you are not familiar with these.
// See also: [cipher.NewCTR] for low-level usage.
func (p *Provider) NewCTRStream(key, iv Key) Stream {
	return newSteam(key, iv, ctrStreamBuilder)
}

// SimpleCTRStream creates a new AES-256-CTR stream cipher from the given key and iv.
//
// An [Aes256] key for encryption/decryption will be derived from the
// arbitrary keyPassphrase string via scrypt.
//
// The iv will be a random value.
//
// See also: [Provider.NewCTRStream] for more control.
func (p *Provider) SimpleCTRStream(keyPassphrase string) Stream {
	return p.NewCTRStream(p.NewAesKey(keyPassphrase), p.NewRandomIv())
}

// ============ AEAD Block Methods ============

// NewGCM creates a new GCM cipher with the given key and nonce.
// It's caller's responsibility to ensure the following:
//
//   - The key must be 16 or 32 bytes long to select AES-128 or AES-256.
//   - The nonce must be 12 bytes long.
//
// Use [Provider.SimpleGCM] if you are not familiar with these.
//
// See also: [cipher.NewGCM] for low-level usage.
func (p *Provider) NewGCM(key, nonce, additionalData Key) Block {
	return newGCM(key, nonce, additionalData, p)
}

// SimpleGCM creates a new AES-256-GCM cipher from the given key and additional data.
//
// The keyPassphrase and additionalPassphrase parameters can be any arbitrary strings.
// SimpleGCM will derive the real key, nonce and additionalData used in the GCM mode
// from the these passphrases via Provider.KeyDerivation with the Provider.SaltFunc().
//
// The nonce will be a random value.
//
// See also: [Provider.NewGCM]
func (p *Provider) SimpleGCM(keyPassphrase, additionalPassphrase string) Block {
	return p.NewGCM(p.NewAesKey(keyPassphrase), p.NewRandomNonce(), p.NewNonce(additionalPassphrase))
}

// ============ Key Derivation Methods ============

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
// Use [Provider.NewAesKey], [Provider.NewNonce], or [Provider.NewIv] for specific key types.
func (p *Provider) NewKey(passphrase string, len KeyLen, salt string) Key {
	return newKeyGen(passphrase, len, salt, p.KeyDerivation)
}

// NewAesKey creates a new AES key derived from the passphrase.
//
// [Aes256] and the provider's salt function are used by default.
// Use [WithSalt] and [WithLen] options to customize the key derivation.
func (p *Provider) NewAesKey(passphrase string, options ...KeyGenOption) Key {
	return newAesKey(passphrase, options, p)
}

// NewNonce creates a new nonce with default [NonceSize].
//
// The output key will be derived from the passphrase via
// Sequential Memory-Hard Functions with the provider's salt function.
func (p *Provider) NewNonce(passphrase string, options ...KeyGenOption) Key {
	return newNonce(passphrase, options, p)
}

// NewRandomNonce creates a new random nonce with default [NonceSize].
//
// The output key will be derived from the passphrase via
// Sequential Memory-Hard Functions with the provider's salt function.
func (p *Provider) NewRandomNonce() Key {
	return newRandomNonce(p)
}

// NewIv creates a new IV with [aes.BlockSize] bytes.
//
// The output key will be derived from the passphrase via
// Sequential Memory-Hard Functions with the provider's salt function.
func (p *Provider) NewIv(passphrase string, options ...KeyGenOption) Key {
	return newIv(passphrase, options, p)
}

// NewRandomIv creates a new random IV with [aes.BlockSize] bytes.
//
// It first attempts to use crypto/rand for cryptographically secure randomness.
// If that fails, it falls back to generating an IV using the current time and
// math/rand as a passphrase for key derivation.
func (p *Provider) NewRandomIv() Key {
	return newRandomIv(p)
}
