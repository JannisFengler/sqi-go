package sqiinterface

// Sqisign defines the interface for the Sqisign implementation.
type Sqisign interface {
	// GenerateKeyPair generates a public and secret key pair.
	// Returns the public and secret keys or an error if something goes wrong.
	GenerateKeyPair() ([]byte, []byte, error)

	// Sign signs a message with a secret key.
	// Returns the signed message or an error if something goes wrong.
	Sign(m []byte, sk []byte) ([]byte, error)

	// Verify verifies a signed message and returns the original message.
	// Returns an error if the verification fails.
	Verify(sm []byte, pk []byte) ([]byte, error)
}
