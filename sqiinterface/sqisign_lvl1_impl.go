package sqiinterface

// #cgo CFLAGS: -Ic/jannis/sign/sqiinterface/the-sqisign/include
// #cgo LDFLAGS: -Lc/jannis/sign/sqiinterface/the-sqisign/build/src -lsqisign_lvl1
// #include "sig.h"
// #include "mem.h"
// #include "rng.h"

import "C"
import (
	"errors"
	"unsafe"
)

const (
	// TODO: Replace these sizes with the actual sizes
	PublicKeySize   = 48 // placeholder
	SecretKeySize   = 48 // placeholder
	SignatureSize   = 64 // placeholder
)

// SqisignImpl implements the Sqisign interface.
type SqisignImpl struct{}

// GenerateKeyPair generates a public and secret key pair.
// Returns the public and secret keys or an error if something goes wrong.
func (s *SqisignImpl) GenerateKeyPair() ([]byte, []byte, error) {
	var pk [PublicKeySize]byte
	var sk [SecretKeySize]byte

	// Generate random bytes for the secret key
	res := C.randombytes((*C.uchar)(&sk[0]), C.ulonglong(SecretKeySize))
	if res != 0 {
		return nil, nil, errors.New("failed to generate random bytes for secret key")
	}

	// Generate the key pair
	res = C.sqisign_keypair((*C.uchar)(&pk[0]), (*C.uchar)(&sk[0]))
	if res != 0 {
		return nil, nil, errors.New("failed to generate keypair")
	}

	return pk[:], sk[:], nil
}

// Sign signs a message with a secret key.
// Returns the signed message or an error if something goes wrong.
func (s *SqisignImpl) Sign(m []byte, sk []byte) ([]byte, error) {
	var smlen C.ulonglong
	var sm [SignatureSize + len(m)]byte

	res := C.sqisign_sign((*C.uchar)(&sm[0]), &smlen, (*C.uchar)(&m[0]), 
						  C.ulonglong(len(m)), (*C.uchar)(&sk[0]))

	if res != 0 {
		return nil, errors.New("failed to sign message")
	}

	return sm[:smlen], nil
}

// Verify verifies a signed message and returns the original message.
// Returns an error if the verification fails.
func (s *SqisignImpl) Verify(sm []byte, pk []byte) ([]byte, error) {
	var mlen C.ulonglong
	var m [len(sm)]byte // Assuming message length <= sm length

	res := C.sqisign_open((*C.uchar)(&m[0]), &mlen, (*C.uchar)(&sm[0]),
						  C.ulonglong(len(sm)), (*C.uchar)(&pk[0]))

	if res != 0 {
		return nil, errors.New("failed to verify message")
	}

	return m[:mlen], nil
}

// New returns a new Sqisign object.
func New() Sqisign {
	return &SqisignImpl{}
}
