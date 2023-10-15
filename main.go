package main

import (
	"fmt"
	"log"
	"github.com/jannisfengler/sqi-go/sqiinterface"
)

func main() {
	// Create an instance of Sqisign
	sqi := sqisign.New()

	// Generate a key pair
	pk, sk, err := sqi.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	fmt.Printf("Public Key: %x\n", pk)
	fmt.Printf("Secret Key: %x\n", sk)

	// Sign a message
	message := []byte("Hello, SQIsign!")
	signedMessage, err := sqi.Sign(message, sk)
	if err != nil {
		log.Fatalf("Failed to sign the message: %v", err)
	}

	fmt.Printf("Signed Message: %x\n", signedMessage)

	// Verify the signed message
	originalMessage, err := sqi.Verify(signedMessage, pk)
	if err != nil {
		log.Fatalf("Failed to verify the signed message: %v", err)
	}

	fmt.Printf("Original Message: %s\n", originalMessage)
}

