package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"

	"golang.org/x/crypto/curve25519"
)

func hmac256(secret, message []byte) []byte {
	x := hmac.New(sha256.New, secret)
	x.Write(message)
	return x.Sum(nil)
}

func x25519(scalar, point []byte) []byte {
	r, err := curve25519.X25519(scalar, point)
	if err != nil {
		panic(err)
	}
	return r
}

func signpss(certificateKey, digest []byte) []byte {
	key, err := x509.ParsePKCS8PrivateKey(certificateKey)
	if err != nil {
		panic(err)
	}
	signature, err := rsa.SignPSS(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, digest, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		panic(err)
	}
	return signature
}

func aesgcm(key, iv []byte) *Cipher {
	c, err := NewCipher(key[:16], iv[:12])
	if err != nil {
		panic(err)
	}
	return c
}

type Cipher struct {
	cipher         cipher.AEAD
	iv             [12]byte
	sequenceNumber int
}

func NewCipher(key, iv []byte) (*Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	cipher := &Cipher{
		cipher: aesgcm,
	}
	copy(cipher.iv[:], iv)
	return cipher, nil
}

func (c *Cipher) seal(dst, plaintext, aad []byte) []byte {
	var nonce = c.iv
	nonce[11] ^= byte(c.sequenceNumber)
	c.sequenceNumber++
	return c.cipher.Seal(dst, nonce[:], plaintext, aad)
}
