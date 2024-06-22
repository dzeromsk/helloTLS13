package main

import (
	"bytes"

	"golang.org/x/crypto/cryptobyte"
)

type clientHello struct {
	sessionID []byte
	publicKey []byte
}

func decodeHello(data []byte, c *clientHello) bool {
	r := cryptobyte.String(data)

	r.Skip(5) // Record Header
	r.Skip(4) // Handshake Header
	r.Skip(2) // Client Version

	var (
		clientRandom       []byte
		sessionID          cryptobyte.String
		cipherSuites       cryptobyte.String
		compressionMethods cryptobyte.String
		extensions         cryptobyte.String
	)

	r.ReadBytes(&clientRandom, 32)
	r.ReadUint8LengthPrefixed(&sessionID)
	r.ReadUint16LengthPrefixed(&cipherSuites)
	r.ReadUint8LengthPrefixed(&compressionMethods)
	r.ReadUint16LengthPrefixed(&extensions)

	var publicKey cryptobyte.String
	for !extensions.Empty() {
		var (
			extension uint16
			data      cryptobyte.String
		)

		extensions.ReadUint16(&extension)
		extensions.ReadUint16LengthPrefixed(&data)

		switch extension {
		case 0x0033:
			var keyData cryptobyte.String
			data.ReadUint16LengthPrefixed(&keyData)
			for !keyData.Empty() {
				var group uint16
				keyData.ReadUint16(&group)
				keyData.ReadUint16LengthPrefixed(&publicKey)
				if group == 29 {
					break
				}
			}
			// {
			// 	keyData.Skip(2) // x25519
			// 	keyData.ReadUint16LengthPrefixed(&publicKey)
			// }
		}
	}

	c.sessionID = bytes.Clone(sessionID)
	c.publicKey = bytes.Clone(publicKey)

	return true
}

func decodeChangeCipherSpec(data []byte) bool {
	// TODO: verify
	return true
}

func decodeHandshakeFinished(data []byte) bool {
	// TODO: verify
	return true
}
