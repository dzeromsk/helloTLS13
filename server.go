package main

import (
	"bufio"
	"net"

	"golang.org/x/crypto/cryptobyte"
)

type KTLSServer struct {
	*bufio.Scanner
	net.Conn
	cipher *Cipher
}

func NewKTLSServer(conn net.Conn) *KTLSServer {
	s := bufio.NewScanner(conn)
	s.Split(scanRecord)
	return &KTLSServer{
		Scanner: s,
		Conn:    conn,
	}
}

// debug
func (s *KTLSServer) Write(b []byte) (n int, err error) {
	// println(hex.Dump(b))
	return s.Conn.Write(b)
}

func wrappedResp() []byte {
	var cb cryptobyte.Builder
	cb.AddUint8(0x17)    // Application data
	cb.AddUint16(0x0303) // TLS 1.2
	cb.AddUint16LengthPrefixed(func(cb *cryptobyte.Builder) {
		cb.AddBytes(resp)
		cb.AddUint8(0x17)             // Application record
		cb.AddBytes(make([]byte, 16)) // Auth/AEAD tag
	})
	return cb.BytesOrPanic()
}

var defaultResponse = wrappedResp()

func (s *KTLSServer) WriteEncrypted(b []byte) (n int, err error) {
	aad := b[0:header]
	src := b[header : len(b)-tag]
	dst := b[header:header:len(b)]
	s.cipher.seal(dst, src, aad)
	return s.Conn.Write(b)
}
