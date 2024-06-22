package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"

	"golang.org/x/crypto/cryptobyte"
)

//go:generate go run gen.go > static.go

func main() {
	ln, err := net.Listen("tcp", ":8443")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		go tls13(conn)
	}
}

func tls13(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered in f", r)
		}
	}()
	println("open")
	defer println("close")
	defer conn.Close()
	s := NewServerConn(conn)
	if handshake(s) {
		for s.Scan() {
			println(hex.Dump(s.Bytes()))
			s.WriteEncrypted(bytes.Clone(defaultResponse))
		}
	}
	if err := s.Err(); err != nil {
		panic(err)
	}
}

var errBrokenRecord = errors.New("broken record")

func scanRecord(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) >= 5 {
		// Calculate record size
		size := 5 + int(binary.BigEndian.Uint16(data[3:5]))
		if len(data) >= size {
			return size, data[:size], nil
		}
	}
	// If we're at EOF, we have a final, non-empty, non-terminated record, return error
	if atEOF && len(data) > 0 {
		return len(data), nil, errBrokenRecord
	}
	// Request more data
	return 0, nil, nil
}

type ServerConn struct {
	*bufio.Scanner
	net.Conn
	cipher *Cipher
}

func NewServerConn(conn net.Conn) *ServerConn {
	s := bufio.NewScanner(conn)
	s.Split(scanRecord)
	return &ServerConn{
		Scanner: s,
		Conn:    conn,
	}
}

// debug
func (s *ServerConn) Write(b []byte) (n int, err error) {
	// println(hex.Dump(b))
	return s.Conn.Write(b)
}

var resp = []byte("HTTP/1.1 200\r\nContent-Length: 12\r\n\r\nHello World\n")

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

func (s *ServerConn) WriteEncrypted(b []byte) (n int, err error) {
	aad := b[0:header]
	src := b[header : len(b)-tag]
	dst := b[header:header:len(b)]
	s.cipher.seal(dst, src, aad)
	return s.Conn.Write(b)
}
