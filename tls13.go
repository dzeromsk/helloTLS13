package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
)

func tls13(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered in f", r)
		}
	}()
	println("open")
	defer println("close")
	defer conn.Close()
	s := NewKTLSServer(conn)
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

func handshake(s *KTLSServer) bool {
	h := sha256.New()
	var client clientHello
	if s.Scan() {
		record := s.Bytes()
		if decodeHello(record, &client) {
			println("hello")

			r := handshakeView(handshakeTemplate)

			// Client Hello
			h.Write(record[5:])

			// Server Hello
			r.updateHello(client.sessionID)
			r.hashHello(h)

			h1 := h.Sum(nil)

			// Server Handshake Keys Calc
			sk := x25519(serverPrivate[:], client.publicKey)   // shared key
			hs := hmac256(d1[:], sk)                           // handshake secret
			sh := hmac256(hs, ServerHandshakeTrafficLabel(h1)) // s hs traffic
			hk := hmac256(sh, KeyLabel[:])
			hi := hmac256(sh, IVLabel[:])
			ch := aesgcm(hk, hi)

			kprint("client public key", client.publicKey)
			kprint("shared key", sk)
			kprint("early secret", earlySecretXXX[:])
			kprint("derived secret", d1[:])
			kprint("handshake secret", hs)
			kprint("s hs traffic", sh)
			kprint("server_hs_write_key", hk)
			kprint("server_hs_write_iv", hi)

			// Server Extensions
			r.hashExtension(h)
			r.sealExtension(ch)

			// Server Certificate
			r.hashCertificate(h)
			r.sealCertificate(ch)

			h2 := h.Sum(nil)

			v := sha256.New()
			v.Write(signPrefix[:])
			v.Write(h2)

			signature := signpss(certificateKey, v.Sum(nil))

			// Server Certificate Verify
			r.updateCertificateVerify(signature)
			r.hashCertificateVerify(h)
			r.sealCertificateVerify(ch)

			h3 := h.Sum(nil)                  // finished hash
			fk := hmac256(sh, FinishLabel[:]) // finished key
			vd := hmac256(fk, h3)             // verify data

			kprint("finished key", fk)
			kprint("finished hash", h3)
			kprint("verify data", vd)

			// Server Finished
			r.updateFinished(vd)
			r.hashFinished(h)
			r.sealFinished(ch)

			s.Write(r[:])

			h4 := h.Sum(nil) // final hash
			return finish(s, hs, h4)
		}
	}
	return false
}

func finish(s *KTLSServer, hs, h4 []byte) bool {
	if s.Scan() {
		if decodeHandshakeFinished(s.Bytes()) {
			println("finish")

			// Server Application Keys Calc
			d2 := hmac256(hs, DerivedLabel[:])                   // derived secret
			ms := hmac256(d2, zerosXXX[:])                       // master secret
			sa := hmac256(ms, ServerApplicationTrafficLabel(h4)) // s ap traffic
			ak := hmac256(sa, KeyLabel[:])
			ai := hmac256(sa, IVLabel[:])
			ca := aesgcm(ak, ai)

			kprint("derived secret", d2)
			kprint("master secret", ms)
			kprint("s ap traffic", sa)
			kprint("server_app_write_key", ak)
			kprint("server_app_write_iv", ai)

			s.cipher = ca

			return true
		}
	}
	return false
}

func kprint(name string, key []byte) {
	fmt.Printf("[+] %s: %x\n", name, key)
}
