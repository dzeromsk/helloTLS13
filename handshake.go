package main

import (
	"crypto/sha256"
	"fmt"
)

func handshake(s *ServerConn) bool {
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

func finish(s *ServerConn, hs, h4 []byte) bool {
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
