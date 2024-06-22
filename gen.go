//go:build ignore

// This program generates static TLS data
// Invoke as
//
//	go run gen.go -output md5block.go

package main

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"go/format"
	"log"
	"os"
	"strings"
	"text/template"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

var output = flag.String("output", "static.go", "output file name")

var (
	// We use static certs to make records reproducible
	randomFile         = flag.String("random", "testdata/random.dat", "Random string used in Server Hello")
	certificateFile    = flag.String("cert", "testdata/tls.crt", "TLS Certificate")
	certificateKeyFile = flag.String("key", "testdata/tls.key", "TLS Certificate Key")
	serverPublicFile   = flag.String("serverPublic", "testdata/server.pub", "Ephemeral public TLS key")
	serverPrivateFile  = flag.String("serverPrivate", "testdata/server.key", "Ephemeral private TLS key")
)

func main() {
	flag.Parse()

	certificate, err := os.ReadFile(*certificateFile)
	if err != nil {
		log.Fatal(err)
	}

	certificateKey, err := os.ReadFile(*certificateKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	serverPublic, err := os.ReadFile(*serverPublicFile)
	if err != nil {
		log.Fatal(err)
	}

	serverPrivate, err := os.ReadFile(*serverPrivateFile)
	if err != nil {
		log.Fatal(err)
	}

	random, err := os.ReadFile(*randomFile)
	if err != nil {
		log.Fatal(err)
	}

	r := map[string]any{
		"serverPrivate":                 serverPrivate,
		"earlySecret":                   earlySecret,
		"d1":                            hkdfExpandLabel(earlySecret, "derived", emptyHash[:], 32),
		"hello":                         encodeHello(random, serverPublic),
		"extensions":                    encodeExtensions(),
		"certificate":                   encodeCertificate(certificate),
		"certificateVerify":             encodeCertificateVerify(),
		"finished":                      encodeFinished(),
		"derivedLabel":                  updateHash(encodeExpandedHkdfLabel("derived", 32), emptyHash[:]),
		"serverHandshakeTrafficLabel":   encodeExpandedHkdfLabel("s hs traffic", 32),
		"clientHandshakeSTrafficLabel":  encodeExpandedHkdfLabel("c hs traffic", 32),
		"keyLabel":                      encodeExpandedHkdfLabelNoHash("key", 16),
		"ivLabel":                       encodeExpandedHkdfLabelNoHash("iv", 12),
		"finishLabel":                   encodeExpandedHkdfLabelNoHash("finished", 32),
		"clientApplicationTrafficLabel": encodeExpandedHkdfLabel("c ap traffic", 32),
		"serverApplicationTrafficLabel": encodeExpandedHkdfLabel("s ap traffic", 32),
		"zeros":                         zeros,
		"signPrefix":                    encodeSignPrefix(),
		"certificateKey":                certificateKey,
	}
	for k := range r {
		if b, ok := r[k].([]byte); ok {
			r[k+"Size"] = len(b)
		}
	}

	var buf bytes.Buffer

	t := template.Must(template.New("main").Funcs(funcs).Parse(program))
	if err := t.Execute(&buf, r); err != nil {
		log.Fatal(err)
	}

	data, err := format.Source(buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile(*output, data, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

var funcs = template.FuncMap{
	"hexdump": hexdump,
}

var (
	zeros       = make([]byte, 32)
	psk         = make([]byte, 32)
	emptyHash   = sha256.Sum256(nil)
	earlySecret = hkdf.Extract(sha256.New, psk, zeros)
)

func encodeHello(random, serverPublic []byte) []byte {
	data := make([]byte, 0, 127)
	b := cryptobyte.NewBuilder(data)
	b.AddUint8(0x16)    // handshake record
	b.AddUint16(0x0303) // legacy protocol version of "3,3" (TLS 1.2)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0x02)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(0x0303) // Server Version
			// c.random = make([]byte, 32)
			b.AddBytes(random) // Server Random
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				// TODO: assume session is always 32 bytes?
				b.AddBytes(make([]byte, 32))
			})
			b.AddUint16(0x1301) // Cipher Suite
			b.AddUint8(0x00)    // Compression Method
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16(0x002b) // Supported Versions
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(0x0304) // TLS 1.3
				})
				b.AddUint16(0x0033) // Key Share
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(0x001d) // x25519
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(serverPublic) // Public Key
					})
				})
			})
		})
	})
	return b.BytesOrPanic()
}

func encodeExtensions() []byte {
	var b cryptobyte.Builder
	b.AddUint8(0x17)    // Application data
	b.AddUint16(0x0303) // TLS 1.2
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0x08) // Encrypted extensions
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(0x0000)
		})
		b.AddUint8(0x16)             // Handshake record
		b.AddBytes(make([]byte, 16)) // Auth/AEAD tag
	})
	return b.BytesOrPanic()
}

func encodeCertificate(certificate []byte) []byte {
	var b cryptobyte.Builder
	b.AddUint8(0x17)    // Application data
	b.AddUint16(0x0303) // TLS 1.2
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0x0b) // Certificate
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(0x00) // Request Context
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(certificate)
				})
				b.AddUint16(0x0000) // Certificate extensions
			})
		})
		b.AddUint8(0x16)             // Handshake record
		b.AddBytes(make([]byte, 16)) // Auth/AEAD tag
	})
	return b.BytesOrPanic()
}

func encodeCertificateVerify() []byte {
	var b cryptobyte.Builder
	b.AddUint8(0x17)    // Application data
	b.AddUint16(0x0303) // TLS 1.2
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0x0f) // Certificate Verify
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(0x0804) // RSA-PSS-RSAE-SHA256 signature
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(make([]byte, 256))
			})
		})
		b.AddUint8(0x16)             // Handshake record
		b.AddBytes(make([]byte, 16)) // Auth/AEAD tag
	})
	return b.BytesOrPanic()
}

func encodeFinished() []byte {
	var b cryptobyte.Builder
	b.AddUint8(0x17)    // Application data
	b.AddUint16(0x0303) // TLS 1.2
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0x14) // Finished
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(make([]byte, 32))
		})
		b.AddUint8(0x16)             // Handshake record
		b.AddBytes(make([]byte, 16)) // Auth/AEAD tag
	})
	return b.BytesOrPanic()
}

func hkdfExpandLabel(secret []byte, label string, context []byte, length uint16) []byte {
	// From https://datatracker.ietf.org/doc/html/rfc8446#section-7.1:
	//
	//	HKDF-Expand-Label(Secret, Label, Context, Length) =
	//	     HKDF-Expand(Secret, HkdfLabel, Length)
	//
	//	Where HkdfLabel is specified as:
	//
	//	struct {
	//	    uint16 length = Length;
	//	    opaque label<7..255> = "tls13 " + Label;
	//	    opaque context<0..255> = Context;
	//	} HkdfLabel;
	//
	//	Derive-Secret(Secret, Label, Messages) =
	//	     HKDF-Expand-Label(Secret, Label,
	//	                       Transcript-Hash(Messages), Hash.length)
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})

	reader := hkdf.Expand(sha256.New, secret, hkdfLabel.BytesOrPanic())
	buf := make([]byte, length)
	reader.Read(buf)
	return buf
}

func encodeExpandedHkdfLabelNoHash(label string, length uint16) []byte {
	var b cryptobyte.Builder
	b.AddUint16(length)
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(nil)
	})

	// extra byte added by hkdf.Expand, counter=1
	b.AddUint8(1)
	return b.BytesOrPanic()
}

func encodeExpandedHkdfLabel(label string, length uint16) []byte {
	var b cryptobyte.Builder
	b.AddUint16(length)
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(make([]byte, length))
	})

	// extra byte added by hkdf.Expand, counter=1
	b.AddUint8(1)
	return b.BytesOrPanic()
}

func updateHash(label []byte, context []byte) []byte {
	copy(label[len(label)-1-len(context):], context)
	return label
}

func encodeSignPrefix() []byte {
	o := make([]byte, 0, 98)
	o = append(o, bytes.Repeat([]byte{0x20}, 64)...)
	o = append(o, []byte("TLS 1.3, server CertificateVerify")...)
	o = append(o, 0x00)
	return o
}

// hexdump prints a hexdump of the given buffer.
func hexdump(b []byte) string {
	var w strings.Builder
	const step = 8
	length := len(b)
	for i := 0; i < length; i += step {
		end := i + step
		if end > length {
			end = length
		}
		line := b[i:end]
		// fmt.Printf("%08x  ", i) // Print the offset.
		// Print hex values
		for j := 0; j < step; j++ {
			if j < len(line) {
				fmt.Fprintf(&w, "0x%02x, ", line[j])
			} else {
				fmt.Fprint(&w, "      ")
			}
		}
		// Print ASCII representation
		fmt.Fprint(&w, "// |")
		for j := 0; j < len(line); j++ {
			if line[j] >= 32 && line[j] <= 126 {
				fmt.Fprintf(&w, "%c", line[j])
			} else {
				fmt.Fprint(&w, ".")
			}
		}
		fmt.Fprintln(&w, "|")
	}
	return w.String()
}

const program = `// Code generated by go run gen.go -output static.go; DO NOT EDIT.

package main

import "hash"

var serverPrivate = [...]byte{
	{{ .serverPrivate | hexdump -}}
}

var earlySecretXXX = [...]byte{
	{{ .earlySecret | hexdump -}}
}

var d1 = [...]byte{
	{{ .d1 | hexdump -}}
}

var handshakeTemplate = [...]byte{
	// Hello
	{{ .hello | hexdump }}

	// Extensions
	{{ .extensions | hexdump }}

	// Certificate
	{{ .certificate | hexdump }}

	// CertificateVerify
	{{ .certificateVerify | hexdump }}

	// Finished
	{{ .finished | hexdump -}}
}

var DerivedLabel = [...]byte{
	{{ .derivedLabel | hexdump -}}
}

var serverHandshakeTrafficLabel = [...]byte{
	{{ .serverHandshakeTrafficLabel | hexdump -}}
}

func ServerHandshakeTrafficLabel(hash []byte) []byte {
	var label = serverHandshakeTrafficLabel
	copy(label[{{ .serverHandshakeTrafficLabelSize }}-1-32:], hash[:32])
	return label[:]
}

var ClientHandshakeSTrafficLabel = [...]byte{
	{{ .clientHandshakeSTrafficLabel | hexdump -}}
}

var KeyLabel = [...]byte{
	{{ .keyLabel | hexdump -}}
}

var IVLabel = [...]byte{
	{{ .ivLabel | hexdump -}}
}

var FinishLabel = [...]byte{
	{{ .finishLabel | hexdump -}}
}

var clientApplicationTrafficLabel = [...]byte{
	{{ .clientApplicationTrafficLabel | hexdump -}}
}

func ClientApplicationTrafficLabel(hash []byte) []byte {
	var label = clientApplicationTrafficLabel
	copy(label[{{ .clientApplicationTrafficLabelSize }}-1-32:], hash[:32])
	return label[:]
}

var serverApplicationTrafficLabel = [...]byte{
	{{ .serverApplicationTrafficLabel | hexdump -}}
}

func ServerApplicationTrafficLabel(hash []byte) []byte {
	var label = serverApplicationTrafficLabel
	copy(label[{{ .serverApplicationTrafficLabelSize }}-1-32:], hash[:32])
	return label[:]
}

var signPrefix = [...]byte{
	{{ .signPrefix | hexdump -}}
}

var zerosXXX = [...]byte{
	{{ .zeros | hexdump -}}
}

var certificateKey = []byte{
	{{ .certificateKey | hexdump -}}
}

const (
	header = 5
	typ    = 1
	tag    = 16
	meta   = header + typ + tag
)

const handshakeSize = {{ .helloSize }} + {{ .extensionsSize }} + {{ .certificateSize }} + {{ .certificateVerifySize }} + {{ .finishedSize }}
type handshakeView [handshakeSize]byte


func (raw *handshakeView) hashHello(hash hash.Hash) {
	const offset, data = 0, {{ .helloSize }}-header

	hash.Write(raw[offset+header : offset+header+data])
}

func (raw *handshakeView) updateHello(sessionID []byte) {
	const offset, data = 0, {{ .helloSize }}
	copy(raw[offset+8+8+8+8+8+4:], sessionID[:32])
}

func (raw *handshakeView) sealExtension(cipher *Cipher) {
	const offset, data = {{ .helloSize }}, {{ .extensionsSize }}-meta

	aad := raw[offset : offset+header]
	src := raw[offset+header : offset+header+data+typ]
	dst := raw[offset+header : offset+header : offset+header+data+typ+tag]

	cipher.seal(dst, src, aad)
}

func (raw *handshakeView) hashExtension(hash hash.Hash) {
	const offset, data = {{ .helloSize }}, {{ .extensionsSize }}-meta

	hash.Write(raw[offset+header : offset+header+data])
}

func (raw *handshakeView) sealCertificate(cipher *Cipher) {
	const offset, data = {{ .helloSize }}+{{ .extensionsSize }}, {{ .certificateSize }}-meta

	aad := raw[offset : offset+header]
	src := raw[offset+header : offset+header+data+typ]
	dst := raw[offset+header : offset+header : offset+header+data+typ+tag]

	cipher.seal(dst, src, aad)
}

func (raw *handshakeView) hashCertificate(hash hash.Hash) {
	const offset, data = {{ .helloSize }}+{{ .extensionsSize }}, {{ .certificateSize }}-meta

	hash.Write(raw[offset+header : offset+header+data])
}

func (raw *handshakeView) sealCertificateVerify(cipher *Cipher) {
	const offset, data = {{ .helloSize }}+{{ .extensionsSize }}+{{ .certificateSize }}, {{ .certificateVerifySize }}-meta

	aad := raw[offset : offset+header]
	src := raw[offset+header : offset+header+data+typ]
	dst := raw[offset+header : offset+header : offset+header+data+typ+tag]

	cipher.seal(dst, src, aad)
}

func (raw *handshakeView) hashCertificateVerify(hash hash.Hash) {
	const offset, data = {{ .helloSize }}+{{ .extensionsSize }}+{{ .certificateSize }}, {{ .certificateVerifySize }}-meta

	hash.Write(raw[offset+header : offset+header+data])
}

func (raw *handshakeView) updateCertificateVerify(signature []byte) {
	const offset, data = {{ .helloSize }}+{{ .extensionsSize }}+{{ .certificateSize }}, {{ .certificateVerifySize }}-meta
	copy(raw[offset+header+1+3+2+2:], signature)
}

func (raw *handshakeView) sealFinished(cipher *Cipher) {
	const offset, data = {{ .helloSize }}+{{ .extensionsSize }}+{{ .certificateSize }}+{{ .certificateVerifySize }}, {{ .finishedSize }}-meta

	aad := raw[offset : offset+header]
	src := raw[offset+header : offset+header+data+typ]
	dst := raw[offset+header : offset+header : offset+header+data+typ+tag]

	cipher.seal(dst, src, aad)
}

func (raw *handshakeView) hashFinished(hash hash.Hash) {
	const offset, data = {{ .helloSize }}+{{ .extensionsSize }}+{{ .certificateSize }}+{{ .certificateVerifySize }}, {{ .finishedSize }}-meta

	hash.Write(raw[offset+header : offset+header+data])
}

func (raw *handshakeView) updateFinished(verifyData []byte) {
	const offset, data = {{ .helloSize }}+{{ .extensionsSize }}+{{ .certificateSize }}+{{ .certificateVerifySize }}, {{ .finishedSize }}-meta
	copy(raw[offset+header+1+3:], verifyData)
}
`
