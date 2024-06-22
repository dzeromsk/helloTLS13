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

var certificate = []byte{
	0x30, 0x82, 0x03, 0x3a, 0x30, 0x82, 0x02, 0x22, 0xa0, 0x03, 0x02, 0x01,
	0x02, 0x02, 0x14, 0x6a, 0xe4, 0x89, 0x1c, 0x23, 0x16, 0x28, 0x4c, 0x8c,
	0x45, 0x23, 0x30, 0xa3, 0x12, 0x4f, 0xe8, 0x4f, 0xb6, 0x5f, 0xb0, 0x30,
	0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
	0x05, 0x00, 0x30, 0x12, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04,
	0x03, 0x0c, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x30, 0x1e,
	0x17, 0x0d, 0x32, 0x34, 0x30, 0x36, 0x31, 0x32, 0x31, 0x35, 0x32, 0x31,
	0x33, 0x34, 0x5a, 0x17, 0x0d, 0x33, 0x34, 0x30, 0x36, 0x31, 0x30, 0x31,
	0x35, 0x32, 0x31, 0x33, 0x34, 0x5a, 0x30, 0x12, 0x31, 0x10, 0x30, 0x0e,
	0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70,
	0x6c, 0x65, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
	0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01,
	0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xf4,
	0xfd, 0x4b, 0x15, 0x03, 0x66, 0x71, 0x5a, 0xcb, 0x62, 0xe3, 0xe9, 0x57,
	0x03, 0x65, 0x43, 0x50, 0xfe, 0xda, 0xa4, 0xb5, 0x6b, 0x0a, 0xbb, 0x3b,
	0xd2, 0xdc, 0x88, 0x12, 0x6d, 0x11, 0xe2, 0xd2, 0x85, 0x6e, 0xf7, 0xc8,
	0x87, 0x0f, 0xe7, 0x2e, 0x2a, 0x38, 0x30, 0x22, 0x82, 0x1d, 0x9e, 0x8f,
	0x78, 0xa1, 0xa8, 0x37, 0x45, 0x71, 0x86, 0x91, 0xdc, 0xe9, 0xac, 0x24,
	0xb6, 0x41, 0xf4, 0x9b, 0x0a, 0x0a, 0xa7, 0x1c, 0x6c, 0x57, 0xfb, 0x04,
	0xc4, 0xf2, 0x15, 0x16, 0xc5, 0x84, 0x7b, 0x74, 0x21, 0x7d, 0x65, 0x05,
	0xb4, 0xb3, 0x8b, 0xda, 0xcd, 0xf8, 0xa5, 0xd1, 0x44, 0xc7, 0x89, 0x6f,
	0xfc, 0xd0, 0xc6, 0xfa, 0x3d, 0x1a, 0x23, 0x6b, 0x9f, 0x19, 0xd9, 0xa6,
	0x8c, 0xb7, 0x2b, 0x44, 0x3d, 0x6a, 0x1d, 0x21, 0xc1, 0xd0, 0x51, 0x49,
	0xf1, 0xbc, 0xe0, 0xa1, 0x1b, 0xe6, 0xda, 0xb9, 0xca, 0xaf, 0x0c, 0xe5,
	0x14, 0x21, 0x94, 0x87, 0x33, 0xf3, 0x4e, 0x46, 0x21, 0x87, 0xa0, 0x0f,
	0xd7, 0x19, 0x93, 0x44, 0x4b, 0x07, 0xbc, 0x04, 0x17, 0xd4, 0xad, 0xed,
	0x15, 0x56, 0xc0, 0x59, 0xf3, 0x6a, 0xaf, 0x3f, 0x45, 0x1d, 0x22, 0x9b,
	0xb0, 0x4e, 0xa5, 0xa8, 0x50, 0x5d, 0x2f, 0xe4, 0x4e, 0xfb, 0x99, 0x5b,
	0x10, 0x34, 0x28, 0x44, 0x90, 0xfc, 0xa9, 0x3b, 0x7f, 0x4d, 0xc3, 0xea,
	0x05, 0xb3, 0xcc, 0x11, 0x93, 0xa5, 0x9c, 0xda, 0x0f, 0x60, 0xd6, 0x21,
	0x51, 0xc9, 0xb0, 0xbd, 0xf7, 0x01, 0xe2, 0xcf, 0xf7, 0x0f, 0x02, 0x93,
	0x8c, 0xc5, 0xe6, 0xcd, 0xb2, 0xe9, 0x02, 0x70, 0xd5, 0xc0, 0xa6, 0x4f,
	0x15, 0xd7, 0x04, 0x48, 0x53, 0x10, 0x42, 0xed, 0x94, 0xb1, 0xeb, 0x23,
	0x77, 0x16, 0xee, 0x10, 0xd8, 0x0b, 0x7f, 0x91, 0x88, 0x55, 0x5c, 0x66,
	0xab, 0x3d, 0x0f, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x81, 0x87, 0x30,
	0x81, 0x84, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04,
	0x14, 0x4f, 0x32, 0x36, 0x1f, 0x55, 0xde, 0x2c, 0x5a, 0xa5, 0x99, 0x3a,
	0x33, 0xf0, 0x5f, 0x56, 0x17, 0xae, 0xcc, 0xde, 0xaa, 0x30, 0x1f, 0x06,
	0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x4f, 0x32,
	0x36, 0x1f, 0x55, 0xde, 0x2c, 0x5a, 0xa5, 0x99, 0x3a, 0x33, 0xf0, 0x5f,
	0x56, 0x17, 0xae, 0xcc, 0xde, 0xaa, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d,
	0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30,
	0x12, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x0b, 0x30, 0x09, 0x82, 0x07,
	0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x30, 0x1d, 0x06, 0x03, 0x55,
	0x1d, 0x25, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
	0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
	0x03, 0x02, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
	0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0xd6, 0x78,
	0x0f, 0x5a, 0x58, 0x0d, 0xdf, 0x74, 0x1c, 0x12, 0x78, 0xd4, 0xc6, 0xeb,
	0xe5, 0x9b, 0xa7, 0xbf, 0x42, 0x1a, 0x1b, 0x64, 0x71, 0x1a, 0xdb, 0xe9,
	0x51, 0x95, 0x5d, 0xbd, 0x88, 0xd9, 0x57, 0xef, 0x64, 0x9f, 0x51, 0xda,
	0x74, 0x02, 0xe6, 0xb0, 0x46, 0x87, 0xbb, 0x6a, 0x08, 0xaf, 0x52, 0xef,
	0x3d, 0xe0, 0x01, 0xee, 0x83, 0xe5, 0x42, 0xda, 0x11, 0xf9, 0x25, 0x7f,
	0xc3, 0xb3, 0x90, 0xfd, 0xd1, 0x0c, 0x94, 0xe3, 0x67, 0x61, 0x84, 0x79,
	0x4f, 0xb4, 0xc5, 0x1f, 0x6b, 0x7e, 0x6e, 0x9b, 0x3f, 0x21, 0x5a, 0x3e,
	0x33, 0x88, 0x78, 0x13, 0x9a, 0x4a, 0x13, 0x09, 0x23, 0xa0, 0x12, 0x86,
	0x03, 0xb1, 0xdd, 0x20, 0xac, 0xda, 0x77, 0x8b, 0x5d, 0xfa, 0xef, 0x94,
	0x09, 0x97, 0xa7, 0x9a, 0xe6, 0x39, 0xb0, 0xdc, 0x44, 0x33, 0xa2, 0x6d,
	0x89, 0xbe, 0x04, 0x8a, 0x1c, 0x64, 0x4e, 0x9c, 0xa8, 0xbe, 0x98, 0xac,
	0x50, 0x2a, 0x3f, 0x3b, 0x3c, 0xda, 0xd9, 0xfd, 0xbe, 0x13, 0x83, 0xb9,
	0x20, 0x05, 0x49, 0x9c, 0x4c, 0x88, 0xce, 0x1f, 0x2d, 0x73, 0x94, 0xb9,
	0x98, 0x4a, 0x8e, 0x8d, 0x24, 0x66, 0x52, 0x41, 0xb3, 0x06, 0xf7, 0xb4,
	0xc7, 0x54, 0x42, 0x8a, 0xe2, 0xc4, 0x8f, 0xa4, 0xc7, 0xc8, 0x21, 0xce,
	0x81, 0x1b, 0x34, 0x5a, 0x45, 0x67, 0x1a, 0xae, 0x23, 0x67, 0x41, 0x9b,
	0x95, 0xe0, 0x92, 0xb4, 0x29, 0x49, 0x73, 0xc8, 0xd6, 0xc8, 0xd8, 0xb7,
	0x09, 0xdd, 0xf9, 0x8d, 0x52, 0x14, 0x31, 0xe4, 0x1c, 0xa5, 0xe4, 0xf9,
	0x59, 0xa7, 0x34, 0x46, 0x9b, 0x0c, 0x22, 0x03, 0x94, 0xae, 0x06, 0xf7,
	0x45, 0x40, 0x6a, 0x76, 0x4a, 0x72, 0x9e, 0xfc, 0x12, 0xdc, 0xeb, 0xce,
	0x0a, 0x62, 0xdc, 0xce, 0xe9, 0xe8, 0x66, 0xc3, 0xac, 0x8f, 0x6c, 0x66,
	0x3c, 0xfc,
}

var certificateKey = []byte{
	0x30, 0x82, 0x04, 0xbe, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
	0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x04, 0xa8, 0x30, 0x82, 0x04, 0xa4, 0x02, 0x01,
	0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xf4, 0xfd, 0x4b, 0x15, 0x03, 0x66, 0x71, 0x5a, 0xcb, 0x62,
	0xe3, 0xe9, 0x57, 0x03, 0x65, 0x43, 0x50, 0xfe, 0xda, 0xa4, 0xb5, 0x6b, 0x0a, 0xbb, 0x3b, 0xd2,
	0xdc, 0x88, 0x12, 0x6d, 0x11, 0xe2, 0xd2, 0x85, 0x6e, 0xf7, 0xc8, 0x87, 0x0f, 0xe7, 0x2e, 0x2a,
	0x38, 0x30, 0x22, 0x82, 0x1d, 0x9e, 0x8f, 0x78, 0xa1, 0xa8, 0x37, 0x45, 0x71, 0x86, 0x91, 0xdc,
	0xe9, 0xac, 0x24, 0xb6, 0x41, 0xf4, 0x9b, 0x0a, 0x0a, 0xa7, 0x1c, 0x6c, 0x57, 0xfb, 0x04, 0xc4,
	0xf2, 0x15, 0x16, 0xc5, 0x84, 0x7b, 0x74, 0x21, 0x7d, 0x65, 0x05, 0xb4, 0xb3, 0x8b, 0xda, 0xcd,
	0xf8, 0xa5, 0xd1, 0x44, 0xc7, 0x89, 0x6f, 0xfc, 0xd0, 0xc6, 0xfa, 0x3d, 0x1a, 0x23, 0x6b, 0x9f,
	0x19, 0xd9, 0xa6, 0x8c, 0xb7, 0x2b, 0x44, 0x3d, 0x6a, 0x1d, 0x21, 0xc1, 0xd0, 0x51, 0x49, 0xf1,
	0xbc, 0xe0, 0xa1, 0x1b, 0xe6, 0xda, 0xb9, 0xca, 0xaf, 0x0c, 0xe5, 0x14, 0x21, 0x94, 0x87, 0x33,
	0xf3, 0x4e, 0x46, 0x21, 0x87, 0xa0, 0x0f, 0xd7, 0x19, 0x93, 0x44, 0x4b, 0x07, 0xbc, 0x04, 0x17,
	0xd4, 0xad, 0xed, 0x15, 0x56, 0xc0, 0x59, 0xf3, 0x6a, 0xaf, 0x3f, 0x45, 0x1d, 0x22, 0x9b, 0xb0,
	0x4e, 0xa5, 0xa8, 0x50, 0x5d, 0x2f, 0xe4, 0x4e, 0xfb, 0x99, 0x5b, 0x10, 0x34, 0x28, 0x44, 0x90,
	0xfc, 0xa9, 0x3b, 0x7f, 0x4d, 0xc3, 0xea, 0x05, 0xb3, 0xcc, 0x11, 0x93, 0xa5, 0x9c, 0xda, 0x0f,
	0x60, 0xd6, 0x21, 0x51, 0xc9, 0xb0, 0xbd, 0xf7, 0x01, 0xe2, 0xcf, 0xf7, 0x0f, 0x02, 0x93, 0x8c,
	0xc5, 0xe6, 0xcd, 0xb2, 0xe9, 0x02, 0x70, 0xd5, 0xc0, 0xa6, 0x4f, 0x15, 0xd7, 0x04, 0x48, 0x53,
	0x10, 0x42, 0xed, 0x94, 0xb1, 0xeb, 0x23, 0x77, 0x16, 0xee, 0x10, 0xd8, 0x0b, 0x7f, 0x91, 0x88,
	0x55, 0x5c, 0x66, 0xab, 0x3d, 0x0f, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01, 0x00, 0x1d,
	0x29, 0xd7, 0xd9, 0xc1, 0x05, 0x5d, 0x62, 0x13, 0x0b, 0x0b, 0x19, 0x78, 0x57, 0xb9, 0xa2, 0xb9,
	0x4e, 0x15, 0x45, 0xfd, 0x28, 0xa8, 0x66, 0xe0, 0x78, 0xb9, 0xf2, 0xe2, 0xca, 0xa4, 0x11, 0xed,
	0xc0, 0x9f, 0x94, 0x94, 0x84, 0xeb, 0x72, 0x38, 0x2f, 0x23, 0x70, 0x2b, 0x73, 0x74, 0xc6, 0x2e,
	0xcb, 0x0b, 0xe7, 0x63, 0xe8, 0xfa, 0xda, 0x2b, 0x9b, 0xf2, 0x1f, 0x21, 0x61, 0xa6, 0xd9, 0x50,
	0xe9, 0x71, 0x9a, 0x32, 0x0a, 0x7d, 0xb0, 0xae, 0x81, 0x29, 0x56, 0x34, 0x57, 0x3f, 0xed, 0x98,
	0x45, 0xf2, 0x50, 0xe7, 0xcc, 0x7a, 0x81, 0x20, 0x03, 0x5b, 0xe1, 0x95, 0x57, 0x4c, 0x2f, 0x82,
	0xaa, 0xc4, 0x49, 0xa3, 0x79, 0x49, 0x96, 0xc4, 0xd5, 0x74, 0x34, 0xd2, 0x1c, 0x37, 0x23, 0xc9,
	0xe4, 0x4b, 0xb0, 0xfb, 0x17, 0x40, 0xce, 0xa4, 0x70, 0x47, 0xed, 0x2f, 0x90, 0x8c, 0x3a, 0xea,
	0xb9, 0xac, 0x7d, 0xf4, 0xfa, 0x6e, 0xc9, 0xe7, 0x85, 0x1b, 0xe3, 0x36, 0x53, 0x17, 0xec, 0xef,
	0x40, 0xb9, 0x36, 0x3d, 0xf3, 0x88, 0x63, 0xec, 0x35, 0x45, 0x42, 0x99, 0x71, 0xd6, 0xf2, 0x63,
	0x71, 0x39, 0x82, 0x75, 0x45, 0x2e, 0x7a, 0xdb, 0x2d, 0x5f, 0x75, 0x18, 0x2e, 0xdf, 0x25, 0x4f,
	0xf9, 0xf4, 0xa7, 0x96, 0xf3, 0x3b, 0xce, 0xe6, 0x00, 0x2a, 0xc0, 0x6c, 0x8b, 0x85, 0x6c, 0x96,
	0x4a, 0x73, 0x14, 0xea, 0xd2, 0xcd, 0x32, 0xbe, 0x90, 0x6e, 0x93, 0x6b, 0xfd, 0x22, 0xc1, 0x1f,
	0x83, 0xb6, 0xe8, 0x87, 0xd7, 0x23, 0x76, 0x39, 0x24, 0xba, 0x71, 0x9d, 0x88, 0x06, 0xca, 0x05,
	0xee, 0xac, 0x9a, 0x6a, 0xe8, 0x35, 0xfa, 0x3b, 0xc8, 0x6f, 0x65, 0xa1, 0x9e, 0xd3, 0x54, 0xb2,
	0x83, 0x49, 0x65, 0xf2, 0xb2, 0x4b, 0x26, 0x2a, 0x39, 0xc1, 0xe2, 0x33, 0x9f, 0x89, 0x45, 0x02,
	0x81, 0x81, 0x00, 0xfc, 0x9b, 0xce, 0xfa, 0x3f, 0x56, 0xcb, 0x31, 0x76, 0xaf, 0x41, 0x28, 0x01,
	0xfc, 0xef, 0xb2, 0xfd, 0xbb, 0x0a, 0x6e, 0x76, 0x76, 0x4d, 0x56, 0x7e, 0x62, 0x80, 0xba, 0x37,
	0xc6, 0x6b, 0x40, 0x6a, 0xcf, 0x05, 0xa7, 0x6f, 0x66, 0x4c, 0xfb, 0xaa, 0xb2, 0x0e, 0x81, 0x32,
	0xde, 0xf3, 0x2d, 0xa4, 0x87, 0x30, 0x61, 0x98, 0x06, 0x15, 0x6d, 0x33, 0xf6, 0x21, 0xfa, 0xb0,
	0x1b, 0xca, 0x97, 0x18, 0x0a, 0xda, 0x10, 0xb9, 0x88, 0x89, 0x6f, 0x81, 0x56, 0x70, 0x0d, 0x4a,
	0x70, 0x6c, 0x13, 0x9f, 0x66, 0xe3, 0x9e, 0x5f, 0x81, 0xad, 0x0d, 0x79, 0x76, 0x8f, 0xd5, 0x78,
	0x2c, 0x61, 0x32, 0xa1, 0x9e, 0x64, 0x09, 0xba, 0x14, 0x4b, 0xf5, 0x1f, 0xb4, 0x38, 0x2d, 0x6d,
	0x1e, 0xc6, 0x3b, 0x49, 0xa2, 0x6c, 0x6d, 0x52, 0x78, 0x77, 0x40, 0x97, 0x6f, 0x9c, 0xa3, 0xf6,
	0x92, 0xbf, 0xdd, 0x02, 0x81, 0x81, 0x00, 0xf8, 0x47, 0x4c, 0x5f, 0x30, 0x01, 0x80, 0x0c, 0xc9,
	0x2e, 0x09, 0x60, 0x20, 0x87, 0x8d, 0x8a, 0x18, 0xe5, 0x9f, 0x1e, 0x01, 0x91, 0xe8, 0x3d, 0x4e,
	0x25, 0xc4, 0x4f, 0xe4, 0x9c, 0xa9, 0x0b, 0x22, 0xb8, 0xee, 0x01, 0xe5, 0x70, 0xed, 0x31, 0x02,
	0x9b, 0x5c, 0x4c, 0x4e, 0x97, 0x95, 0x27, 0x46, 0xa5, 0x6e, 0xdc, 0x5a, 0xbe, 0xd1, 0xc2, 0xbb,
	0xb6, 0x60, 0x87, 0x28, 0x5f, 0xa8, 0x62, 0x01, 0x47, 0xc5, 0x6c, 0x97, 0xcb, 0x51, 0x8c, 0x44,
	0xfa, 0x98, 0xe1, 0x4c, 0xdc, 0xa6, 0x1b, 0xb5, 0x2f, 0x7b, 0xa1, 0xd2, 0x02, 0x75, 0x17, 0xb7,
	0xa9, 0x82, 0xe4, 0x11, 0x55, 0x3b, 0xaa, 0x2e, 0x41, 0x90, 0xd9, 0x4d, 0xed, 0x1e, 0xc1, 0xfc,
	0xce, 0xd8, 0x68, 0xf2, 0x9f, 0x66, 0x3f, 0x49, 0x72, 0xe1, 0xf3, 0x82, 0x1a, 0x26, 0x38, 0xaa,
	0x10, 0xb6, 0x18, 0xbf, 0x51, 0x57, 0xdb, 0x02, 0x81, 0x81, 0x00, 0xbc, 0xe8, 0xfc, 0x81, 0xb3,
	0x2a, 0x82, 0x6c, 0xac, 0x58, 0x65, 0xfe, 0xb8, 0x75, 0xe3, 0x00, 0x55, 0xb6, 0x32, 0x17, 0xe7,
	0xe9, 0x92, 0xee, 0xb3, 0x37, 0x91, 0x13, 0x32, 0x30, 0xe5, 0xf6, 0x57, 0xaa, 0x18, 0x8d, 0x5d,
	0xc7, 0x00, 0x9d, 0x58, 0xcb, 0x2e, 0x03, 0xba, 0xfa, 0x76, 0x9b, 0xd4, 0xa5, 0xf1, 0x2d, 0x9b,
	0x16, 0x39, 0xa1, 0xe0, 0x31, 0x1a, 0xba, 0x32, 0x47, 0xa6, 0x5b, 0x16, 0x74, 0xcf, 0x1d, 0xa0,
	0xd2, 0x96, 0x0d, 0x58, 0x89, 0x3e, 0xe5, 0x01, 0x9d, 0x4f, 0x85, 0xe1, 0x38, 0x7d, 0xd2, 0xeb,
	0x93, 0xbb, 0xca, 0x0e, 0xe2, 0xf6, 0xaf, 0xea, 0xde, 0x2d, 0x96, 0x42, 0xbd, 0x84, 0x0c, 0xae,
	0x27, 0x0d, 0xa2, 0xf4, 0x21, 0xbf, 0xbd, 0x61, 0x14, 0x99, 0xa4, 0xae, 0xed, 0x93, 0xee, 0xb1,
	0xb5, 0x3b, 0x61, 0x87, 0x9e, 0xc5, 0x62, 0xed, 0x3c, 0x53, 0xd5, 0x02, 0x81, 0x80, 0x5c, 0x29,
	0xdb, 0x67, 0xda, 0x62, 0x34, 0x2e, 0x8a, 0xdf, 0xd4, 0x0b, 0x23, 0x08, 0x2e, 0xba, 0x7c, 0xd3,
	0x80, 0x65, 0x9b, 0x1f, 0x96, 0x9e, 0x6b, 0x4c, 0x09, 0xbb, 0xbe, 0x99, 0x89, 0x06, 0xe1, 0x34,
	0xd4, 0xe5, 0x4f, 0x4e, 0xc4, 0x3d, 0xd5, 0x41, 0xe6, 0xd9, 0x4c, 0xb3, 0x68, 0x62, 0xd4, 0x0e,
	0xc5, 0x40, 0x77, 0x4f, 0x2e, 0x7e, 0xa3, 0x3f, 0xe8, 0x45, 0x43, 0xef, 0x7e, 0x8a, 0x22, 0xff,
	0x89, 0x81, 0xee, 0x37, 0x43, 0x66, 0x56, 0x94, 0xcf, 0xfb, 0x92, 0x94, 0xb5, 0xf4, 0xc3, 0x25,
	0x85, 0x37, 0x64, 0xc6, 0x14, 0xc1, 0x61, 0x24, 0x43, 0xba, 0x75, 0xd4, 0xb5, 0xf9, 0x4e, 0x82,
	0x78, 0x4a, 0xb2, 0x6a, 0xbb, 0x68, 0x37, 0x78, 0x71, 0x4d, 0x44, 0x03, 0x77, 0xe9, 0x36, 0x52,
	0xb7, 0x1d, 0xb5, 0xc6, 0x0f, 0x3a, 0x29, 0xa7, 0x5a, 0x71, 0x85, 0x53, 0xa4, 0xd1, 0x02, 0x81,
	0x81, 0x00, 0x86, 0xcf, 0xe6, 0xb5, 0x59, 0x3c, 0x72, 0xa9, 0x94, 0x02, 0xe6, 0xc0, 0xe6, 0xb2,
	0x3c, 0xd6, 0x52, 0xf6, 0x3d, 0x10, 0x0c, 0xd8, 0xcb, 0x2e, 0xac, 0xda, 0xca, 0xf1, 0x97, 0x46,
	0x00, 0x40, 0xd9, 0x27, 0xdd, 0xd7, 0xde, 0x63, 0x24, 0xdf, 0x6a, 0x3c, 0xef, 0xc3, 0xa0, 0xe1,
	0x55, 0xd6, 0x4a, 0x24, 0xed, 0xe1, 0xc9, 0xf1, 0xcd, 0xf2, 0xf2, 0x05, 0xc3, 0x78, 0xbd, 0xc9,
	0xea, 0x8a, 0x71, 0xde, 0xe4, 0xf1, 0xac, 0xeb, 0xf4, 0xe9, 0x51, 0x5f, 0x47, 0xcb, 0xfa, 0x43,
	0xe4, 0x99, 0x33, 0x72, 0xaf, 0x6b, 0x22, 0xb4, 0x9b, 0x48, 0xec, 0x7b, 0x85, 0xac, 0x8d, 0x5d,
	0x04, 0x18, 0xc5, 0x96, 0x42, 0xe3, 0x92, 0x5d, 0x63, 0xd1, 0x57, 0x68, 0x9f, 0x6e, 0xf5, 0x7b,
	0xb8, 0x9f, 0xb9, 0x76, 0xdc, 0xa8, 0x81, 0x61, 0x87, 0x74, 0xa1, 0xec, 0x70, 0xc1, 0xde, 0x17,
	0x0a, 0xb0,
}

var serverPublic = []byte{
	0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d, 0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a, 0xf9,
	0x10, 0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa, 0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80,
	0xb6, 0x15,
}

var serverPrivate = []byte{
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e,
	0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad,
	0xae, 0xaf,
}

var random = []byte{
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, // |pqrstuvw|
	0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, // |xyz{|}~.|
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, // |........|
	0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, // |........|
}

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

	r := map[string]any{
		"serverPrivate":                 serverPrivate,
		"earlySecret":                   earlySecret,
		"d1":                            hkdfExpandLabel(earlySecret, "derived", emptyHash[:], 32),
		"hello":                         encodeHello(),
		"extensions":                    encodeExtensions(),
		"certificate":                   encodeCertificate(),
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

func encodeHello() []byte {
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

func encodeCertificate() []byte {
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