package main

import (
	"bufio"
	"bytes"
	"net"
)

var resp = []byte("HTTP/1.1 200\r\nContent-Length: 12\r\n\r\nHello World\n")

func http11(conn net.Conn) {
	defer conn.Close()
	s := bufio.NewScanner(conn)
	s.Split(scanRequest)
	for s.Scan() {
		conn.Write(resp)
	}
}

var crlf = []byte{'\r', '\n', '\r', '\n'}

func scanRequest(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.Index(data, crlf); i >= 0 {
		return i + 1, data[0:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}
