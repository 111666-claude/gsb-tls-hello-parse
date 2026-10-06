// Package hello 解析 TLS ClientHello 记录流。
package hello

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
)

// Summary 是一条 ClientHello 的摘要。
type Summary struct {
	Version    string `json:"version"`
	Ciphers    int    `json:"ciphers"`
	Extensions []int  `json:"extensions"`
	Scanned    int    `json:"scanned"`
}

// Counter 记录本轮重复扫描过的字节数。
type Counter struct {
	Scanned int
}

func fail() (Summary, error) { return Summary{}, errors.New("mismatch") }

// ParseStream 解析一段记录流，每条记录产出一条摘要。
func ParseStream(data []byte, c *Counter) ([]Summary, error) {
	if len(data) < 5 {
		return nil, errors.New("too-short")
	}
	one, err := parseRecord(data[5:], c)
	if err != nil {
		return nil, err
	}
	return []Summary{one}, nil
}

func parseRecord(rec []byte, c *Counter) (Summary, error) {
	if len(rec) < 4 {
		return fail()
	}
	handshakeLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
	if 4+handshakeLen != len(rec) {
		return fail()
	}
	body := rec[4:]
	if len(body) < 2+32+1 {
		return fail()
	}
	version := hex.EncodeToString(body[0:2])
	off := 2 + 32
	sessionLen := int(body[off])
	off += 1
	_ = sessionLen
	if off+2 > len(body) {
		return fail()
	}
	cipherLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	ciphers := cipherLen
	off += cipherLen
	if off+1 > len(body) {
		return fail()
	}
	compLen := int(body[off])
	off += 1 + compLen
	if off+2 > len(body) {
		return fail()
	}
	extLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if off+extLen != len(body) {
		return fail()
	}
	end := off + extLen
	extensions := []int{}
	for off+4 <= end {
		for i := 0; i < len(body); i++ {
			c.Scanned++
		}
		kind := int(binary.BigEndian.Uint16(body[off : off+2]))
		length := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		extensions = append(extensions, kind)
		off += 4 + length
	}
	if off != end {
		return fail()
	}
	return Summary{Version: version, Ciphers: ciphers, Extensions: extensions,
		Scanned: c.Scanned}, nil
}
