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
	var out []Summary
	for len(data) > 0 {
		if len(data) < 5 {
			return nil, errors.New("too-short")
		}
		recLen := int(binary.BigEndian.Uint16(data[3:5]))
		if len(data) < 5+recLen {
			return nil, errors.New("too-short")
		}
		one, err := parseRecord(data[5:5+recLen], c)
		if err != nil {
			return nil, err
		}
		out = append(out, one)
		data = data[5+recLen:]
	}
	return out, nil
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
	if off+sessionLen > len(body) {
		return fail()
	}
	off += sessionLen
	if off+2 > len(body) {
		return fail()
	}
	cipherLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if cipherLen%2 != 0 || off+cipherLen > len(body) {
		return fail()
	}
	ciphers := cipherLen / 2
	off += cipherLen
	if off+1 > len(body) {
		return fail()
	}
	compLen := int(body[off])
	off += 1
	if off+compLen > len(body) {
		return fail()
	}
	off += compLen
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
	seen := map[int]bool{}
	for off < end {
		if off+4 > end {
			return fail()
		}
		kind := int(binary.BigEndian.Uint16(body[off : off+2]))
		length := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		if seen[kind] {
			return Summary{}, errors.New("duplicate-extension")
		}
		seen[kind] = true
		if off+4+length > end {
			return fail()
		}
		extensions = append(extensions, kind)
		c.Scanned += 4 + length
		off += 4 + length
	}
	return Summary{Version: version, Ciphers: ciphers, Extensions: extensions,
		Scanned: c.Scanned}, nil
}
