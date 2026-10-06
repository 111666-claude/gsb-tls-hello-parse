// 手工拼记录与 ClientHello，供测试与场景使用。
package hello

import "encoding/binary"

// ClientHello 拼一条 ClientHello 消息体。
func ClientHello(sessionID, ciphers, extensions []byte) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)
	head := make([]byte, 2)
	binary.BigEndian.PutUint16(head, uint16(len(ciphers)))
	body = append(body, head...)
	body = append(body, ciphers...)
	body = append(body, 1, 0)
	binary.BigEndian.PutUint16(head, uint16(len(extensions)))
	body = append(body, head...)
	return append(body, extensions...)
}

// Record 把一条消息体包成记录。
func Record(body []byte) []byte {
	out := make([]byte, 5)
	out[0] = 0x16
	binary.BigEndian.PutUint16(out[3:5], uint16(4+len(body)))
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(append(out, hs...), body...)
}
