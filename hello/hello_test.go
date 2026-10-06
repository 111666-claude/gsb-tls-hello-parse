package hello

import "testing"

func TestVersion(t *testing.T) {
	got, err := ParseStream(Record(ClientHello(nil, []byte{0x13, 0x01}, nil)), &Counter{})
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if len(got) != 1 || got[0].Version != "0303" {
		t.Fatalf("版本应是 0303：%+v", got)
	}
}

func TestTooShort(t *testing.T) {
	if _, err := ParseStream([]byte{1, 2, 3}, &Counter{}); err == nil {
		t.Fatal("太短的输入应报错")
	}
}

func TestHandshakeLengthMustMatch(t *testing.T) {
	raw := Record(ClientHello(nil, []byte{0x13, 0x01}, nil))
	raw[6] = 0x7F
	if _, err := ParseStream(raw, &Counter{}); err == nil {
		t.Fatal("握手长度与记录不符应报错")
	}
}

func TestOneExtensionIsListed(t *testing.T) {
	ext := []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}
	got, err := ParseStream(Record(ClientHello(nil, []byte{0x13, 0x01}, ext)), &Counter{})
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if len(got[0].Extensions) != 1 || got[0].Extensions[0] != 11 {
		t.Fatalf("应列出扩展 11：%+v", got[0].Extensions)
	}
}

func TestNoExtensions(t *testing.T) {
	got, err := ParseStream(Record(ClientHello(nil, []byte{0x13, 0x01}, nil)), &Counter{})
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if len(got[0].Extensions) != 0 {
		t.Fatalf("没有扩展时不该有扩展：%+v", got[0].Extensions)
	}
}
