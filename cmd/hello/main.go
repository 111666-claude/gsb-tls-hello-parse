// Command hello 是 ClientHello 摘要的场景入口。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"example.com/tls-hello-parse/hello"
)

func emit(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))
}

func ext(kind int, payload []byte) []byte {
	out := []byte{byte(kind >> 8), byte(kind), byte(len(payload) >> 8), byte(len(payload))}
	return append(out, payload...)
}

func main() {
	sample := flag.String("sample", "", "session|ciphers|stream|dupext|work")
	flag.Parse()

	c := &hello.Counter{}
	switch *sample {
	case "session":
		raw := hello.Record(hello.ClientHello([]byte{1, 2, 3, 4}, []byte{0x13, 0x01, 0x13, 0x02}, nil))
		got, err := hello.ParseStream(raw, c)
		if err != nil {
			emit(map[string]string{"error": err.Error()})
			return
		}
		emit(map[string]any{"ciphers": got[0].Ciphers})
	case "ciphers":
		raw := hello.Record(hello.ClientHello(nil, []byte{0x13, 0x01, 0x13, 0x02}, nil))
		got, err := hello.ParseStream(raw, c)
		if err != nil {
			emit(map[string]string{"error": err.Error()})
			return
		}
		emit(map[string]any{"ciphers": got[0].Ciphers})
	case "stream":
		one := hello.Record(hello.ClientHello(nil, []byte{0x13, 0x01}, nil))
		raw := append(append([]byte{}, one...), one...)
		got, err := hello.ParseStream(raw, c)
		if err != nil {
			emit(map[string]string{"error": err.Error()})
			return
		}
		emit(map[string]any{"records": len(got)})
	case "dupext":
		exts := append(append([]byte{}, ext(11, []byte{1, 0})...), ext(11, []byte{2, 0})...)
		got, err := hello.ParseStream(hello.Record(hello.ClientHello(nil, []byte{0x13, 0x01}, exts)), c)
		if err != nil {
			emit(map[string]string{"error": err.Error()})
			return
		}
		emit(map[string]any{"extensions": got[0].Extensions})
	case "work":
		exts := []byte{}
		for i := 0; i < 2000; i++ {
			exts = append(exts, ext(i, nil)...)
		}
		got, err := hello.ParseStream(hello.Record(hello.ClientHello(nil, []byte{0x13, 0x01}, exts)), c)
		if err != nil {
			emit(map[string]string{"error": err.Error()})
			return
		}
		emit(map[string]int{"extensions": len(got[0].Extensions), "scanned": got[0].Scanned})
	default:
		fmt.Fprintln(os.Stderr, "未知场景："+*sample)
		os.Exit(2)
	}
}
