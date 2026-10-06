# tls-hello-parse

解析一段 TLS 记录流里的 ClientHello，按记录产出摘要。只用标准库。

```
go test ./...
go vet ./...
go run ./cmd/hello --sample=session
go run ./cmd/hello --sample=ciphers
go run ./cmd/hello --sample=stream
go run ./cmd/hello --sample=dupext
go run ./cmd/hello --sample=work
```

## 口径

- **记录流**：输入是一串记录，每条由 5 字节记录头（类型 + 版本 + 2 字节长度）界定；要一路切到流尾，尾部落单的半个记录算坏数据。
- **握手层**：记录内容是一条握手消息（1 字节类型 + 3 字节长度），它的长度必须正好等于记录剩下的字节。
- **自洽**：ClientHello 内部逐层（会话号、密码套件、压缩方法、扩展）的长度都必须正好把外层铺满，多一个字节或少一个字节都算 `mismatch`。
- **密码套件**：2 字节长度给的是字节数，条数是它的一半。
- **扩展**：扩展区按长度界定，同一个扩展类型只允许出现一次，重复报 `duplicate-extension`。
- **版本**：按两字节十六进制给出。

## 不变量

- 每条记录产出一条摘要，记录数与流里的记录数一致。
- 各层长度自洽，不越读也不漏读。
- 扩展类型在一份 ClientHello 里唯一。
- `scanned`（重复扫描的字节数）不随扩展条数乘消息长度放大：两千条扩展不超过 9000。

## 输出契约

每个场景打印一行 JSON；出错时打印 `{"error": "..."}`；
`--sample=work` 只打印 `{"extensions": N, "scanned": N}`。
