package handshake

import (
	"bytes"
	"encoding/binary"
)

type CipherSuite uint16

// ref. https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.4
// +------------------------------+-------------+
// | Description                  | Value       |
// +------------------------------+-------------+
// | TLS_AES_128_GCM_SHA256       | {0x13,0x01} |
// |                              |             |
// | TLS_AES_256_GCM_SHA384       | {0x13,0x02} |
// |                              |             |
// | TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} |
// |                              |             |
// | TLS_AES_128_CCM_SHA256       | {0x13,0x04} |
// |                              |             |
// | TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} |
// +------------------------------+-------------+
const (
	TLS_AES_128_GCM_SHA256       CipherSuite = 0x1301
	TLS_AES_256_GCM_SHA384                   = 0x1302
	TLS_CHACHA20_POLY1305_SHA256             = 0x1303
	TLS_AES_128_CCM_SHA256                   = 0x1304
	TLS_AES_128_CCM_8_SHA256                 = 0x1305
)

func (c CipherSuite) Encode() []byte {
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, uint16(c))
	return bytes
}

func DecodeCipherSuite(b []byte) ([]byte, CipherSuite) {
	cipherSuiteBytes := b[:2]
	var cipherSuite uint16
	binary.Read(bytes.NewReader(cipherSuiteBytes), binary.BigEndian, &cipherSuite)

	switch cipherSuite {
	case 0x1301:
		return b[2:], TLS_AES_128_GCM_SHA256
	case 0x1302:
		return b[2:], TLS_AES_256_GCM_SHA384
	case 0x1303:
		return b[2:], TLS_CHACHA20_POLY1305_SHA256
	case 0x1304:
		return b[2:], TLS_AES_128_CCM_SHA256
	case 0x1305:
		return b[2:], TLS_AES_128_CCM_8_SHA256
	}

	return nil, 0
}
