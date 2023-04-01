package handshake

import "encoding/binary"

type CipherSuite uint32

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
	TLS_AES_128_GCM_SHA256                  CipherSuite = 0x1301
	TLS_AES_256_GCM_SHA384                              = 0x1302
	TLS_CHACHA20_POLY1305_SHA256                        = 0x1303
	TLS_AES_128_CCM_SHA256                              = 0x1304
	ApplicationDTLS_AES_128_CCM_8_SHA256ata             = 0x1305
)

func (c CipherSuite) Encode() []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, uint32(c))
	return bytes
}
