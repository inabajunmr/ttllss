package handshake

import (
	"bytes"
	"encoding/binary"
)

// enum {
//
// 	/* Elliptic Curve Groups (ECDHE) */
// 	secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
// 	x25519(0x001D), x448(0x001E),
//
// 	/* Finite Field Groups (DHE) */
// 	ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
// 	ffdhe6144(0x0103), ffdhe8192(0x0104),
//
// 	/* Reserved Code Points */
// 	ffdhe_private_use(0x01FC..0x01FF),
// 	ecdhe_private_use(0xFE00..0xFEFF),
// 	(0xFFFF)
// } NamedGroup;

const (
	// Elliptic Curve Groups (ECDHE)
	Secp256r1 uint16 = 0x0017
	Secp384r1 uint16 = 0x0018
	Secp521r1 uint16 = 0x0019
	X25519    uint16 = 0x001D
	X448      uint16 = 0x001E

	// Finite Field Groups (DHE)
	Ffdhe2048 uint16 = 0x0100
	Ffdhe3072 uint16 = 0x0101
	Ffdhe4096 uint16 = 0x0102
	Ffdhe6144 uint16 = 0x0103
	Ffdhe8192 uint16 = 0x0104

	// Reserved Code Points
	FfdhePrivateUseStart uint16 = 0x01FC
	FfdhePrivateUseEnd   uint16 = 0x01FF
	EcdhePrivateUseStart uint16 = 0xFE00
	EcdhePrivateUseEnd   uint16 = 0xFEFF
	ReservedCodePoint    uint16 = 0xFFFF
)

type NamedGroup struct {
	namedGroup uint16
}

func (p NamedGroup) Encode() []byte {
	namedGroupByte := make([]byte, 2)
	binary.BigEndian.PutUint16(namedGroupByte, uint16(p.namedGroup))
	return namedGroupByte
}

func DecodeNamedGroup(b []byte) ([]byte, NamedGroup) {
	namedGroupBytes := b[:2]
	var namedGroup uint16
	binary.Read(bytes.NewReader(namedGroupBytes), binary.BigEndian, &namedGroup)
	return b[2:], NamedGroup{namedGroup}
}

func NewNamedGroup(namedGroup uint16) NamedGroup {
	return NamedGroup{namedGroup: namedGroup}
}
