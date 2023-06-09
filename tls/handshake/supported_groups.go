package handshake

import (
	"bytes"
	"encoding/binary"
)

// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7

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
//
// struct {
// 	NamedGroup named_group_list<2..2^16-1>;
// } NamedGroupList;

type SupportedGroupsExtention struct {
	namedGroupList []NamedGroup
}

func NewSupportedGroupsExtention(namedGroupList []NamedGroup) SupportedGroupsExtention {
	return SupportedGroupsExtention{namedGroupList: namedGroupList}
}

func (s SupportedGroupsExtention) Type() ExtensionType {
	return SupportedGroups
}

func (s SupportedGroupsExtention) Encode() []byte {

	encoded := []byte{}

	// length
	supportedGroupsLengthBytes := make([]byte, 2)
	suportedGroupsLength := uint16(len(s.namedGroupList) * 2)
	binary.BigEndian.PutUint16(supportedGroupsLengthBytes, suportedGroupsLength)
	encoded = append(encoded, supportedGroupsLengthBytes...)

	for _, v := range s.namedGroupList {
		encoded = append(encoded, v.Encode()...)
	}
	return encoded
}

func DecodeSupportedGroups(data []byte) SupportedGroupsExtention {

	// type is already decoded...
	lengthBytes := data[:2]
	var length uint16
	binary.Read(bytes.NewReader(lengthBytes), binary.BigEndian, &length)
	data = data[2:]

	var result []NamedGroup
	for i := 0; i < int(length)/2; i++ {
		var group NamedGroup
		data, group = DecodeNamedGroup(data)
		result = append(result, group)
	}
	return SupportedGroupsExtention{namedGroupList: result}
}
