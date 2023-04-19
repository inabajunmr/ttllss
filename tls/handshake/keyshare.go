package handshake

import (
	"bytes"
	"encoding/binary"
)

// ref. https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8
// struct {
// 	NamedGroup group;
// 	opaque key_exchange<1..2^16-1>;
// } KeyShareEntry;

type KeyShareEntry struct {
	Group       NamedGroup
	KeyExchange []byte
}

func NewKeyShareEntry(group NamedGroup, keyExchange []byte) KeyShareEntry {
	return KeyShareEntry{Group: group, KeyExchange: keyExchange}
}

func (p KeyShareEntry) Encode() []byte {
	var encoded []byte

	// group
	encoded = append(encoded, p.Group.Encode()...)

	// KeyExchange length
	lengthByte2 := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthByte2, uint16(len(p.KeyExchange)))
	encoded = append(encoded, lengthByte2...)

	// KeyExchange
	encoded = append(encoded, p.KeyExchange...)

	return encoded
}

func DecodeKeyShareEntry(b []byte) ([]byte, KeyShareEntry) {

	var group NamedGroup
	b, group = DecodeNamedGroup(b)

	keyExchangelengthBytes := b[:2]
	var keyExchangeLength uint16
	binary.Read(bytes.NewReader(keyExchangelengthBytes), binary.BigEndian, &keyExchangeLength)
	b = b[2:]

	keyExchange := b[:keyExchangeLength]
	b = b[keyExchangeLength:]

	return b, KeyShareEntry{Group: group, KeyExchange: keyExchange}
}
