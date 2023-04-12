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
	group       NamedGroup
	keyExchange []byte
}

func NewKeyShareEntry(group NamedGroup, keyExchange []byte) KeyShareEntry {
	return KeyShareEntry{group: group, keyExchange: keyExchange}
}

func (p KeyShareEntry) Encode() []byte {
	var encoded []byte

	// KeyShareEntry length
	lengthByte := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthByte, uint16(4+len(p.keyExchange))) // length byte + group byte + followings...
	encoded = append(encoded, lengthByte...)

	// group
	encoded = append(encoded, p.group.Encode()...)

	// KeyExchange length
	lengthByte2 := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthByte2, uint16(len(p.keyExchange)))
	encoded = append(encoded, lengthByte2...)

	// KeyExchange
	encoded = append(encoded, p.keyExchange...)

	return encoded
}

func DecodeKeyShareEntry(b []byte) ([]byte, KeyShareEntry) {
	keyShareEntrylengthBytes := b[:2]
	var keyShareEntryLength uint16
	binary.Read(bytes.NewReader(keyShareEntrylengthBytes), binary.BigEndian, &keyShareEntryLength)
	b = b[2:]

	var group NamedGroup
	b, group = DecodeNamedGroup(b)

	keyExchangelengthBytes := b[:2]
	var keyExchangeLength uint16
	binary.Read(bytes.NewReader(keyExchangelengthBytes), binary.BigEndian, &keyExchangeLength)
	b = b[2:]

	keyExchange := b[:keyExchangeLength]
	b = b[keyExchangeLength:]

	return b, KeyShareEntry{group: group, keyExchange: keyExchange}
}
