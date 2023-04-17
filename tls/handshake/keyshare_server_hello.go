package handshake

import "encoding/binary"

// ref. https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8

// struct {
// 	KeyShareEntry server_share;
// } KeyShareServerHello;

type KeyShareServerHello struct {
	serverShare KeyShareEntry
}

func NewKeyShareServerHello(serverShare KeyShareEntry) KeyShareServerHello {
	return KeyShareServerHello{serverShare: serverShare}
}

func (s KeyShareServerHello) Encode() []byte {

	encodedShare := s.serverShare.Encode()

	var encoded []byte
	// type
	encoded = append(encoded, KeyShare.Encode()...)

	// length
	lengthBytes := make([]byte, 2)
	var encodedSharesLength = len(encodedShare)
	binary.BigEndian.PutUint16(lengthBytes, uint16(encodedSharesLength))
	encoded = append(encoded, lengthBytes...)

	// serverShare
	encoded = append(encoded, encodedShare...)

	return encoded
}

func DecodeKeyShareServerHello(data []byte) KeyShareServerHello {
	_, keyShareEntry := DecodeKeyShareEntry(data)
	return KeyShareServerHello{serverShare: keyShareEntry}
}
