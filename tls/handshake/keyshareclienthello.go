package handshake

import "encoding/binary"

// ref. https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8

// struct {
// 	KeyShareEntry client_shares<0..2^16-1>;
// } KeyShareClientHello;

type KeyShareClientHello struct {
	clientShares []KeyShareEntry
}

func (s KeyShareClientHello) Encode() []byte {

	var encodedShares []byte
	for _, v := range s.clientShares {
		encodedShares = append(encodedShares, v.Encode()...)
	}

	var encoded []byte
	// type
	encoded = append(encoded, KeyShare.Encode()...)

	// length
	lengthBytes := make([]byte, 2)
	var encodedSharesLength = len(encodedShares)
	binary.BigEndian.PutUint16(lengthBytes, uint16(encodedSharesLength))
	encoded = append(encoded, lengthBytes...)

	// clientShares
	encoded = append(encoded, encodedShares...)

	return encoded
}

// func KeyShareClientHelloDecode(data []byte, extensionLength uint16) ([]byte, KeyShareClientHello) {
// 	return nil, nil
// }
