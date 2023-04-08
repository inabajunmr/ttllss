package handshake

import "encoding/binary"

// ref. https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8

// struct {
// 	KeyShareEntry client_shares<0..2^16-1>;
// } KeyShareClientHello;

type KeyShareClientHello struct {
	clientShares []KeyShareEntry
}

func NewKeyShareClientHello(clientShare []KeyShareEntry) KeyShareClientHello {
	return KeyShareClientHello{clientShares: clientShare}
}

func (s KeyShareClientHello) Encode() []byte {

	var encodedShares []byte
	for _, v := range s.clientShares {
		encodedShares = append(encodedShares, v.Encode()...)
	}

	// TODO type と length のエンコードは共通部分にまとめたい

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

func KeyShareClientHelloDecode(data []byte) KeyShareClientHello {

	var clientShares []KeyShareEntry

	for len(data) != 0 {
		var k KeyShareEntry
		data, k = DecodeKeyShareEntry(data)
		clientShares = append(clientShares, k)
	}

	return KeyShareClientHello{clientShares: clientShares}
}
