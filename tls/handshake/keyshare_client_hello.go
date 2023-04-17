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

func (s KeyShareClientHello) Type() ExtensionType {
	return KeyShare
}

func (s KeyShareClientHello) Encode() []byte {

	var encodedShares []byte
	for _, v := range s.clientShares {
		encodedShares = append(encodedShares, v.Encode()...)
	}

	// TODO type と length のエンコードは共通部分にまとめたい
	// Encode と Decode の対応が取れてない（type と length を Encode では書いてるのに Decode は共通化されてて個々の関数に書いてない）からテストがめんどくさい

	var encoded []byte
	// type
	encoded = append(encoded, KeyShare.Encode()...)

	// key share extension length
	lengthBytes := make([]byte, 2)
	var encodedSharesLength = len(encodedShares)
	binary.BigEndian.PutUint16(lengthBytes, uint16(encodedSharesLength+2))
	encoded = append(encoded, lengthBytes...)

	// key share data length
	lengthBytes2 := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes2, uint16(encodedSharesLength))
	encoded = append(encoded, lengthBytes2...)

	// clientShares
	encoded = append(encoded, encodedShares...)

	return encoded
}

func DecodeKeyShareClientHello(data []byte) KeyShareClientHello {

	var clientShares []KeyShareEntry

	// discard key share data lenght
	data = data[2:]

	// decode
	for len(data) != 0 {
		var k KeyShareEntry
		data, k = DecodeKeyShareEntry(data)
		clientShares = append(clientShares, k)
	}

	return KeyShareClientHello{clientShares: clientShares}
}
