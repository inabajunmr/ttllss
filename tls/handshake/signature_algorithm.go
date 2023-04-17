package handshake

import (
	"bytes"
	"encoding/binary"
)

// ref. https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3

// struct {
// 	SignatureScheme supported_signature_algorithms<2..2^16-2>;
// } SignatureSchemeList;

type SignatureSchemeList struct {
	supportedSignatureAlgorithms []SignatureScheme
}

func NewSignatureAlgorithmExtention(supportedSignatureAlgorithms []SignatureScheme) SignatureSchemeList {
	return SignatureSchemeList{supportedSignatureAlgorithms: supportedSignatureAlgorithms}
}

func (s SignatureSchemeList) Type() ExtensionType {
	return SignatureAlgorithms
}

func (s SignatureSchemeList) Encode() []byte {

	encoded := []byte{}

	// length
	SignatureAlgorithmLengthBytes := make([]byte, 2)
	suportedGroupsLength := uint16(len(s.supportedSignatureAlgorithms) * 2)
	binary.BigEndian.PutUint16(SignatureAlgorithmLengthBytes, suportedGroupsLength)
	encoded = append(encoded, SignatureAlgorithmLengthBytes...)

	for _, v := range s.supportedSignatureAlgorithms {
		encoded = append(encoded, v.Encode()...)
	}
	return encoded
}

func DecodeSignatureAlgorithmExtention(data []byte) SignatureSchemeList {

	// type is already decoded...
	lengthBytes := data[:2]
	var length uint16
	binary.Read(bytes.NewReader(lengthBytes), binary.BigEndian, &length)
	data = data[2:]

	var result []SignatureScheme
	for i := 0; i < int(length)/2; i++ {
		var group SignatureScheme
		data, group = DecodeSignatureScheme(data)
		result = append(result, group)
	}
	return SignatureSchemeList{supportedSignatureAlgorithms: result}
}
