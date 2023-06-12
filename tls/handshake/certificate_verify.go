package handshake

import (
	"bytes"
	"encoding/binary"
)

// https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3
// struct {
//     SignatureScheme algorithm;
//     opaque signature<0..2^16-1>;
// } CertificateVerify;

type CertificateVerify struct {
	algorithm SignatureScheme
	signature []byte
}

func (c CertificateVerify) Encode() []byte {
	var encoded []byte

	// algorithm
	encoded = c.algorithm.Encode()

	// signature
	signatureLenBytes := make([]byte, 2)
	signatureLen := uint16(len(c.signature))
	binary.BigEndian.PutUint16(signatureLenBytes, signatureLen)
	encoded = append(encoded, signatureLenBytes...)
	encoded = append(encoded, c.signature...)

	return encoded
}

func DecodeCertificateVerify(data []byte) CertificateVerify {

	// algorithm
	var algorithm SignatureScheme
	data, algorithm = DecodeSignatureScheme(data)

	// signature
	signatureLenByte := data[:2]
	var signatureLen uint16
	binary.Read(bytes.NewReader(signatureLenByte), binary.BigEndian, &signatureLen)
	data = data[2:]

	signature := data[:signatureLen]
	// data = data[signatureLen:]

	return CertificateVerify{
		algorithm: algorithm,
		signature: signature,
	}

}
