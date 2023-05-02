package record

import (
	"bytes"
	"encoding/binary"
)

// ref. https://datatracker.ietf.org/doc/html/rfc8446#section-5.2

// struct {
// 	opaque content[TLSPlaintext.length];
// 	ContentType type;
// 	uint8 zeros[length_of_padding];
// } TLSInnerPlaintext;

// struct {
// 	ContentType opaque_type = application_data; /* 23 */
// 	ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
// 	uint16 length;
// 	opaque encrypted_record[TLSCiphertext.length];
// } TLSCiphertext;

type TLSCiphertext struct {
	opaqueType          ContentType
	legacyRecordVersion uint16
	length              uint16
	EncryptedRecord     []byte
}

func NewTLSCiphertext(opaqueType ContentType, encryptedRecord []byte) TLSCiphertext {
	return TLSCiphertext{
		opaqueType:          opaqueType,
		legacyRecordVersion: 0x0303,
		length:              uint16(len(encryptedRecord)),
		EncryptedRecord:     encryptedRecord,
	}
}

func (t TLSCiphertext) Encode() []byte {
	encoded := []byte{}

	// type
	encoded = append(encoded, t.opaqueType.Encode())

	// legacyRecordVersion
	vertionBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(vertionBytes, t.legacyRecordVersion)
	encoded = append(encoded, vertionBytes...)

	// length
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, t.length)
	encoded = append(encoded, lengthBytes...)

	// fragment
	encoded = append(encoded, t.EncryptedRecord...)

	return encoded
}

func DecodeTLSCiphertext(data []byte) ([]byte, TLSCiphertext) {

	// type
	var opaqueType ContentType
	data, opaqueType = DecodeContentType(data)

	// legacyRecordVersion
	legacyRecordVersionByte := data[:2]
	var legacyRecordVersion uint16
	binary.Read(bytes.NewReader(legacyRecordVersionByte), binary.BigEndian, &legacyRecordVersion)
	data = data[2:]

	// length
	lengthByte := data[:2]
	var length uint16
	binary.Read(bytes.NewReader(lengthByte), binary.BigEndian, &length)
	data = data[2:]

	// encryptedRecord
	encryptedRecord := data[:length]

	return data[length:], TLSCiphertext{
		opaqueType:          opaqueType,
		legacyRecordVersion: legacyRecordVersion,
		length:              length,
		EncryptedRecord:     encryptedRecord,
	}
}

// additional_data = TLSCiphertext.opaque_type || TLSCiphertext.legacy_record_version || TLSCiphertext.length
func (t TLSCiphertext) AdditionalData() []byte {
	result := []byte{}

	// type
	result = append(result, t.opaqueType.Encode())

	// legacyRecordVersion
	vertionBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(vertionBytes, t.legacyRecordVersion)
	result = append(result, vertionBytes...)

	// length
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, t.length)
	result = append(result, lengthBytes...)

	return result
}
