package handshake

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
)

// ref. https://datatracker.ietf.org/doc/html/rfc8446#section-4.2

type Extension interface {
	Encode() []byte
	Type() ExtensionType
}

func EncodeExtensions(extensions []Extension) []byte {
	// extensions
	var encodedExtensions []byte
	// construct extensions before encoding length of extension
	for _, v := range extensions {
		// TODO v の型に合わせて type を出力
		// TODO v.Encode() のサイズに合わせて length を出力？
		fmt.Println(reflect.TypeOf(v))
		encodedExtensions = append(encodedExtensions, v.Encode()...)
	}

	extensionsLenBytes := make([]byte, 2)
	extensionsLen := uint16(len(encodedExtensions))
	binary.BigEndian.PutUint16(extensionsLenBytes, extensionsLen)

	encoded := extensionsLenBytes
	encoded = append(encoded, encodedExtensions...)

	return encoded

}

func DecodeExtensions(data []byte, isClient bool) ([]byte, []Extension) {
	lengthBytes := data[:2]
	var length uint16
	binary.Read(bytes.NewReader(lengthBytes), binary.BigEndian, &length)
	data = data[2:]

	extensionBytes := data[:length]
	data = data[length:]

	var extensions []Extension
	for len(extensionBytes) != 0 {
		var extension Extension
		extensionBytes, extension = decodeExtension(extensionBytes, isClient)
		extensions = append(extensions, extension)
	}

	return data, extensions
}

func decodeExtension(data []byte, isClient bool) ([]byte, Extension) {
	data, extensionType := DecodeExtensionType(data)

	lengthBytes := data[:2]
	var length uint16
	binary.Read(bytes.NewReader(lengthBytes), binary.BigEndian, &length)
	data = data[2:]

	extensionData := data[:length]
	data = data[length:]

	switch extensionType {
	case SupportedVersions:
		return data, DecodeSupportedVersion(extensionData, isClient)
	case SupportedGroups:
		return data, DecodeSupportedGroups(extensionData)
	case KeyShare:
		if isClient {
			return data, DecodeKeyShareClientHello(extensionData)
		} else {
			return data, DecodeKeyShareServerHello(extensionData)
		}
	case SignatureAlgorithms:
		return data, DecodeSignatureAlgorithmExtention(extensionData)
	}

	return data, nil
}
