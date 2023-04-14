package handshake

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// ref. https://datatracker.ietf.org/doc/html/rfc8446#section-4.2

type Extension interface {
	Encode() []byte
}

func EncodeExtensions(extensions []Extension) []byte {
	// extensions
	var encodedExtensions []byte
	// construct extensions before encoding length of extension
	for _, v := range extensions {
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
			fmt.Println("CLIENT")
			return data, KeyShareClientHelloDecode(extensionData)
		} else {
			fmt.Println("SERVER")
			return data, KeyShareServerHelloDecode(extensionData)
		}
	case SignatureAlgorithms:
		return data, DecodeSignatureAlgorithmExtention(extensionData)
	}

	return data, nil
}
