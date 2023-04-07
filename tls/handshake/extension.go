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

	fmt.Printf("1data: %x\n", data)
	data, extensionType := DecodeExtensionType(data)
	fmt.Printf("type: %x\n", extensionType)

	lengthBytes := data[:2]
	var length uint16
	binary.Read(bytes.NewReader(lengthBytes), binary.BigEndian, &length)
	data = data[2:]

	extensionData := data[:length]
	fmt.Printf("2ex data: %x\n", extensionData)
	fmt.Printf("3data: %x\nlen: %x\n", data, length)
	data = data[length:]
	fmt.Printf("4data: %x\nlen: %x\n", data, length)

	switch extensionType {
	case SupportedVersions:
		return data, DecodeSupportedVersion(extensionData, isClient)
	case SupportedGroups:
		return data, DecodeSupportedGroups(extensionData)
	case KeyShare:
		if isClient {
			return data, KeyShareClientHelloDecode(extensionData)
		} else {
			return data, KeyShareServerHelloDecode(extensionData)
		}
	}

	return data, nil
}
