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
	data, extensionType := DecodeExtensionType(data)

	lengthBytes := data[:2]
	var length uint16
	binary.Read(bytes.NewReader(lengthBytes), binary.BigEndian, &length)
	data = data[2:]

	fmt.Printf("type: %v\n", extensionType)

	// TODO
	switch extensionType {
	case SupportedVersions:
		return DecodeSupportedVersion(data, length, isClient)
	case SupportedGroups:
		return DecodeSupportedGroups(data, length)
	}

	return data, nil
}
