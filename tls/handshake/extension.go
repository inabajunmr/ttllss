package handshake

import (
	"bytes"
	"encoding/binary"
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

	var extensions []Extension
	for i := 0; i < int(length); i++ { // TODO これも length でループするんじゃなくて length 分読み込む、という理解が正しそう
		var extension Extension
		data, extension = decodeExtension(data, isClient)
		extensions = append(extensions, extension)
	}

	return data, extensions
}

func decodeExtension(bytes []byte, isClient bool) ([]byte, Extension) {
	bytes, ExtensionType := DecodeExtensionType(bytes)

	switch ExtensionType {
	case SupportedVersions:
		{
			return DecodeSupportedVersion(bytes, isClient)
		}
	}

	return bytes, nil
}
