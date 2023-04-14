package handshake

import (
	"encoding/binary"
)

// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1

// struct {
// 	select (Handshake.msg_type) {
// 		case client_hello:
// 			 ProtocolVersion versions<2..254>;
//
// 		case server_hello: /* and HelloRetryRequest */
// 			 ProtocolVersion selected_version;
// 	};
// } SupportedVersions;

type SupportedVersionsExtention struct {
	isClientHello   bool
	versions        []ProtocolVersion
	selectedVersion ProtocolVersion
}

func NewSupportedVersionsForClient(versions []ProtocolVersion) SupportedVersionsExtention {
	return SupportedVersionsExtention{isClientHello: true, versions: versions}
}

func NewSupportedVersionsForServer(version ProtocolVersion) SupportedVersionsExtention {
	return SupportedVersionsExtention{isClientHello: false, selectedVersion: version}
}

func (s SupportedVersionsExtention) Encode() []byte {
	encoded := []byte{}
	encoded = append(encoded, SupportedVersions.Encode()...)

	if s.isClientHello {
		// version number * 2 + 1(for 1 byte length field)
		lengthBytes := make([]byte, 2)
		extensionLength := uint16(len(s.versions)*2 + 1)
		binary.BigEndian.PutUint16(lengthBytes, extensionLength)
		encoded = append(encoded, lengthBytes...)

		// length
		encoded = append(encoded, byte(len(s.versions)*2)) // 1 version uses 2 bytes
		for _, v := range s.versions {
			encoded = append(encoded, v.Encode()...)
		}
		return encoded
	} else {
		// version number * 2
		lengthBytes := make([]byte, 2)
		extensionLength := uint16(2)
		binary.BigEndian.PutUint16(lengthBytes, extensionLength)
		encoded = append(encoded, lengthBytes...)

		return append(encoded, s.selectedVersion.Encode()...)
	}
}

func DecodeSupportedVersion(data []byte, isClientHello bool) SupportedVersionsExtention {

	// type is already decoded...
	if isClientHello {
		// length byte
		data = data[1:]

		var result []ProtocolVersion
		for len(data) != 0 {
			var version ProtocolVersion
			data, version = DecodeProtocolVersion(data)
			result = append(result, version)
		}
		return SupportedVersionsExtention{isClientHello: true, versions: result}
	} else {
		var version ProtocolVersion
		_, version = DecodeProtocolVersion(data)
		return SupportedVersionsExtention{isClientHello: false, selectedVersion: version}
	}
}
