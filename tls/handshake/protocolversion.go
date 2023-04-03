package handshake

import (
	"bytes"
	"encoding/binary"
)

type ProtocolVersion struct {
	version uint16
}

func (p ProtocolVersion) Encode() []byte {
	versionByte := make([]byte, 2)
	binary.BigEndian.PutUint16(versionByte, p.version)
	return versionByte
}

func DecodeProtocolVersion(b []byte) ([]byte, ProtocolVersion) {
	// legacyVersion
	legacyVersionBytes := b[:2]
	var legacyVersion uint16
	binary.Read(bytes.NewReader(legacyVersionBytes), binary.BigEndian, &legacyVersion)
	return b[2:], ProtocolVersion{legacyVersion}
}

func NewProtocolVersion(version uint16) ProtocolVersion {
	return ProtocolVersion{version: version}
}
