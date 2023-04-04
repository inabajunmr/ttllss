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
	versionBytes := b[:2]
	var version uint16
	binary.Read(bytes.NewReader(versionBytes), binary.BigEndian, &version)
	return b[2:], ProtocolVersion{version}
}

func NewProtocolVersion(version uint16) ProtocolVersion {
	return ProtocolVersion{version: version}
}
