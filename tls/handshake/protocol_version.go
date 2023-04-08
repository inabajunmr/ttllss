package handshake

import (
	"bytes"
	"encoding/binary"
)

type ProtocolVersion uint16

func (p ProtocolVersion) Encode() []byte {
	versionByte := make([]byte, 2)
	binary.BigEndian.PutUint16(versionByte, uint16(p))
	return versionByte
}

func DecodeProtocolVersion(b []byte) ([]byte, ProtocolVersion) {
	// legacyVersion
	versionBytes := b[:2]
	var version ProtocolVersion
	binary.Read(bytes.NewReader(versionBytes), binary.BigEndian, &version)
	return b[2:], version
}
