package handshake

import "encoding/binary"

type ProtocolVersion struct {
	version uint16
}

func (p ProtocolVersion) Encode() []byte {
	versionByte := make([]byte, 2)
	binary.BigEndian.PutUint16(versionByte, p.version)
	return versionByte
}

func NewProtocolVersion(version uint16) ProtocolVersion {
	return ProtocolVersion{version: version}
}
