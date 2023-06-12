package handshake

type UnknownExtention struct {
	t       ExtensionType
	payload []byte
}

func (s UnknownExtention) Type() ExtensionType {
	return s.t
}

func (s UnknownExtention) Encode() []byte {
	return s.payload
}
