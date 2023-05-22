package handshake

// ref. https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.1
//
//	struct {
//		Extension extensions<0..2^16-1>;
//	} EncryptedExtensions;
type EncryptedExtensions struct {
	extensions []Extension
}

func NewEncryptedExtensions(extensions []Extension) EncryptedExtensions {
	return EncryptedExtensions{
		extensions: extensions,
	}
}

func (sh EncryptedExtensions) Encode() []byte {

	encoded := []byte{}

	// extensions
	encoded = append(encoded, EncodeExtensions(sh.extensions)...)

	return encoded

}

func DecodeEncryptedExtensions(data []byte) EncryptedExtensions {

	// extensions
	_, extensions := DecodeExtensions(data, false)

	return EncryptedExtensions{
		extensions: extensions,
	}
}
