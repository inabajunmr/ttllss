package key

import "encoding/binary"

//  struct {
//      uint16 length = Length;
//      opaque label<7..255> = "tls13 " + Label;
//      opaque context<0..255> = Context;
//  } HkdfLabel;

type HkdfLabel struct {
	length  uint16
	label   []byte
	context []byte
}

func NewHkdfLabel(length uint16, label []byte, context []byte) HkdfLabel {
	return HkdfLabel{length: length, label: label, context: context}
}

func (l HkdfLabel) Encode() []byte {
	var result []byte

	// length
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, uint16(l.length))
	result = append(result, lengthBytes...)

	// length of label
	result = append(result, byte(len(l.label)))

	// label
	result = append(result, l.label...)

	// length of context
	result = append(result, byte(len(l.context)))

	// context
	result = append(result, l.context...)

	return result
}
