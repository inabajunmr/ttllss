package record

type ContentType int

// ref. https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
// enum {
// 	invalid(0),
// 	change_cipher_spec(20),
// 	alert(21),
// 	handshake(22),
// 	application_data(23),
// 	(255)
// } ContentType;

const (
	Invalid ContentType = iota
	ChangeChipherSpec
	Alert
	HandShake
	ApplicationData
)

func (c ContentType) Encode() byte {
	switch c {
	case Invalid:
		return 0
	case ChangeChipherSpec:
		return 20
	case Alert:
		return 21
	case HandShake:
		return 22
	case ApplicationData:
		return 23
	}

	return 255
}
